package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type ClockCompensation struct {
	ID         int64     `json:"id"`
	ObservedAt time.Time `json:"observed_at"`
	Previous   int64     `json:"previous_unix"`
	Current    int64     `json:"current_unix"`
	Shift      int64     `json:"shift_seconds"`
	Reason     string    `json:"reason"`
	Tasks      []string  `json:"affected_tasks"`
}

// Compensation and audit commit together. The idempotency key also protects a retry
// after a commit acknowledgement was lost. Caller holds the in-process task lifecycle lock.
func (d *DB) CompensateClock(ctx context.Context, key string, previous, current, shift int64, reason string, ids []string) (map[string]int64, error) {
	out := map[string]int64{}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var eventID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO clock_compensations(event_key,previous_unix,current_unix,shift_seconds,reason) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id`, key, previous, current, shift, reason).Scan(&eventID)
	if err == sql.ErrNoRows {
		// Recover persisted deadlines for the original affected set, without applying twice.
		rows, e := tx.QueryContext(ctx, `SELECT t.id::text,EXTRACT(EPOCH FROM t.deadline_at)::bigint FROM tasks t JOIN clock_compensations c ON c.event_key=$1 WHERE c.affected_tasks ? t.id::text AND t.deadline_at IS NOT NULL`, key)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var id string
			var dl int64
			if e = rows.Scan(&id, &dl); e != nil {
				rows.Close()
				return nil, e
			}
			out[id] = dl
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		return out, tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	affected := []string{}
	if shift != 0 {
		for _, id := range ids {
			// Lock eligibility even for tasks without a task deadline: their recovery
			// observation and cooldown still lose time during a freeze.
			var eligible string
			err = tx.QueryRowContext(ctx, `SELECT id::text FROM tasks WHERE id=$1 AND status='running' AND NOT paused AND NOT queued AND deleted_at IS NULL AND COALESCE(first_run_at,created_at)<=to_timestamp($2) AND (deadline_at IS NULL OR deadline_at>to_timestamp($2)) FOR UPDATE`, id, previous).Scan(&eligible)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return nil, err
			}
			var dl int64
			err = tx.QueryRowContext(ctx, `UPDATE tasks SET deadline_at=deadline_at+($2*interval '1 second') WHERE id=$1 AND status='running' AND NOT paused AND NOT queued AND deleted_at IS NULL AND first_run_at<=to_timestamp($3) AND deadline_at>to_timestamp($3) RETURNING EXTRACT(EPOCH FROM deadline_at)::bigint`, id, shift, previous).Scan(&dl)
			if err != nil && err != sql.ErrNoRows {
				return nil, err
			}
			if err == nil {
				out[id] = dl
			}
			affected = append(affected, id)
			_, err = tx.ExecContext(ctx, `UPDATE task_recovery_history SET observe_until=observe_until+$2 WHERE task_id=$1 AND status='observing' AND started_at<=$3 AND observe_until>$3`, id, shift, previous)
			if err != nil {
				return nil, err
			}
			_, err = tx.ExecContext(ctx, `UPDATE task_recovery_state SET last_attempt=last_attempt+$2 WHERE task_id=$1 AND last_attempt>0 AND last_attempt<=$3`, id, shift, previous)
			if err != nil {
				return nil, err
			}
		}
	}
	b, _ := json.Marshal(affected)
	if _, err = tx.ExecContext(ctx, "UPDATE clock_compensations SET affected_tasks=$2 WHERE id=$1", eventID, string(b)); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}
func (d *DB) ClockHistory(ctx context.Context, before int64) ([]ClockCompensation, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,observed_at,previous_unix,current_unix,shift_seconds,reason,affected_tasks FROM clock_compensations WHERE ($1::bigint=0 OR id<$1) ORDER BY id DESC LIMIT 50`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClockCompensation{}
	for rows.Next() {
		var v ClockCompensation
		var b []byte
		if err = rows.Scan(&v.ID, &v.ObservedAt, &v.Previous, &v.Current, &v.Shift, &v.Reason, &b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &v.Tasks); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
