package db

import (
	"context"
	"database/sql"
)

type TaskRecoveryState struct {
	Attempts    int   `json:"attempts"`
	LastAttempt int64 `json:"last_attempt"`
	ProgressID  int64 `json:"-"`
}
type TaskRecoverySnapshot struct {
	TaskRecoveryState
	Pending        int
	Approvals      int
	LastActivity   int64
	LatestProgress int64
}

func (d *DB) GetTaskRecoveryState(ctx context.Context, id string) (TaskRecoveryState, error) {
	var out TaskRecoveryState
	err := d.QueryRowContext(ctx, `SELECT attempts,last_attempt,progress_id FROM task_recovery_state WHERE task_id=$1`, id).Scan(&out.Attempts, &out.LastAttempt, &out.ProgressID)
	if err == sql.ErrNoRows {
		err = nil
	}
	return out, err
}
func (d *DB) TaskRecoverySnapshot(ctx context.Context, id string) (TaskRecoverySnapshot, error) {
	var out TaskRecoverySnapshot
	err := d.QueryRowContext(ctx, `SELECT
 COALESCE(r.attempts,0),COALESCE(r.last_attempt,0),COALESCE(r.progress_id,0),
 (SELECT count(*) FROM exploration_nodes n WHERE n.exploration_id=t.exploration_id AND n.kind='intent' AND n.state IN ('open','running')),
 (SELECT count(*) FROM intercept_pending p WHERE p.task_id=t.id::text AND p.status='pending'),
 COALESCE((SELECT EXTRACT(EPOCH FROM max(created_at))::bigint FROM activity a WHERE a.exploration_id=t.exploration_id),EXTRACT(EPOCH FROM t.created_at)::bigint),
 COALESCE((SELECT max(id) FROM activity a WHERE a.exploration_id=t.exploration_id AND (a.kind='user' OR (a.worker LIKE 'work#%' AND a.kind='result' AND NOT a.is_error))),0)
 FROM tasks t LEFT JOIN task_recovery_state r ON r.task_id=t.id
 WHERE t.id=$1 AND t.deleted_at IS NULL AND NOT t.paused AND NOT t.queued AND t.status NOT IN ('done','failed','timeout')`, id).Scan(&out.Attempts, &out.LastAttempt, &out.ProgressID, &out.Pending, &out.Approvals, &out.LastActivity, &out.LatestProgress)
	return out, err
}

// Reserve before waking; a write failure cannot cause unbounded retries. CAS
// prevents duplicate reservation if more than one scheduler inspects the task.
func (d *DB) ReserveTaskRecovery(ctx context.Context, id string, old TaskRecoveryState, next TaskRecoveryState, observationSeconds ...int64) (bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO task_recovery_state(task_id,attempts,last_attempt,progress_id)
 VALUES($1,$2,$3,$4) ON CONFLICT(task_id) DO UPDATE SET attempts=$2,last_attempt=$3,progress_id=$4
 WHERE task_recovery_state.attempts=$5 AND task_recovery_state.last_attempt=$6 AND task_recovery_state.progress_id=$7`, id, next.Attempts, next.LastAttempt, next.ProgressID, old.Attempts, old.LastAttempt, old.ProgressID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	seconds := int64(300)
	if len(observationSeconds) > 0 {
		seconds = observationSeconds[0]
	}
	// Close an elapsed observation before reserving another; normally the monitor already did so.
	_, err = tx.ExecContext(ctx, `UPDATE task_recovery_history SET status='no_progress',finished_at=$2 WHERE task_id=$1 AND status='observing' AND observe_until<=$2`, id, next.LastAttempt)
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO task_recovery_history(task_id,attempt,started_at,observe_until,progress_id)
 SELECT t.id,$2,$3,$4,COALESCE((SELECT max(a.id) FROM activity a WHERE a.exploration_id=t.exploration_id),0) FROM tasks t WHERE t.id=$1`, id, next.Attempts, next.LastAttempt, next.LastAttempt+seconds)
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// UpdateRecoveryOutcomes observes worker completion only: human messages/logs are not recovery success.
func (d *DB) UpdateRecoveryOutcomes(ctx context.Context, now int64) error {
	_, err := d.ExecContext(ctx, `WITH outcomes AS (
 SELECT h.id, CASE
 WHEN EXISTS(SELECT 1 FROM activity a WHERE a.exploration_id=t.exploration_id AND a.id>h.progress_id AND a.created_at<=to_timestamp(h.observe_until) AND a.worker LIKE 'work#%' AND a.kind='result' AND NOT a.is_error) THEN 'recovered'
 WHEN t.status='done' THEN 'recovered'
 WHEN t.paused OR t.queued OR t.deleted_at IS NOT NULL OR t.status IN ('failed','timeout') THEN 'interrupted'
 WHEN h.observe_until<=$1 THEN 'no_progress' ELSE 'observing' END AS outcome
 FROM task_recovery_history h JOIN tasks t ON t.id=h.task_id WHERE h.status='observing')
 UPDATE task_recovery_history h SET status=o.outcome,finished_at=$1 FROM outcomes o WHERE h.id=o.id AND o.outcome<>'observing'`, now)
	return err
}

type TaskRecoveryEvent struct {
	ID               int64  `json:"id"`
	TaskID           string `json:"task_id"`
	Attempt          int    `json:"attempt"`
	StartedAt        int64  `json:"started_at"`
	ObserveUntil     int64  `json:"observe_until"`
	Status           string `json:"status"`
	FinishedAt       int64  `json:"finished_at"`
	AcknowledgedNote string `json:"acknowledged_note,omitempty"`
}

func (d *DB) RecoveryHistory(ctx context.Context, id string, before int64) ([]TaskRecoveryEvent, error) {
	rows, err := d.QueryContext(ctx, `SELECT h.id,h.task_id::text,h.attempt,h.started_at,h.observe_until,h.status,h.finished_at,COALESCE(a.note,'') FROM task_recovery_history h LEFT JOIN task_recovery_ack a ON a.history_id=h.id WHERE h.task_id=$1 AND ($2::bigint=0 OR h.id<$2) ORDER BY h.id DESC LIMIT 50`, id, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskRecoveryEvent{}
	for rows.Next() {
		var e TaskRecoveryEvent
		if err = rows.Scan(&e.ID, &e.TaskID, &e.Attempt, &e.StartedAt, &e.ObserveUntil, &e.Status, &e.FinishedAt, &e.AcknowledgedNote); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const recoveryAlertQuery = ` FROM task_recovery_history h JOIN tasks t ON t.id=h.task_id JOIN task_recovery_state r ON r.task_id=t.id
 WHERE NOT EXISTS(SELECT 1 FROM task_recovery_ack ack WHERE ack.history_id=h.id) AND h.status='no_progress' AND r.attempts>=3 AND t.deleted_at IS NULL AND t.status NOT IN ('done','failed','timeout')
 AND NOT t.paused AND NOT t.queued
 AND h.id=(SELECT max(x.id) FROM task_recovery_history x WHERE x.task_id=t.id)
 AND NOT EXISTS(SELECT 1 FROM activity a WHERE a.exploration_id=t.exploration_id AND a.id>h.progress_id AND (a.kind='user' OR (a.worker LIKE 'work#%' AND a.kind='result' AND NOT a.is_error)))`

func (d *DB) RecoveryAlerts(ctx context.Context) ([]TaskRecoveryEvent, error) {
	rows, err := d.QueryContext(ctx, `SELECT h.id,h.task_id::text,h.attempt,h.started_at,h.observe_until,h.status,h.finished_at
`+recoveryAlertQuery+`
 ORDER BY h.id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskRecoveryEvent{}
	for rows.Next() {
		var e TaskRecoveryEvent
		if err = rows.Scan(&e.ID, &e.TaskID, &e.Attempt, &e.StartedAt, &e.ObserveUntil, &e.Status, &e.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
