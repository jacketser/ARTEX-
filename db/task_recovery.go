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
func (d *DB) ReserveTaskRecovery(ctx context.Context, id string, old TaskRecoveryState, next TaskRecoveryState) (bool, error) {
	res, err := d.ExecContext(ctx, `INSERT INTO task_recovery_state(task_id,attempts,last_attempt,progress_id)
 VALUES($1,$2,$3,$4) ON CONFLICT(task_id) DO UPDATE SET attempts=$2,last_attempt=$3,progress_id=$4
 WHERE task_recovery_state.attempts=$5 AND task_recovery_state.last_attempt=$6 AND task_recovery_state.progress_id=$7`, id, next.Attempts, next.LastAttempt, next.ProgressID, old.Attempts, old.LastAttempt, old.ProgressID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
