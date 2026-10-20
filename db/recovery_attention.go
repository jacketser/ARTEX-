package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/notify"
	"strconv"
)

func (d *DB) AcknowledgeRecovery(ctx context.Context, taskID string, historyID int64, note string) error {
	res, err := d.ExecContext(ctx, `INSERT INTO task_recovery_ack(history_id,note) SELECT id,$3 FROM task_recovery_history WHERE id=$2 AND task_id=$1 AND status='no_progress' ON CONFLICT DO NOTHING`, taskID, historyID, note)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}
func (d *DB) QueueRecoveryNotifications(ctx context.Context) error {
	alerts, err := d.RecoveryAlerts(ctx)
	if err != nil {
		return err
	}
	for _, a := range alerts {
		if err = d.queueRecoveryNotification(ctx, a); err != nil {
			return err
		}
	}
	return nil
}
func (d *DB) queueRecoveryNotification(ctx context.Context, a TaskRecoveryEvent) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Per-observation deduplication survives restarts. Never backfill previously consumed events.
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO task_recovery_notifications(history_id) SELECT h.id `+recoveryAlertQuery+` AND h.id=$1 ON CONFLICT DO NOTHING RETURNING history_id`, a.ID).Scan(&id)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	tid, _ := strconv.ParseInt(a.TaskID, 10, 64)
	snap := notify.Snapshot{Kind: notify.EventRecoveryExhausted, TaskID: tid, Name: fmt.Sprintf("任务 #%s 自动恢复未取得进展", a.TaskID), Severity: "notice", Summary: "连续 3 次自动唤醒后观察期内仍无成功 Worker 结果，请打开任务检查。此通知不包含任务目标、凭据或工具输出。", AssetIDs: []int64{}}
	b, _ := json.Marshal(snap)
	var event int64
	err = tx.QueryRowContext(ctx, `INSERT INTO notification_events(kind,finding_id,snapshot) VALUES($1,0,$2) RETURNING id`, notify.EventRecoveryExhausted, string(b)).Scan(&event)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE task_recovery_notifications SET event_id=$2 WHERE history_id=$1", id, event); err != nil {
		return err
	}
	return tx.Commit()
}
