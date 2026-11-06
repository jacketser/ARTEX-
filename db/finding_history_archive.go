package db

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

var archiveFindingHistoryTables = []string{"finding_retests", "finding_reviews", "finding_review_history"}

func checkArchiveRetests(tx *sql.Tx, taskID int64) error {
	var active bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM finding_retests r JOIN findings f ON f.id=r.finding_id WHERE f.task_id=$1 AND r.status IN ('pending','running'))`, taskID).Scan(&active); err != nil {
		return err
	}
	if active {
		return ErrTaskArchiveActiveRetest
	}
	return nil
}

// ValidateArchiveFindingHistory rejects incomplete v4 manifests and extensions
// in older formats. It never invents missing history for legacy archives.
func ValidateArchiveFindingHistory(snapshot *TaskArchiveSnapshot) error {
	if snapshot == nil || !IsTaskArchiveFormatSupported(snapshot.FormatVersion) {
		return ErrTaskArchiveFormatMismatch
	}
	findings, err := decodeArchiveRows(snapshot.Tables["findings"])
	if err != nil {
		return err
	}
	owned := map[int64]bool{}
	for _, f := range findings {
		id, ok := jsonInt64(f["id"])
		tid, owner := jsonInt64(f["task_id"])
		if ok && owner && tid == snapshot.TaskID {
			owned[id] = true
		}
	}
	for _, table := range archiveFindingHistoryTables {
		raw, present := snapshot.Tables[table]
		rows, err := decodeArchiveRows(raw)
		if err != nil {
			return err
		}
		count, counted := snapshot.DataCounts[table]
		if _, streamed := snapshot.StreamedTables[table]; streamed {
			return ErrTaskArchiveFormatMismatch
		}
		if snapshot.FormatVersion < 4 {
			if len(rows) != 0 || count != 0 {
				return ErrTaskArchiveFormatMismatch
			}
			continue
		}
		if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || !counted || count != int64(len(rows)) {
			return fmt.Errorf("%w: 归档审阅表 %s 缺失或计数不匹配", ErrTaskArchiveFormatMismatch, table)
		}
		ids := map[int64]bool{}
		conversations := map[int64]bool{}
		for _, row := range rows {
			fid, ok := jsonInt64(row["finding_id"])
			if !ok || !owned[fid] {
				return errors.New("归档审阅引用其他任务或缺失的漏洞")
			}
			key := "id"
			if table == "finding_reviews" {
				key = "finding_id"
			}
			id, ok := jsonInt64(row[key])
			if !ok || id <= 0 || ids[id] {
				return errors.New("归档审阅记录 ID 无效或重复")
			}
			ids[id] = true
			if table == "finding_retests" {
				status, _ := row["status"].(string)
				if status != "completed" && status != "failed" && status != "stopped" {
					return errors.New("归档只支持已结束的复测记录")
				}
				if row["conversation_id"] != nil {
					cid, ok := jsonInt64(row["conversation_id"])
					if !ok || cid <= 0 || conversations[cid] {
						return errors.New("归档复测会话引用无效或重复")
					}
					conversations[cid] = true
				}
			}
		}
	}
	return nil
}

func restoreArchiveFindingHistory(tx *sql.Tx, snapshot *TaskArchiveSnapshot) ([]string, error) {
	warnings := []string{}
	if snapshot.FormatVersion < 4 {
		return warnings, nil
	}
	retests, err := decodeArchiveRows(snapshot.Tables["finding_retests"])
	if err != nil {
		return nil, err
	}
	for _, row := range retests {
		cid, linked := jsonInt64(row["conversation_id"])
		if !linked {
			continue
		}
		var agent string
		err := tx.QueryRow(`SELECT agent_key FROM conversations WHERE id=$1 FOR KEY SHARE`, cid).Scan(&agent)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && agent != FindingRetestAgentKey) {
			row["conversation_id"] = nil
			id, _ := jsonInt64(row["id"])
			warnings = append(warnings, fmt.Sprintf("复测 %d 的原会话已不存在或类型不符，已保留记录并解除会话链接", id))
		} else if err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal(retests)
	if err != nil {
		return nil, err
	}
	if err = insertArchiveRows(tx, "finding_retests", raw); err != nil {
		return nil, fmt.Errorf("restore retests: %w", err)
	}
	// Suppress only the review-history trigger for this transaction. Never disable
	// a table trigger globally or generate a new historical event during replay.
	if _, err = tx.Exec(`SELECT set_config('artex.restoring_finding_history','on',true)`); err != nil {
		return nil, err
	}
	for _, table := range []string{"finding_reviews", "finding_review_history"} {
		if err = insertArchiveRows(tx, table, snapshot.Tables[table]); err != nil {
			return nil, fmt.Errorf("restore %s: %w", table, err)
		}
	}
	if _, err = tx.Exec(`SELECT set_config('artex.restoring_finding_history','off',true)`); err != nil {
		return nil, err
	}
	return warnings, nil
}
