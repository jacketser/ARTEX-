package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/Autumn-27/artex/honeydetect"
	"time"
)

// SetHoneypot updates only the reserved metadata key.
func (s *AssetStore) SetHoneypot(id int64, result any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	updated, err := s.db.Exec(`UPDATE assets SET extra=jsonb_set(COALESCE(extra,'{}'::jsonb),'{honeypot}',$2::jsonb,true) WHERE id=$1`, id, string(raw))
	if err != nil {
		return err
	}
	n, err := updated.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}

func HoneypotInput(a *Asset) honeydetect.Input {
	get := func(k string) string { v, _ := a.Extra[k].(string); return v }
	return honeydetect.Input{Service: a.ServiceName, Title: a.PageTitle, Technologies: a.Technologies, Banner: get("banner"), ServerHeader: get("server_header"), PoweredBy: get("powered_by"), ResponseSummary: get("response_summary")}
}

var ErrHoneypotStale = errors.New("资产元数据已变化，请刷新后重新复核")

// AssessHoneypot locks source metadata and preserves unrelated extra keys atomically.
func (s *AssetStore) AssessHoneypot(ctx context.Context, id int64, manual map[string]string) (honeydetect.Result, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return honeydetect.Result{}, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT jsonb_build_object('service_name',COALESCE(service_name,''),'page_title',COALESCE(page_title,''),'technologies',technologies,'extra',extra) FROM assets WHERE id=$1 FOR UPDATE`, id).Scan(&raw)
	if err != nil {
		return honeydetect.Result{}, err
	}
	var a Asset
	if err = json.Unmarshal(raw, &a); err != nil {
		return honeydetect.Result{}, err
	}
	result := honeydetect.Detect(HoneypotInput(&a))
	result.AssessedAt = time.Now().Unix()
	if manual != nil && manual["fingerprint"] != result.Fingerprint {
		return result, ErrHoneypotStale
	}
	data, _ := json.Marshal(result)
	_, err = tx.ExecContext(ctx, `UPDATE assets SET extra=jsonb_set(jsonb_set(COALESCE(extra,'{}'),'{honeypot}',$2::jsonb,true),'{honeypot_stale}','false',true) WHERE id=$1`, id, string(data))
	if err != nil {
		return result, err
	}
	if manual != nil {
		review, _ := json.Marshal(map[string]any{"fingerprint": result.Fingerprint, "verdict": manual["verdict"], "note": manual["note"], "updated_at": time.Now().Unix(), "stale": false})
		_, err = tx.ExecContext(ctx, `UPDATE assets SET extra=jsonb_set(extra,'{honeypot_review}',$2::jsonb,true) WHERE id=$1`, id, string(review))
		if err != nil {
			return result, err
		}
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM asset_honeypot_pending WHERE asset_id=$1`, id)
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}
func (s *AssetStore) RefreshHoneypots(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT asset_id FROM asset_honeypot_pending ORDER BY queued_at,asset_id LIMIT 25`)
	if err != nil {
		return err
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err = s.AssessHoneypot(ctx, id, nil); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	return nil
}

const HoneypotStatusSQL = `(CASE WHEN extra->>'honeypot_stale'='true' THEN 'stale'
 WHEN extra->'honeypot_review'->>'stale'='false' AND extra->'honeypot_review'->>'fingerprint'=extra->'honeypot'->>'fingerprint' AND extra->'honeypot_review'->>'verdict' IN ('confirmed','excluded') THEN extra->'honeypot_review'->>'verdict'
 WHEN NOT (extra ? 'honeypot') THEN 'unassessed'
 WHEN extra->'honeypot'->>'matched'='true' THEN 'suspected' ELSE 'none' END)`
