package db

import (
	"database/sql"
	"encoding/json"
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
