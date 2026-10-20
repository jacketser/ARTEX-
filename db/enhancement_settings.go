package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/honeydetect"
	"github.com/Autumn-27/artex/scenarioprompt"
)

const HoneyRulesKey = "honeypot_rules"
const ScenarioKey = "scenario_prompts"

func (d *DB) HoneypotRules() (honeydetect.RuleSet, error) {
	cfg := honeydetect.DefaultRules()
	v, ok, err := d.GetSetting(HoneyRulesKey)
	if err != nil {
		return cfg, err
	}
	if ok {
		if err = json.Unmarshal([]byte(v), &cfg); err != nil {
			return cfg, err
		}
	}
	return cfg, cfg.Validate()
}
func (d *DB) SaveHoneypotRules(ctx context.Context, cfg honeydetect.RuleSet) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(cfg)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(722681)"); err != nil {
		return err
	}
	old := honeydetect.DefaultRules()
	var prior string
	readErr := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=$1", HoneyRulesKey).Scan(&prior)
	if readErr != nil && readErr != sql.ErrNoRows {
		return readErr
	}
	same := true
	if readErr == nil {
		same = json.Unmarshal([]byte(prior), &old) == nil
	}
	same = same && old.Revision() == cfg.Revision()
	_, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, HoneyRulesKey, string(b))
	if err != nil {
		return err
	}
	if same {
		return tx.Commit()
	}
	_, err = tx.ExecContext(ctx, `UPDATE assets SET extra=CASE WHEN extra ? 'honeypot_review' THEN jsonb_set(jsonb_set(COALESCE(extra,'{}'),'{honeypot_stale}','true',true),'{honeypot_review,stale}','true',true) ELSE jsonb_set(COALESCE(extra,'{}'),'{honeypot_stale}','true',true) END WHERE type='service'`)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *AssetStore) ScenarioConfig() (scenarioprompt.Config, error) {
	c := scenarioprompt.Default()
	v, ok, err := s.db.GetSetting(ScenarioKey)
	if err != nil {
		return c, err
	}
	if ok {
		if err = json.Unmarshal([]byte(v), &c); err != nil {
			return c, err
		}
	}
	return c, c.Validate()
}
func (d *DB) SaveScenarioConfig(c scenarioprompt.Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("配置编码失败: %w", err)
	}
	return d.SetSetting(ScenarioKey, string(b))
}
