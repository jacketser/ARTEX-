package server

import (
	"context"
	"net/url"
	"os"
)

// Load current credentials on each guarded exchange so profile edits/password
// resets have no stale-cache window. Query errors fail closed in the proxy.
func (m *Manager) trafficSecrets(ctx context.Context) ([]string, error) {
	secrets := []string{os.Getenv("OPENAI_API_KEY"), os.Getenv("ANTHROPIC_API_KEY"), os.Getenv("ARTEX_PG_DSN")}
	if u, e := url.Parse(os.Getenv("ARTEX_PG_DSN")); e == nil && u.User != nil {
		if p, ok := u.User.Password(); ok {
			secrets = append(secrets, p)
		}
	}
	rows, err := m.pg.QueryContext(ctx, `SELECT api_key FROM llm_profiles WHERE api_key IS NOT NULL UNION ALL SELECT value FROM settings WHERE key IN ($1,$2,$3)`, authPassKey, settingBraveKey, settingTavilyKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var secret string
		if err := rows.Scan(&secret); err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	return secrets, rows.Err()
}
