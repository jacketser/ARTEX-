package server

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/traffic"
)

func TestPassthroughPolicyMigrationAndAPI(t *testing.T) {
	s, _, req := trafficEvidenceServer(t)
	old, exists, err := s.m.pg.GetSetting(proxySecurityKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if exists {
			s.m.pg.SetSetting(proxySecurityKey, old)
		} else {
			s.m.pg.Exec("DELETE FROM settings WHERE key=$1", proxySecurityKey)
		}
	})
	// Older persisted settings have no mode; upgrade must default to refusal.
	legacy := `{"host_requests_per_minute":3000,"host_distinct_urls_per_minute":1500,"url_requests_per_minute":120,"task_requests_per_minute":13,"unattributed_requests_per_minute":3000,"cooldown_seconds":60,"max_body_kib":5120}`
	if err := s.m.pg.SetSetting(proxySecurityKey, legacy); err != nil {
		t.Fatal(err)
	}
	s.m.applyProxySecurity()
	if cfg := s.m.traffic.SecurityConfig(); cfg.PassthroughMode != "block" || cfg.TaskRequests != 13 {
		t.Fatal("legacy limits or default mode lost", cfg)
	}
	for _, mode := range []string{"allow", "block"} {
		cfg := traffic.DefaultSecurityConfig()
		cfg.PassthroughMode = mode
		body, _ := json.Marshal(cfg)
		if w := req("PUT", "/api/settings/proxy-security", string(body)); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		if current, err := s.m.proxySecurityConfig(); err != nil || current.PassthroughMode != mode || s.m.traffic.SecurityConfig().PassthroughMode != mode {
			t.Fatal("mode not persisted/applied", current, err)
		}
	}
	for _, mode := range []string{"", "invalid"} {
		cfg := traffic.DefaultSecurityConfig()
		cfg.PassthroughMode = mode
		body, _ := json.Marshal(cfg)
		if w := req("PUT", "/api/settings/proxy-security", string(body)); w.Code != 400 {
			t.Fatal("invalid mode accepted", w.Code)
		}
		if cfg, err := s.m.proxySecurityConfig(); err != nil || cfg.PassthroughMode != "block" {
			t.Fatal("invalid input changed policy")
		}
	}
}
