package traffic

import (
	"errors"
	"time"
)

// SecurityConfig has hard ceilings; credential checks and redaction cannot be disabled.
type SecurityConfig struct {
	HostRequests         int `json:"host_requests_per_minute"`
	HostURLs             int `json:"host_distinct_urls_per_minute"`
	URLRequests          int `json:"url_requests_per_minute"`
	TaskRequests         int `json:"task_requests_per_minute"`
	UnattributedRequests int `json:"unattributed_requests_per_minute"`
	CooldownSeconds      int `json:"cooldown_seconds"`
	MaxBodyKiB           int `json:"max_body_kib"`
}

func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{3000, 1500, 120, 3000, 3000, 60, 5120}
}
func (c SecurityConfig) Validate() error {
	if c.HostRequests < 1 || c.HostRequests > 30000 || c.HostURLs < 1 || c.HostURLs > 3000 || c.HostURLs > c.HostRequests || c.URLRequests < 1 || c.URLRequests > c.HostRequests || c.TaskRequests < 1 || c.TaskRequests > 30000 || c.UnattributedRequests < 1 || c.UnattributedRequests > 30000 || c.CooldownSeconds < 1 || c.CooldownSeconds > 3600 || c.MaxBodyKiB < 1 || c.MaxBodyKiB > 5120 {
		return errors.New("代理限额无效：请求数 1–30000、不同 URL 1–3000，单 URL/不同 URL 不得超过主机请求数；冷却 1–3600 秒，正文 1–5120 KiB")
	}
	return nil
}
func (t *Traffic) SetSecurityConfig(c SecurityConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	t.security.mu.Lock()
	defer t.security.mu.Unlock()
	t.security.config = &c // preserve counters/cooldowns when changing limits
	return nil
}
func (g *securityGuard) policyLocked() SecurityConfig {
	if g.config == nil {
		return DefaultSecurityConfig()
	}
	return *g.config
}
func (t *Traffic) SecurityConfig() SecurityConfig {
	t.security.mu.Lock()
	defer t.security.mu.Unlock()
	return t.security.policyLocked()
}

type SecurityStats struct {
	Allowed         uint64            `json:"allowed"`
	Blocked         map[string]uint64 `json:"blocked"`
	TrackedHosts    int               `json:"tracked_hosts"`
	TrackedTasks    int               `json:"tracked_tasks"`
	ActiveCooldowns int               `json:"active_cooldowns"`
}

func (t *Traffic) SecurityStats() SecurityStats {
	g := &t.security
	g.mu.Lock()
	defer g.mu.Unlock()
	out := SecurityStats{Allowed: g.allowed.Load(), Blocked: map[string]uint64{}, TrackedHosts: len(g.hosts), TrackedTasks: len(g.tasks)}
	for k, v := range g.blocked {
		out.Blocked[k] = v
	}
	for _, ws := range []map[string]*hostWindow{g.hosts, g.tasks} {
		for _, w := range ws {
			if time.Now().Before(w.blockedUntil) {
				out.ActiveCooldowns++
			}
		}
	}
	return out
}
func (g *securityGuard) block(reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.blocked == nil {
		g.blocked = map[string]uint64{}
	}
	g.blocked[reason]++
}
