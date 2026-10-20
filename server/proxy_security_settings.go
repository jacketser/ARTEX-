package server

import (
	"encoding/json"
	"github.com/Autumn-27/artex/traffic"
	"net/http"
)

const proxySecurityKey = "proxy_security"

func (m *Manager) proxySecurityConfig() (traffic.SecurityConfig, error) {
	c := traffic.DefaultSecurityConfig()
	v, ok, err := m.pg.GetSetting(proxySecurityKey)
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
func (m *Manager) applyProxySecurity() {
	if m.traffic == nil {
		return
	}
	c, err := m.proxySecurityConfig()
	if err != nil {
		m.traffic.SetSecurityUnavailable(true)
		return
	}
	m.traffic.SetSecurityConfig(c)
	m.traffic.SetSecurityUnavailable(false)
}
func (s *Server) proxySecuritySettings(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if r.Method == http.MethodPut {
		var c traffic.SecurityConfig
		if !decodeEnhancement(w, r, &c) {
			return
		}
		if err := c.Validate(); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		b, _ := json.Marshal(c)
		if err := s.m.pg.SetSetting(proxySecurityKey, string(b)); err != nil {
			writeErr(w, 503, "保存代理安全配置失败")
			return
		}
		s.m.applyProxySecurity()
	}
	c, err := s.m.proxySecurityConfig()
	if err != nil {
		writeErr(w, 503, "代理安全配置不可用")
		return
	}
	writeJSON(w, 200, c)
}
func (s *Server) proxySecurityStats(w http.ResponseWriter, r *http.Request) {
	var stats any
	if s.m.traffic != nil {
		stats = s.m.traffic.SecurityStats()
	}
	writeJSON(w, 200, map[string]any{"capture_enabled": s.m.TrafficEnabled(), "stats": stats, "scope": "process_lifetime"})
}
