package server

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestCaptureToggleKeepsAgentAndBrowserProtection(t *testing.T) {
	s, _, req := trafficEvidenceServer(t)
	m := s.m
	oldCapture := m.TrafficEnabled()
	t.Cleanup(func() { m.SetTrafficEnabled(oldCapture) })
	servers, err := m.pg.ListMCP()
	if err != nil {
		t.Fatal(err)
	}
	var browser *db.MCPServer
	for _, srv := range servers {
		if srv.Name == browserMCPName {
			browser = srv
			break
		}
	}
	if browser == nil {
		t.Fatal("seeded browser missing")
	}
	prior := *browser
	t.Cleanup(func() { m.pg.SaveMCP(&prior) })
	oldProxy := m.GlobalProxy()
	t.Cleanup(func() { m.SetGlobalProxy(oldProxy) })
	if err := m.SetGlobalProxy("http://upstream.example.test:8080"); err != nil {
		t.Fatal(err)
	}
	for _, capture := range []bool{false, true, false} {
		if err := m.SetTrafficEnabled(capture); err != nil {
			t.Fatal(err)
		}
		if m.traffic.CaptureEnabled() != capture || m.TrafficEnabled() != capture {
			t.Fatal("capture state drift")
		}
		if m.ProxyAddr() != m.traffic.ProxyAddr() || m.ProxyCACert() != m.traffic.CACertPath() {
			t.Fatal("security route or CA removed")
		}
		u, err := url.Parse(m.TaskProxyAddr("42"))
		if err != nil || u.User == nil || u.User.Username() != "task-42" {
			t.Fatal("task attribution lost")
		}
		if (len(m.HostTools()) > 0) != capture {
			t.Fatal("traffic tools do not match capture state")
		}
		if m.GlobalProxy() != "http://upstream.example.test:8080" {
			t.Fatal("upstream configuration lost")
		}
		servers, err := m.pg.ListMCP()
		if err != nil {
			t.Fatal(err)
		}
		for _, srv := range servers {
			if srv.Name != browserMCPName {
				continue
			}
			args := decodeStrSlice(srv.Args)
			if !strings.Contains(strings.Join(args, " "), "--proxy-server "+m.ProxyAddr()) {
				t.Fatal("browser route removed", args)
			}
			if decodeStrMap(srv.Env)["NODE_EXTRA_CA_CERTS"] != m.ProxyCACert() {
				t.Fatal("browser CA removed")
			}
		}
		w := req("GET", "/api/proxy-security/stats", "")
		var stats struct {
			ProxyConfigured bool `json:"proxy_configured"`
			CaptureEnabled  bool `json:"capture_enabled"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &stats) != nil || !stats.ProxyConfigured || stats.CaptureEnabled != capture {
			t.Fatal("status conflates protection with persistence", w.Body)
		}
	}
	// Persisted capture-off state must already apply before the proxy starts.
	restarted, err := NewManager(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.traffic == nil || restarted.traffic.CaptureEnabled() || restarted.ProxyCACert() == "" || restarted.ProxyAddr() != restarted.traffic.ProxyAddr() {
		t.Fatal("restart lost protection/persistence split")
	}
}
