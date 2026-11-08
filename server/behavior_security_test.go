package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/honeydetect"
	"github.com/Autumn-27/artex/traffic"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBehaviorAuthorizationAuditAndPolicyAPI(t *testing.T) {
	s, _, req := trafficEvidenceServer(t)
	for _, key := range []string{behaviorKey, proxySecurityKey} {
		old, ok, e := s.m.pg.GetSetting(key)
		if e != nil {
			t.Fatal(e)
		}
		s.m.pg.Exec("DELETE FROM settings WHERE key=$1", key)
		t.Cleanup(func() {
			if ok {
				s.m.pg.SetSetting(key, old)
			} else {
				s.m.pg.Exec("DELETE FROM settings WHERE key=$1", key)
			}
		})
	}
	paths := []string{"/api/settings/honeypot-behavior", "/api/settings/proxy-security", "/api/proxy-security/stats"}
	for _, path := range paths {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Fatal("unauthenticated access", path, w.Code)
		}
		if w = req("GET", path, ""); w.Code != 200 {
			t.Fatal(path, w.Code, w.Body)
		}
	}
	for _, path := range paths[:2] {
		for _, bad := range []string{`{}`, `{"unknown":true}`, `{} {}`} {
			if w := req("PUT", path, bad); w.Code != 400 {
				t.Fatal("invalid config", path, w.Code, w.Body)
			}
		}
	}
	c := traffic.DefaultSecurityConfig()
	c.TaskRequests = 7
	b, _ := json.Marshal(c)
	if w := req("PUT", paths[1], string(b)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if s.m.traffic.SecurityConfig().TaskRequests != 7 {
		t.Fatal("policy not applied")
	}
	var id int64
	if e := s.m.pg.QueryRow(`INSERT INTO assets(type,url,service_name) VALUES('service','http://127.0.0.1:1','HTTP') RETURNING id`).Scan(&id); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.m.pg.Exec("DELETE FROM assets WHERE id=$1", id) })
	path := fmt.Sprintf("/api/assets/%d/honeypot-behavior", id)
	consent := `{"confirm":true,"origin":"http://127.0.0.1:1"}`
	if w := req("POST", path, consent); w.Code != 403 {
		t.Fatal("default enabled", w.Code, w.Body)
	}
	b, _ = json.Marshal(honeydetect.BehaviorConfig{Enabled: true, AllowedOrigins: []string{"http://127.0.0.1:1"}})
	if w := req("PUT", paths[0], string(b)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, body := range []string{`{"confirm":false,"origin":"http://127.0.0.1:1"}`, `{"confirm":true,"origin":"http://other.test"}`} {
		w := req("POST", path, body)
		if w.Code != 400 && w.Code != 409 {
			t.Fatal(w.Code, w.Body)
		}
	}
	// The allowed origin still cannot reach loopback; the attempted check is audited.
	if w := req("POST", path, consent); w.Code != 200 || !strings.Contains(w.Body.String(), "inconclusive") {
		t.Fatal(w.Code, w.Body)
	}
	if w := req("POST", path, consent); w.Code != 429 {
		t.Fatal("cooldown bypass", w.Code, w.Body)
	}
	if w := req("GET", path, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "http://127.0.0.1:1") {
		t.Fatal(w.Code, w.Body)
	}
	// Changing only the algorithm must invalidate old verdicts, while preserving
	// the recorded outcome and never issuing another request.
	for _, version := range []string{honeydetect.BehaviorVersion, "http-behavior-v4", "http-behavior-v3", "http-behavior-v2", "http-behavior-v1", ""} {
		stored := map[string]any{"version": version, "outcome": "needs_review", "signals": []string{"legacy content signal"}}
		if version == honeydetect.BehaviorVersion {
			stored["outcome"] = "no_signal"
			stored["signals"] = []string{}
			stored["content_warnings"] = []string{"independent content warning"}
		}
		result, _ := json.Marshal(stored)
		if _, err := s.m.pg.Exec("UPDATE asset_honeypot_probes SET result=$1::jsonb WHERE asset_id=$2", string(result), id); err != nil {
			t.Fatal(err)
		}
		w := req("GET", path, "")
		var records []behaviorRecord
		if err := json.Unmarshal(w.Body.Bytes(), &records); err != nil || w.Code != 200 || len(records) != 1 {
			t.Fatal("history", w.Code, w.Body, err)
		}
		var want, got any
		_ = json.Unmarshal(result, &want)
		err := json.Unmarshal(records[0].Result, &got)
		if err != nil || records[0].Stale != (version != honeydetect.BehaviorVersion) || !reflect.DeepEqual(got, want) {
			t.Fatal("algorithm version not respected or history rewritten", w.Body)
		}
	}
	if _, e := s.m.pg.Exec("UPDATE assets SET page_title='changed' WHERE id=$1", id); e != nil {
		t.Fatal(e)
	}
	if w := req("GET", path, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"stale":true`) {
		t.Fatal("history not stale", w.Body)
	}
	if w := req("GET", path+"?before=-1", ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestBehaviorUpstreamAPIAndPolicyChanges(t *testing.T) {
	for _, mode := range []string{"normal", "proxy_changed", "authorization_revoked", "budget"} {
		t.Run(mode, func(t *testing.T) {
			s, _, req := trafficEvidenceServer(t)
			// The shared read-only fixture deliberately starts with a cancelled
			// service context; active probes need a live request lifetime.
			s.ctx = t.Context()
			for _, key := range []string{behaviorKey, proxySecurityKey} {
				old, ok, err := s.m.pg.GetSetting(key)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if ok {
						s.m.pg.SetSetting(key, old)
					} else {
						s.m.pg.Exec("DELETE FROM settings WHERE key=$1", key)
					}
				})
			}
			origin := "http://192.0.2.12:8080"
			policy, _ := json.Marshal(honeydetect.BehaviorConfig{Enabled: true, AllowedOrigins: []string{origin}})
			if err := s.m.pg.SetSetting(behaviorKey, string(policy)); err != nil {
				t.Fatal(err)
			}
			cfg := traffic.DefaultSecurityConfig()
			if mode == "budget" {
				cfg.UnattributedRequests = 1
			}
			b, _ := json.Marshal(cfg)
			if w := req("PUT", "/api/settings/proxy-security", string(b)); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			var id int64
			if err := s.m.pg.QueryRow(`INSERT INTO assets(type,url) VALUES('service',$1) RETURNING id`, origin).Scan(&id); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.m.pg.Exec("DELETE FROM assets WHERE id=$1", id) })
			var hits atomic.Int32
			p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" || r.Host != "192.0.2.12:8080" {
					t.Errorf("not pinned: %s %s", r.Method, r.Host)
					w.WriteHeader(400)
					return
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
				target, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					t.Error(err)
					return
				}
				target.Body.Close()
				if target.Host != "192.0.2.12:8080" || target.Header.Get("Proxy-Authorization") != "" {
					t.Error("target headers changed")
				}
				hits.Add(1)
				switch mode {
				case "proxy_changed":
					s.m.mu.Lock()
					s.m.globalProxy = "http://127.0.0.1:1"
					s.m.mu.Unlock()
				case "authorization_revoked":
					if err := s.m.pg.SetSetting(behaviorKey, `{"enabled":false,"allowed_origins":[]}`); err != nil {
						t.Error(err)
					}
				}
				io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
				if target.Method != "HEAD" {
					io.WriteString(conn, "ok")
				}
			}))
			defer p.Close()
			s.m.mu.Lock()
			s.m.globalProxy = p.URL
			s.m.mu.Unlock()
			path := fmt.Sprintf("/api/assets/%d/honeypot-behavior", id)
			w := req("POST", path, `{"confirm":true,"origin":"`+origin+`"}`)
			want := int32(4)
			if mode != "normal" {
				want = 1
			}
			if w.Code != 200 || hits.Load() != want {
				t.Fatalf("status=%d hits=%d body=%s", w.Code, hits.Load(), w.Body)
			}
			if mode != "normal" && !strings.Contains(w.Body.String(), "security_budget_or_policy") {
				t.Fatal("policy change ignored", w.Body)
			}
			if history := req("GET", path, ""); history.Code != 200 || !strings.Contains(history.Body.String(), origin) {
				t.Fatal("missing audit", history.Code, history.Body)
			}
		})
	}
}
func TestBehaviorReservationsAreAtomic(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	old, ok, e := s.m.pg.GetSetting(behaviorKey)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if ok {
			s.m.pg.SetSetting(behaviorKey, old)
		} else {
			s.m.pg.Exec("DELETE FROM settings WHERE key=$1", behaviorKey)
		}
	})
	var id int64
	s.m.pg.QueryRow(`INSERT INTO assets(type,url) VALUES('service','http://lab.example.test') RETURNING id`).Scan(&id)
	if id == 0 {
		t.Fatal("asset")
	}
	t.Cleanup(func() { s.m.pg.Exec("DELETE FROM assets WHERE id=$1", id) })
	b, _ := json.Marshal(honeydetect.BehaviorConfig{Enabled: true, AllowedOrigins: []string{"http://lab.example.test"}})
	s.m.pg.SetSetting(behaviorKey, string(b))
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.reserveBehavior(t.Context(), id, "http://lab.example.test", "test", "test")
			if e == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatal("duplicate probes admitted", accepted)
	}
}
