package server

import (
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/honeydetect"
	"github.com/Autumn-27/artex/traffic"
	"net/http/httptest"
	"strings"
	"sync"
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
