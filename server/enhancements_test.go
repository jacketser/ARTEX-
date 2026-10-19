package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnhancedAuthAndSSEThroughHTTP(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	original, existed, err := m.PG().GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if existed {
			_ = m.PG().SetSetting(authPassKey, original)
		} else {
			_, _ = m.PG().Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
		}
	}()
	_, err = m.PG().Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m, jwtKey: []byte("01234567890123456789012345678901")}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/init", s.authInit)
	mux.HandleFunc("POST /api/auth/login", s.authLogin)
	mux.HandleFunc("POST /api/auth/change-password", s.authChangePassword)
	mux.HandleFunc("POST /api/sse-ticket", s.issueSSETicket)
	mux.HandleFunc("GET /api/logs/stream", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	h := s.requireAuth(mux)
	request := func(method, path, body, token string) (int, map[string]any) {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var result map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &result)
		return w.Code, result
	}
	code, out := request("POST", "/api/auth/init", `{"password":"original-password"}`, "")
	if code != 200 {
		t.Fatalf("init status=%d", code)
	}
	token := out["token"].(string)
	if code, _ := request("POST", "/api/auth/init", `{"password":"overwrite-password"}`, ""); code != 403 {
		t.Fatalf("reinitialize status=%d", code)
	}
	code, out = request("POST", "/api/sse-ticket", `{"path":"/api/logs/stream?since=0"}`, token)
	if code != 200 {
		t.Fatalf("ticket status=%d", code)
	}
	ticket := out["ticket"].(string)
	if code, _ := request("GET", "/api/logs/stream?since=0&ticket="+ticket, "", ""); code != 200 {
		t.Fatalf("consume status=%d", code)
	}
	if code, _ := request("GET", "/api/logs/stream?since=0&ticket="+ticket, "", token); code != 401 {
		t.Fatalf("replay with valid bearer status=%d", code)
	}
	code, out = request("POST", "/api/sse-ticket", `{"path":"/api/logs/stream"}`, token)
	if code != 200 {
		t.Fatal(code)
	}
	unused := out["ticket"].(string)
	if code, _ := request("POST", "/api/auth/change-password", `{"old_password":"original-password","new_password":"replacement-password"}`, token); code != 200 {
		t.Fatalf("change status=%d", code)
	}
	if code, _ := request("GET", "/api/logs/stream", "", token); code != 401 {
		t.Fatalf("old token status=%d", code)
	}
	if code, _ := request("GET", "/api/logs/stream?ticket="+unused, "", ""); code != 401 {
		t.Fatalf("old ticket survived password change: %d", code)
	}
	if code, _ := request("POST", "/api/auth/login", `{"username":"ARTEX","password":"replacement-password"}`, ""); code != 200 {
		t.Fatalf("new login status=%d", code)
	}
}

func TestOpenSSERevocationCancelsRequest(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	old, existed, _ := m.PG().GetSetting(authPassKey)
	defer func() {
		if existed {
			_ = m.PG().SetSetting(authPassKey, old)
		} else {
			_, _ = m.PG().Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
		}
	}()
	_ = m.PG().SetSetting(authPassKey, "before")
	s := &Server{m: m, jwtKey: []byte("01234567890123456789012345678901")}
	token, _ := signJWT(sessionSigningKey(s.jwtKey, "before"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serveAuthenticatedStream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }), httptest.NewRecorder(), httptest.NewRequest("GET", "/api/logs/stream", nil).WithContext(ctx), token)
	}()
	_ = m.PG().SetSetting(authPassKey, "after")
	select {
	case <-done:
	case <-time.After(17 * time.Second):
		t.Fatal("revoked stream remained open")
	}
}
