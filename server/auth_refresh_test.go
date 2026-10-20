package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestRefreshSessionLifecycle(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	old, exists, err := m.pg.GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if exists {
			_ = m.pg.SetSetting(authPassKey, old)
		} else {
			m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
		}
	}()
	m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
	s := &Server{m: m, jwtKey: []byte("01234567890123456789012345678901")}
	call := func(fn http.HandlerFunc, body string, c *http.Cookie, origin, header string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost/api/auth/refresh", strings.NewReader(body))
		if c != nil {
			r.AddCookie(c)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r.Header.Set("X-ARTEX-Session", header)
		w := httptest.NewRecorder()
		fn(w, r)
		return w
	}
	token := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var out struct{ Token string }
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		return out.Token
	}
	w := call(s.authInit, `{"password":"initial-password"}`, nil, "", "1")
	access := token(w)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing refresh cookie")
	}
	first := cookies[0]
	if !first.HttpOnly || first.Path != "/api/auth" || first.SameSite != http.SameSiteStrictMode || first.MaxAge < 29*86400 {
		t.Fatal("unsafe cookie attributes")
	}
	var claims jwt.RegisteredClaims
	jwt.NewParser().ParseUnverified(access, &claims)
	if claims.ID == "" || time.Until(claims.ExpiresAt.Time) > jwtTTL {
		t.Fatal("access not bounded/session bound")
	}
	defer m.pg.Exec(`DELETE FROM auth_sessions WHERE id=$1`, claims.ID)
	var stored string
	if e := m.pg.QueryRow(`SELECT token_hash FROM auth_sessions WHERE id=$1`, claims.ID).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(first.Value, stored) {
		t.Fatal("raw refresh persisted")
	}
	for _, tc := range []struct{ origin, header string }{{"https://evil.test", "1"}, {"http://localhost", ""}, {"null", "1"}} {
		if r := call(s.authRefresh, "", first, tc.origin, tc.header); r.Code != 403 {
			t.Fatalf("CSRF accepted: %d", r.Code)
		}
	}
	w = call(s.authRefresh, "", first, "http://localhost", "1")
	access = token(w)
	second := w.Result().Cookies()[0]
	if second.Value == first.Value {
		t.Fatal("token not rotated")
	}
	retry := call(s.authRefresh, "", first, "", "1")
	token(retry)
	if retry.Result().Cookies()[0].Value != second.Value {
		t.Fatal("concurrent retry advanced twice")
	}
	id, _, _ := strings.Cut(first.Value, ".")
	bad := *first
	bad.Value = id + "." + strings.Repeat("x", 43)
	if r := call(s.authRefresh, "", &bad, "", "1"); r.Code != 401 {
		t.Fatal("invalid cookie accepted")
	}
	if valid, e := s.validSession(access); !valid || e != nil {
		t.Fatal("invalid guess revoked valid session")
	}
	// Reuse of the immediately consumed credential after grace revokes the family.
	m.pg.Exec(`UPDATE auth_sessions SET previous_until=now()-interval '1 second' WHERE id=$1`, id)
	if r := call(s.authRefresh, "", first, "", "1"); r.Code != 401 {
		t.Fatal("reuse accepted")
	}
	if valid, _ := s.validSession(access); valid {
		t.Fatal("reuse did not revoke access")
	}
	w = call(s.authLogin, `{"username":"ARTEX","password":"initial-password"}`, nil, "", "1")
	access = token(w)
	c := w.Result().Cookies()[0]
	if r := call(s.authLogout, "", c, "", "1"); r.Code != 200 || r.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout failed")
	}
	if valid, _ := s.validSession(access); valid {
		t.Fatal("logout left access valid")
	}
	if r := call(s.authRefresh, "", c, "", "1"); r.Code != 401 {
		t.Fatal("logout left refresh valid")
	}
	for _, mode := range []string{"idle", "absolute", "password"} {
		w = call(s.authLogin, `{"username":"ARTEX","password":"initial-password"}`, nil, "", "1")
		token(w)
		c = w.Result().Cookies()[0]
		id, _, _ = strings.Cut(c.Value, ".")
		switch mode {
		case "idle":
			m.pg.Exec(`UPDATE auth_sessions SET last_used_at=now()-interval '8 days' WHERE id=$1`, id)
		case "absolute":
			m.pg.Exec(`UPDATE auth_sessions SET expires_at=now()-interval '1 second' WHERE id=$1`, id)
		case "password":
			m.pg.SetSetting(authPassKey, "replacement-hash")
		}
		if r := call(s.authRefresh, "", c, "", "1"); r.Code != 401 {
			t.Fatalf("%s not revoked: %d", mode, r.Code)
		}
	}

}

func TestIssueLoginRejectsChangedPassword(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := &Server{m: m, jwtKey: []byte("01234567890123456789012345678901")}
	w := httptest.NewRecorder()
	s.issueLogin(w, httptest.NewRequest("POST", "/", nil), "non-current-hash")
	if w.Code != 409 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("racing password change issued session: %d", w.Code)
	}
}

func TestRefreshFailsClosed(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.pg.Close()
	s := &Server{m: m}
	r := httptest.NewRequest("POST", "/api/auth/refresh", nil)
	r.Header.Set("X-ARTEX-Session", "1")
	r.AddCookie(&http.Cookie{Name: refreshCookie, Value: strings.Repeat("a", 43) + "." + strings.Repeat("b", 43)})
	w := httptest.NewRecorder()
	s.authRefresh(w, r)
	if w.Code != 503 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestRefreshSecureCookieAndOrigin(t *testing.T) {
	t.Setenv("ARTEX_COOKIE_SECURE", "true")
	s := &Server{}
	r := httptest.NewRequest("POST", "http://example.test/api/auth/refresh", nil)
	r.Header.Set("Origin", "https://example.test")
	if !refreshOriginOK(r) {
		t.Fatal("trusted HTTPS origin rejected")
	}
	w := httptest.NewRecorder()
	s.setRefreshCookie(w, r, "credential", time.Now().Add(time.Hour))
	if !w.Result().Cookies()[0].Secure {
		t.Fatal("HTTPS deployment cookie insecure")
	}
	r.Header.Set("Origin", "http://example.test")
	if refreshOriginOK(r) {
		t.Fatal("scheme downgrade accepted")
	}
}

func TestConcurrentRefreshRotatesOnce(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	old, exists, err := m.pg.GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if exists {
			_ = m.pg.SetSetting(authPassKey, old)
		} else {
			m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
		}
	}()
	if err = m.pg.SetSetting(authPassKey, "concurrency-test-hash"); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m, jwtKey: []byte("01234567890123456789012345678901")}
	w := httptest.NewRecorder()
	s.issueLogin(w, httptest.NewRequest("POST", "/api/auth/login", nil), "concurrency-test-hash")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	cookie := w.Result().Cookies()[0]
	id, _, _ := strings.Cut(cookie.Value, ".")
	defer m.pg.Exec(`DELETE FROM auth_sessions WHERE id=$1`, id)
	done := make(chan *httptest.ResponseRecorder, 8)
	for i := 0; i < 8; i++ {
		go func() {
			r := httptest.NewRequest("POST", "/api/auth/refresh", nil)
			r.Header.Set("X-ARTEX-Session", "1")
			r.AddCookie(cookie)
			out := httptest.NewRecorder()
			s.authRefresh(out, r)
			done <- out
		}()
	}
	next := ""
	for i := 0; i < 8; i++ {
		out := <-done
		if out.Code != 200 {
			t.Fatalf("concurrent status=%d", out.Code)
		}
		value := out.Result().Cookies()[0].Value
		if next != "" && value != next {
			t.Fatal("concurrent refresh diverged")
		}
		next = value
	}
}
