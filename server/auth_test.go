package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// GetSetting 对"键不存在"和"读取出错"的返回值只差一个 error：两种情况 value 都是
// 空串。密码相关的 handler 一旦把 error 当成"还没设置密码"，就会在数据库抖动期间
// 敞开初始化入口——authInit 会放行一个未认证请求去覆盖已有的管理员密码，
// authStatus 则会把前端直接送到 /setup 去照着做这件事。
//
// 这两个测试把 handler 的连接池关掉来制造读取失败，断言两处都 fail closed。
func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	// 关掉池子，让后续 GetSetting 返回 error 而不是 sql.ErrNoRows。
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败被当成未初始化会把用户送去 /setup 覆盖密码); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("读失败时不应回答 initialized，得到 %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"password":"correct horse battery"}`)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", body))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败时放行会让未认证请求覆盖已有密码); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("读失败时不应签发 token: %s", w.Body.String())
	}
}

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name, pw string
		wantErr  bool
	}{
		{"空", "", true},
		{"七位", "1234567", true},
		{"八位", "12345678", false},
		{"八个汉字按字符数而非字节数计", "密码密码密码密码", false},
		{"三个汉字够 9 字节但只有 3 个字符", "密码强", true},
		{"72 字节", strings.Repeat("a", 72), false},
		{"73 字节超出 bcrypt 上限", strings.Repeat("a", 73), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.pw); (got != "") != tc.wantErr {
				t.Fatalf("validatePassword(%q)=%q, wantErr=%v", tc.pw, got, tc.wantErr)
			}
		})
	}
}

// Route tests authenticate through the same password-bound signing key as login.
func signTestJWT(t *testing.T, s *Server) (string, error) {
	t.Helper()
	hash, ok, err := s.m.PG().GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || hash == "" {
		hash = "test-only-password-hash"
		if err := s.m.PG().SetSetting(authPassKey, hash); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.m.PG().Exec(`DELETE FROM settings WHERE key=$1 AND value=$2`, authPassKey, hash) })
	}
	return signJWT(sessionSigningKey(s.jwtKey, hash))
}

func TestPasswordResetRevokesSessions(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := &Server{m: m, jwtKey: []byte("01234567890123456789012345678901")}
	old, exists, err := m.PG().GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if exists {
			_ = m.PG().SetSetting(authPassKey, old)
		} else {
			_, _ = m.PG().Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
		}
	}()
	_ = m.PG().SetSetting(authPassKey, "hash-before-reset")
	token, _ := signJWT(sessionSigningKey(s.jwtKey, "hash-before-reset"))
	if ok, err := s.validSession(token); !ok || err != nil {
		t.Fatalf("before reset: %v %v", ok, err)
	}
	// Same SQL operation as the reset script, with no separate revision to forget.
	_ = m.PG().SetSetting(authPassKey, "hash-after-reset")
	if ok, _ := s.validSession(token); ok {
		t.Fatal("old token survived password reset")
	}
	legacy, _ := signJWT(s.jwtKey)
	if ok, _ := s.validSession(legacy); ok {
		t.Fatal("legacy unbound token accepted")
	}
	newToken, _ := signJWT(sessionSigningKey(s.jwtKey, "hash-after-reset"))
	if ok, err := s.validSession(newToken); !ok || err != nil {
		t.Fatalf("new login: %v %v", ok, err)
	}
	changed, err := m.PG().CompareAndSwapSetting(authPassKey, "hash-before-reset", "stale-write")
	if err != nil || changed {
		t.Fatal("stale password change overwrote reset")
	}
}
