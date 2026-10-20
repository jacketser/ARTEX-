package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const refreshCookie = "artex_refresh"
const refreshLifetime = 30 * 24 * time.Hour

func tokenDigest(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
func randomSessionPart() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func refreshOriginOK(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		scheme := "http"
		if r.TLS != nil || os.Getenv("ARTEX_COOKIE_SECURE") == "true" {
			scheme = "https"
		}
		return err == nil && u.Scheme == scheme && strings.EqualFold(u.Host, r.Host) && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
	}
	return true
}
func (s *Server) refreshKey(hash string) string {
	return tokenDigest(string(sessionSigningKey(s.jwtKey, hash)))
}
func (s *Server) setRefreshCookie(w http.ResponseWriter, r *http.Request, value string, until time.Time) {
	age := int(time.Until(until).Seconds())
	if value == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: value, Path: "/api/auth", HttpOnly: true, Secure: r.TLS != nil || os.Getenv("ARTEX_COOKIE_SECURE") == "true", SameSite: http.SameSiteStrictMode, MaxAge: age, Expires: until})
	w.Header().Set("Cache-Control", "no-store")
}
func (s *Server) accessForSession(id, hash string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: "ARTEX", ID: id, IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL))}).SignedString(sessionSigningKey(s.jwtKey, hash))
}
func (s *Server) issueLogin(w http.ResponseWriter, r *http.Request, hash string) {
	id, secret := randomSessionPart(), randomSessionPart()
	until := time.Now().Add(refreshLifetime)
	result, err := s.m.pg.Exec(`INSERT INTO auth_sessions(id,token_hash,password_key,expires_at,last_used_at) SELECT $1,$2,$3,$4,now() WHERE EXISTS(SELECT 1 FROM settings WHERE key=$5 AND value=$6)`, id, tokenDigest(secret), s.refreshKey(hash), until, authPassKey, hash)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		writeErr(w, 409, "密码已变更，请重新登录")
		return
	}
	tok, err := s.accessForSession(id, hash)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.m.pg.Exec(`DELETE FROM auth_sessions WHERE expires_at<now() OR last_used_at<now()-interval '7 days'`)
	s.setRefreshCookie(w, r, id+"."+secret, until)
	writeJSON(w, 200, map[string]any{"token": tok, "expires_in": int(jwtTTL.Seconds())})
}
func (s *Server) authRefresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !refreshOriginOK(r) || r.Header.Get("X-ARTEX-Session") != "1" {
		writeErr(w, 403, "续期请求来源无效")
		return
	}
	c, err := r.Cookie(refreshCookie)
	if err != nil {
		writeErr(w, 401, "请重新登录")
		return
	}
	id, secret, ok := strings.Cut(c.Value, ".")
	if !ok || len(id) != 43 || len(secret) != 43 {
		writeErr(w, 401, "请重新登录")
		return
	}
	tx, err := s.m.pg.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	defer tx.Rollback()
	var current, previous, binding, hash string
	var until, last, grace time.Time
	var revoked bool
	err = tx.QueryRowContext(r.Context(), `SELECT token_hash,previous_hash,password_key,expires_at,last_used_at,previous_until,revoked FROM auth_sessions WHERE id=$1 FOR UPDATE`, id).Scan(&current, &previous, &binding, &until, &last, &grace, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 401, "请重新登录")
		return
	}
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	err = tx.QueryRowContext(r.Context(), `SELECT value FROM settings WHERE key=$1`, authPassKey).Scan(&hash)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	now := time.Now()
	digest := tokenDigest(secret)
	if revoked || !now.Before(until) || now.Sub(last) > 7*24*time.Hour || binding != s.refreshKey(hash) {
		s.setRefreshCookie(w, r, "", time.Unix(0, 0))
		writeErr(w, 401, "登录已失效")
		return
	}
	// The successor is deterministic only to the server, so a simultaneous retry
	// of the previous token can receive exactly the same successor for 10 seconds.
	mac := hmac.New(sha256.New, s.jwtKey)
	mac.Write([]byte("artex/refresh/v1\x00" + id + "\x00" + secret))
	next := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	switch {
	case hmac.Equal([]byte(digest), []byte(current)):
		_, err = tx.ExecContext(r.Context(), `UPDATE auth_sessions SET previous_hash=token_hash,previous_until=$2,token_hash=$3,last_used_at=$4 WHERE id=$1`, id, now.Add(10*time.Second), tokenDigest(next), now)
	case previous != "" && hmac.Equal([]byte(digest), []byte(previous)) && now.Before(grace) && tokenDigest(next) == current:
		// idempotent retry; do not advance twice
	default:
		// Only a known consumed token proves reuse. Arbitrary bad cookies cannot log
		// out a user merely by guessing/learning a public JWT session identifier.
		if previous != "" && hmac.Equal([]byte(digest), []byte(previous)) {
			_, err = tx.ExecContext(r.Context(), `UPDATE auth_sessions SET revoked=true WHERE id=$1`, id)
			if err == nil {
				err = tx.Commit()
			}
		}
		if err != nil {
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		writeErr(w, 401, "续期凭据无效，请重新登录")
		return
	}
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if err = tx.Commit(); err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	tok, err := s.accessForSession(id, hash)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.setRefreshCookie(w, r, id+"."+next, until)
	writeJSON(w, 200, map[string]any{"token": tok, "expires_in": int(jwtTTL.Seconds())})
}
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if !refreshOriginOK(r) || r.Header.Get("X-ARTEX-Session") != "1" {
		writeErr(w, 403, "退出请求来源无效")
		return
	}
	if c, err := r.Cookie(refreshCookie); err == nil {
		id, secret, ok := strings.Cut(c.Value, ".")
		if ok {
			if _, err = s.m.pg.Exec(`UPDATE auth_sessions SET revoked=true WHERE id=$1 AND (token_hash=$2 OR previous_hash=$2)`, id, tokenDigest(secret)); err != nil {
				writeErr(w, 503, errDataSourceUnavailable)
				return
			}
		}
	}
	s.setRefreshCookie(w, r, "", time.Unix(0, 0))
	writeJSON(w, 200, map[string]any{"ok": true})
}
