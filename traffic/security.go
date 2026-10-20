package traffic

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

const maxGuardBody = 5 * 1024 * 1024
const guardUA = "Mozilla/5.0 (compatible; ARTEX/1.0; authorized-security-assessment)"

type hostWindow struct {
	start, blockedUntil time.Time
	total               int
	urls                map[[32]byte]int
}
type securityGuard struct {
	mu          sync.Mutex
	hosts       map[string]*hostWindow
	tasks       map[string]*hostWindow
	config      *SecurityConfig
	allowed     atomic.Uint64
	unavailable atomic.Bool
	blocked     map[string]uint64
	owners      sync.Map
	taskKey     []byte
	source      func(context.Context) ([]string, error)
}

// SetSecretSource must be installed before serving traffic. Reads are bounded by
// the caller's context; errors fail closed. Values are never emitted in audit logs.
func (t *Traffic) SetSecretSource(source func(context.Context) ([]string, error)) {
	t.security.mu.Lock()
	defer t.security.mu.Unlock()
	t.security.source = source
}
func (t *Traffic) secrets(ctx context.Context) ([]string, error) {
	t.security.mu.Lock()
	source := t.security.source
	t.security.mu.Unlock()
	if source == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return source(ctx)
}

// Per authority: allow ordinary scanners, stop tight loops / unbounded crawls.
// Fixed one-minute windows and bounded maps prevent the guard itself growing.
func (g *securityGuard) admit(host, method, uri string, now time.Time) bool {
	reason, _ := g.admitTask("", host, method, uri, now)
	return reason == ""
}

func secretVariants(secret string) []string {
	if len(secret) < 8 {
		return nil
	} // avoid broad matches on placeholder keys
	return []string{secret, url.QueryEscape(secret), url.PathEscape(secret), base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret)), hex.EncodeToString([]byte(secret))}
}

var privateKeyStart = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)
var privateKeyBlock = regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)

func containsSecret(b []byte, secrets []string) bool {
	if privateKeyStart.Match(b) {
		return true
	}
	for _, secret := range secrets {
		for _, v := range secretVariants(secret) {
			if bytes.Contains(b, []byte(v)) {
				return true
			}
		}
	}
	// Handles percent-encoded form/URL values without modifying the outgoing bytes.
	if decoded, err := url.QueryUnescape(string(b)); err == nil && decoded != string(b) {
		if privateKeyStart.MatchString(decoded) {
			return true
		}
		for _, secret := range secrets {
			if len(secret) >= 8 && strings.Contains(decoded, secret) {
				return true
			}
		}
	}
	// JSON escapes (including unicode escapes) must not hide a configured key.
	var parsed any
	if json.Unmarshal(b, &parsed) == nil {
		var inspect func(any) bool
		inspect = func(v any) bool {
			switch x := v.(type) {
			case string:
				if privateKeyStart.MatchString(x) {
					return true
				}
				for _, secret := range secrets {
					for _, variant := range secretVariants(secret) {
						if strings.Contains(x, variant) {
							return true
						}
					}
				}
			case []any:
				for _, v := range x {
					if inspect(v) {
						return true
					}
				}
			case map[string]any:
				for k, v := range x {
					if inspect(k) || inspect(v) {
						return true
					}
				}
			}
			return false
		}
		if inspect(parsed) {
			return true
		}
	}

	return false
}
func guardReject(f *mproxy.Flow, status int, reason string) {
	headers := http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "X-Artex-Security": {reason}, "Cache-Control": {"no-store"}}
	if status == 429 {
		headers.Set("Retry-After", "60")
	}
	f.Response = &mproxy.Response{StatusCode: status, Header: headers, Body: []byte("ARTEX 安全保护：" + reason + "。请检查任务；不要绕过保护重试。")}
	// No URI, headers, bodies or secret values in audit output.
	authority := sha256.Sum256([]byte(f.Request.URL.Host))
	log.Printf("[security] blocked authority_hash=%x category=%s", authority[:6], reason)
}

func (s *sink) Requestheaders(f *mproxy.Flow) {
	if f.Request == nil || f.Request.URL == nil {
		return
	}
	task, err := s.flowTask(f)
	if err != nil {
		s.reject(f, 407, "task_credential")
		return
	}
	if f.Request.Method == http.MethodConnect {
		return
	}
	if s.t.security.unavailable.Load() {
		s.reject(f, 503, "policy_unavailable")
		return
	}
	policy := s.t.SecurityConfig()
	bodyLimit := policy.MaxBodyKiB * 1024
	r := f.Request
	ctx := context.Background()
	if r.Raw() != nil {
		ctx = r.Raw().Context()
	}
	secrets, err := s.t.secrets(ctx)
	if err != nil {
		s.reject(f, 503, "secret_source_unavailable")
		return
	}
	host := r.URL.Host
	if r.Raw() != nil {
		host = r.Raw().Host
	}
	if containsSecret([]byte(host+"\n"+r.URL.String()+"\n"+headerLines(r.Header)), secrets) {
		s.reject(f, 403, "platform_credential")
		return
	}
	if reason, retry := s.t.security.admitTask(task, canonicalAuthority(r.URL), r.Method, r.URL.RequestURI(), time.Now()); reason != "" {
		s.reject(f, 429, reason)
		f.Response.Header.Set("Retry-After", strconv.Itoa(retry))
		return
	}

	if r.Header == nil {
		r.Header = make(http.Header)
	}
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", guardUA)
	}
	// Buffer before upstream forwarding so a streaming/unknown-length request
	// cannot bypass the Request hook at go-mitmproxy's large-body cutoff.
	if raw := r.Raw(); raw != nil && raw.Body != nil {
		if raw.ContentLength > int64(bodyLimit) {
			s.reject(f, 413, "request_body_limit")
			return
		}
		b, e := io.ReadAll(io.LimitReader(raw.Body, int64(bodyLimit)+1))
		raw.Body.Close()
		if e != nil {
			s.reject(f, 400, "request_body_read")
			return
		}
		if len(b) > bodyLimit {
			s.reject(f, 413, "request_body_limit")
			return
		}
		scan := b
		switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
		case "", "identity":
		case "gzip":
			z, e := gzip.NewReader(bytes.NewReader(b))
			if e != nil {
				s.reject(f, 400, "invalid_encoding")
				return
			}
			scan, e = io.ReadAll(io.LimitReader(z, int64(bodyLimit)+1))
			z.Close()
			if e != nil || len(scan) > bodyLimit {
				s.reject(f, 413, "decoded_body_limit")
				return
			}
		default:
			s.reject(f, 415, "unsupported_request_encoding")
			return
		}
		if containsSecret(scan, secrets) {
			s.reject(f, 403, "platform_credential")
			return
		}
		raw.Body = io.NopCloser(bytes.NewReader(b))
	}
	s.t.security.allowed.Add(1)
}

func sensitiveField(k string) bool {
	k = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, "-", ""), "_", ""))
	switch k {
	case "authorization", "proxyauthorization", "cookie", "setcookie", "password", "passwd", "secret", "token", "accesstoken", "refreshtoken", "apikey", "xapikey", "xauthtoken", "clientsecret":
		return true
	}
	return false
}
func redactBytes(b []byte, secrets []string) []byte {
	out := privateKeyBlock.ReplaceAll(b, []byte("[REDACTED PRIVATE KEY]"))
	for _, secret := range secrets {
		for _, v := range secretVariants(secret) {
			out = bytes.ReplaceAll(out, []byte(v), []byte("[REDACTED]"))
		}
	}
	return out
}
func redactHeaders(h http.Header, secrets []string) http.Header {
	out := h.Clone()
	if out == nil {
		out = make(http.Header)
	}
	for k, vs := range out {
		if sensitiveField(k) {
			out[k] = []string{"[REDACTED]"}
		} else {
			for i, v := range vs {
				vs[i] = string(redactBytes([]byte(v), secrets))
			}
		}
	}
	return out
}
func redactBody(b []byte, ct string, secrets []string) []byte {
	b = redactBytes(b, secrets)
	if strings.Contains(ct, "json") {
		var v any
		if json.Unmarshal(b, &v) == nil {
			changed := false
			var walk func(any) any
			walk = func(x any) any {
				switch z := x.(type) {
				case string:
					safe := string(redactBytes([]byte(z), secrets))
					if safe != z {
						changed = true
					}
					return safe
				case map[string]any:
					for k, v := range z {
						if sensitiveField(k) {
							z[k] = "[REDACTED]"
							changed = true
						} else {
							z[k] = walk(v)
						}
					}
				case []any:
					for i, v := range z {
						z[i] = walk(v)
					}
				}
				return x
			}
			v = walk(v)
			if changed {
				if out, err := json.Marshal(v); err == nil {
					return out
				}
			}
		}
	} else if strings.Contains(ct, "application/x-www-form-urlencoded") {
		if q, e := url.ParseQuery(string(b)); e == nil {
			changed := false
			for k := range q {
				if sensitiveField(k) {
					q.Set(k, "[REDACTED]")
					changed = true
				}
			}
			if changed {
				return []byte(q.Encode())
			}
		}
	}
	return b
}

// Redact a COPY before persistence (including FTS and blobs), never the live wire.
func (t *Traffic) sanitizedFlow(f *mproxy.Flow) (*mproxy.Flow, error) {
	secrets, err := t.secrets(context.Background())
	if err != nil {
		return nil, errors.New("secret source unavailable")
	}
	out := *f
	req := *f.Request
	resp := *f.Response
	u := *req.URL
	if u.User != nil {
		u.User = url.User("REDACTED")
	}
	q := u.Query()
	changed := false
	for k := range q {
		if sensitiveField(k) {
			q.Set(k, "[REDACTED]")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	safeURL, err := url.Parse(string(redactBytes([]byte(u.String()), secrets)))
	if err != nil {
		return nil, errors.New("redacted URL invalid")
	}
	req.URL = safeURL
	req.Header = redactHeaders(req.Header, secrets)
	resp.Header = redactHeaders(resp.Header, secrets)
	req.Body = redactBody(req.Body, req.Header.Get("Content-Type"), secrets)
	resp.Body = redactBody(resp.Body, resp.Header.Get("Content-Type"), secrets)
	// Compressed bodies can hide credentials from byte matching. Omit their
	// stored copy; wire bytes are untouched. Existing raw archives are unchanged.
	for _, part := range []struct {
		h http.Header
		b *[]byte
	}{{req.Header, &req.Body}, {resp.Header, &resp.Body}} {
		if enc := part.h.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") && len(*part.b) > 0 {
			*part.b = []byte("[REDACTED: encoded body omitted]")
			part.h.Del("Content-Encoding")
		}
		part.h.Del("Content-Length")
		part.h.Set("X-Artex-Capture", "sanitized; not-wire-original")
	}
	out.Request = &req
	out.Response = &resp
	return &out, nil
}

func (s *sink) reject(f *mproxy.Flow, status int, reason string) {
	s.t.security.block(reason)
	guardReject(f, status, reason)
}
func (t *Traffic) SetSecurityUnavailable(v bool) { t.security.unavailable.Store(v) }
