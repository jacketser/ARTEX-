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
	"strings"
	"sync"
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
	mu     sync.Mutex
	hosts  map[string]*hostWindow
	source func(context.Context) ([]string, error)
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
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hosts == nil {
		g.hosts = make(map[string]*hostWindow)
	}
	w := g.hosts[host]
	if w != nil && now.Before(w.blockedUntil) {
		return false
	}
	if w == nil || now.Sub(w.start) >= time.Minute {
		if len(g.hosts) >= 4096 {
			for k, v := range g.hosts {
				if now.Sub(v.start) >= time.Minute && !now.Before(v.blockedUntil) {
					delete(g.hosts, k)
				}
			}
			if len(g.hosts) >= 4096 {
				return false
			}
		}
		w = &hostWindow{start: now, urls: make(map[[32]byte]int)}
		g.hosts[host] = w
	}
	w.total++
	if method == http.MethodGet || method == http.MethodHead {
		w.urls[sha256.Sum256([]byte(method+" "+uri))]++
	}
	if w.total > 3000 || len(w.urls) > 1500 || w.urls[sha256.Sum256([]byte(method+" "+uri))] > 120 {
		w.blockedUntil = now.Add(time.Minute)
		return false
	}
	return true
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
	if f.Request == nil || f.Request.URL == nil || f.Request.Method == http.MethodConnect {
		return
	}
	r := f.Request
	ctx := context.Background()
	if r.Raw() != nil {
		ctx = r.Raw().Context()
	}
	secrets, err := s.t.secrets(ctx)
	if err != nil {
		guardReject(f, 503, "secret_source_unavailable")
		return
	}
	host := r.URL.Host
	if r.Raw() != nil {
		host = r.Raw().Host
	}
	if containsSecret([]byte(host+"\n"+r.URL.String()+"\n"+headerLines(r.Header)), secrets) {
		guardReject(f, 403, "platform_credential")
		return
	}
	if !s.t.security.admit(strings.ToLower(r.URL.Host), r.Method, r.URL.RequestURI(), time.Now()) {
		guardReject(f, 429, "crawl_budget")
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
		if raw.ContentLength > maxGuardBody {
			guardReject(f, 413, "request_body_limit")
			return
		}
		b, e := io.ReadAll(io.LimitReader(raw.Body, maxGuardBody+1))
		raw.Body.Close()
		if e != nil {
			guardReject(f, 400, "request_body_read")
			return
		}
		if len(b) > maxGuardBody {
			guardReject(f, 413, "request_body_limit")
			return
		}
		scan := b
		switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
		case "", "identity":
		case "gzip":
			z, e := gzip.NewReader(bytes.NewReader(b))
			if e != nil {
				guardReject(f, 400, "invalid_encoding")
				return
			}
			scan, e = io.ReadAll(io.LimitReader(z, maxGuardBody+1))
			z.Close()
			if e != nil || len(scan) > maxGuardBody {
				guardReject(f, 413, "decoded_body_limit")
				return
			}
		default:
			guardReject(f, 415, "unsupported_request_encoding")
			return
		}
		if containsSecret(scan, secrets) {
			guardReject(f, 403, "platform_credential")
			return
		}
		raw.Body = io.NopCloser(bytes.NewReader(b))
	}
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
