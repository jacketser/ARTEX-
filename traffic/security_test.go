package traffic

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

func TestSecurityHeadersAndCrawlBudget(t *testing.T) {
	tr := &Traffic{}
	tr.SetSecretSource(func(context.Context) ([]string, error) { return []string{"platform-secret-123456"}, nil })
	addon := &sink{t: tr}
	flow := func(raw string) *mproxy.Flow {
		u, _ := url.Parse(raw)
		return &mproxy.Flow{Request: &mproxy.Request{Method: "GET", URL: u, Header: make(http.Header)}}
	}
	for _, v := range []string{"platform-secret-123456", base64.StdEncoding.EncodeToString([]byte("platform-secret-123456"))} {
		f := flow("http://target.test/?q=" + url.QueryEscape(v))
		addon.Requestheaders(f)
		if f.Response == nil || f.Response.StatusCode != 403 {
			t.Fatal("secret not blocked")
		}
	}
	f := flow("http://target.test/normal")
	f.Request.Header.Set("Authorization", "Bearer target-credential")
	addon.Requestheaders(f)
	if f.Response != nil || f.Request.Header.Get("User-Agent") != guardUA {
		t.Fatal("normal target credential blocked or UA missing")
	}
	f = flow("http://target.test/custom")
	f.Request.Header.Set("User-Agent", "explicit-UA")
	addon.Requestheaders(f)
	if f.Request.Header.Get("User-Agent") != "explicit-UA" {
		t.Fatal("explicit UA changed")
	}
	g := securityGuard{}
	now := time.Now()
	for i := 0; i < 120; i++ {
		if !g.admit("a", "GET", "/repeat", now) {
			t.Fatal("early circuit break")
		}
	}
	if g.admit("a", "GET", "/repeat", now) || g.admit("a", "GET", "/different", now) {
		t.Fatal("loop not stopped")
	}
	if !g.admit("b", "GET", "/repeat", now) || !g.admit("a", "GET", "/repeat", now.Add(61*time.Second)) {
		t.Fatal("host isolation/cooldown failed")
	}
	tr.SetSecretSource(func(context.Context) ([]string, error) { return nil, errors.New("db down") })
	f = flow("http://target.test/")
	addon.Requestheaders(f)
	if f.Response == nil || f.Response.StatusCode != 503 {
		t.Fatal("secret source failed open")
	}
}

func TestSecurityRedactionDoesNotAlterWire(t *testing.T) {
	tr := &Traffic{}
	tr.SetSecretSource(func(context.Context) ([]string, error) { return []string{"platform-secret-123456"}, nil })
	u, _ := url.Parse("https://user:pass@target.test/a?token=target-secret&x=1")
	f := &mproxy.Flow{Request: &mproxy.Request{Method: "POST", URL: u, Header: http.Header{"Authorization": {"Bearer target-secret"}, "Content-Type": {"application/json"}}, Body: []byte(`{"password":"target-secret","nested":{"token":"another-secret"},"data":"platform-secret-123456"}`)}, Response: &mproxy.Response{StatusCode: 200, Header: http.Header{"Set-Cookie": {"session=secret"}}, Body: []byte("platform-secret-123456")}}
	clean, err := tr.sanitizedFlow(f)
	if err != nil {
		t.Fatal(err)
	}
	joined := clean.Request.URL.String() + headerLines(clean.Request.Header) + string(clean.Request.Body) + headerLines(clean.Response.Header) + string(clean.Response.Body)
	for _, secret := range []string{"target-secret", "another-secret", "platform-secret-123456", "session=secret", "user:pass"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("persisted %s", secret)
		}
	}
	if !strings.Contains(string(f.Request.Body), "target-secret") || f.Request.Header.Get("Authorization") != "Bearer target-secret" {
		t.Fatal("wire mutated")
	}
}

// Real proxy integration: blocked payloads never reach the target, including
// chunked requests larger than go-mitmproxy's normal streaming cutoff.
func TestSecurityProxyBlocksBeforeForwarding(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	tr.SetSecretSource(func(context.Context) ([]string, error) { return []string{"platform-secret-123456"}, nil })
	go tr.Start()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, e := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	u, _ := url.Parse("http://" + addr)
	transport := &http.Transport{Proxy: http.ProxyURL(u)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	for _, tc := range []struct {
		body string
		code int
	}{{"platform-secret-123456", 403}, {strings.Repeat("x", maxGuardBody+1), 413}, {`{"message":"normal"}`, 200}} {
		req, _ := http.NewRequest("POST", target.URL, io.NopCloser(strings.NewReader(tc.body)))
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.code {
			t.Fatalf("code=%d want %d", resp.StatusCode, tc.code)
		}
	}
	if reached.Load() != 1 {
		t.Fatalf("target received %d requests", reached.Load())
	}
}

func TestCredentialFormats(t *testing.T) {
	secret := "platform+secret/123456"
	for _, v := range append(secretVariants(secret), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		if !containsSecret([]byte(v), []string{secret}) {
			t.Fatal("missed credential format")
		}
	}
	if containsSecret([]byte("Bearer target-authorized"), []string{secret}) {
		t.Fatal("target auth false positive")
	}
	if !bytes.Equal(redactBody([]byte("password=abc&name=test"), "application/x-www-form-urlencoded", nil), []byte("name=test&password=%5BREDACTED%5D")) {
		t.Fatal("form not redacted")
	}
}

func TestEncodedCredentialAndStoredJSON(t *testing.T) {
	raw := []byte(`{"data":"\u0070latform-secret-123456"}`)
	secrets := []string{"platform-secret-123456"}
	if !containsSecret(raw, secrets) {
		t.Fatal("JSON escape bypass")
	}
	safe := redactBody(raw, "application/json", secrets)
	if !bytes.Contains(safe, []byte("REDACTED")) {
		t.Fatal("escaped key persisted")
	}
	tr := &Traffic{}
	u, _ := url.Parse("http://target.test/")
	f := &mproxy.Flow{Request: &mproxy.Request{URL: u, Header: make(http.Header)}, Response: &mproxy.Response{Header: http.Header{"Content-Encoding": {"gzip"}}, Body: []byte{1, 2, 3}}}
	clean, err := tr.sanitizedFlow(f)
	if err != nil || !bytes.Contains(clean.Response.Body, []byte("encoded body omitted")) {
		t.Fatal("encoded record retained")
	}
}

func TestCrawlDistinctAndTotalBudgets(t *testing.T) {
	now := time.Now()
	g := securityGuard{}
	for i := 0; i < 1500; i++ {
		if !g.admit("distinct.test", "GET", fmt.Sprint("/", i), now) {
			t.Fatal("early distinct limit")
		}
	}
	if g.admit("distinct.test", "GET", "/last", now) {
		t.Fatal("distinct URL expansion unbounded")
	}
	for i := 0; i < 3000; i++ {
		if !g.admit("total.test", "POST", "/scan", now) {
			t.Fatal("early total limit")
		}
	}
	if g.admit("total.test", "POST", "/scan", now) {
		t.Fatal("total rate unbounded")
	}
}
