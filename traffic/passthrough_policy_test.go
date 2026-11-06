package traffic

import (
	"bufio"
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
)

func rawPolicyConnect(t *testing.T, tr *Traffic, authority, task string, extra http.Header) *http.Response {
	t.Helper()
	u, _ := url.Parse(tr.TaskProxyAddr(task))
	conn, err := net.DialTimeout("tcp", u.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", authority, authority)
	if u.User != nil {
		pass, _ := u.User.Password()
		fmt.Fprintf(conn, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pass)))
	}
	for key, values := range extra {
		for _, v := range values {
			fmt.Fprintf(conn, "%s: %s\r\n", key, v)
		}
	}
	fmt.Fprint(conn, "\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestPassthroughActualProtocolFailureIsBlocked(t *testing.T) {
	tr := captureTestProxy(t)
	var accepts atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 invalid-status\r\n\r\n")
	}))
	target.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepts.Add(1)
		}
	}
	target.StartTLS()
	defer target.Close()
	client := captureClient(t, tr.ProxyAddr())
	resp, err := client.Get(target.URL)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 502 {
			t.Fatal(resp.StatusCode)
		}
	}
	u, _ := url.Parse(target.URL)
	deadline := time.Now().Add(time.Second)
	for !tr.uninspectable(canonicalAuthority(u), time.Now()) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !tr.uninspectable(canonicalAuthority(u), time.Now()) {
		t.Fatal("real malformed HTTPS did not register failure")
	}
	before := accepts.Load()
	denied := rawPolicyConnect(t, tr, u.Host, "", nil)
	if denied.StatusCode != 407 || denied.Header.Get("X-Artex-Security") != "passthrough_blocked" {
		t.Fatal(denied.StatusCode, denied.Header)
	}
	if accepts.Load() != before {
		t.Fatal("blocked CONNECT reached upstream")
	}
	if tr.SecurityStats().Blocked["passthrough_blocked"] != 1 {
		t.Fatal("missing policy counter")
	}
}

func TestPassthroughAllowQuotaAndSwitchBack(t *testing.T) {
	tr := captureTestProxy(t)
	tr.SetCaptureEnabled(false)
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("task capability forwarded")
		}
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	u, _ := url.Parse(target.URL)
	tr.markUninspectable(canonicalAuthority(u), time.Now())
	cfg := DefaultSecurityConfig()
	cfg.PassthroughMode = "allow"
	cfg.TaskRequests = 1
	if err := tr.SetSecurityConfig(cfg); err != nil {
		t.Fatal(err)
	}
	client := captureClient(t, tr.TaskProxyAddr("1"))
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || hits.Load() != 1 {
		t.Fatal("compatibility tunnel failed")
	}
	denied := rawPolicyConnect(t, tr, u.Host, "1", nil)
	if denied.StatusCode != 407 || denied.Header.Get("X-Artex-Security") != "task_budget" || denied.Header.Get("Retry-After") == "" {
		t.Fatal("tunnel escaped task budget", denied.Header)
	}
	// A distinct task has an independent quota, but changing mode still blocks it.
	if r := rawPolicyConnect(t, tr, u.Host, "2", nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	cfg.PassthroughMode = "block"
	tr.SetSecurityConfig(cfg)
	if r := rawPolicyConnect(t, tr, u.Host, "3", nil); r.StatusCode != 407 || r.Header.Get("X-Artex-Security") != "passthrough_blocked" {
		t.Fatal("mode switch did not block new tunnel")
	}
	// An established compatibility tunnel is intentionally not torn down.
	resp, err = client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || hits.Load() != 2 {
		t.Fatal("existing tunnel behavior changed")
	}
	if n, _ := tr.Count(); n != 0 {
		t.Fatal("opaque tunnel saved as inspected traffic")
	}
	stats := tr.SecurityStats()
	if stats.PassthroughAllowed != 2 || stats.Allowed != 0 {
		t.Fatal(stats)
	}
}

func TestPassthroughModeRecheckedAfterSecretRead(t *testing.T) {
	tr := &Traffic{}
	cfg := DefaultSecurityConfig()
	cfg.PassthroughMode = "allow"
	tr.SetSecurityConfig(cfg)
	tr.markUninspectable("target.test:443", time.Now())
	tr.SetSecretSource(func(context.Context) ([]string, error) {
		tr.SetSecurityConfig(DefaultSecurityConfig())
		return nil, nil
	})
	r := httptest.NewRequest("CONNECT", "http://target.test:443", nil)
	r.Host = "target.test:443"
	w := httptest.NewRecorder()
	ok, err := tr.authenticateProxy(w, r)
	if ok || err == nil || w.Header().Get("X-Artex-Security") != "passthrough_blocked" || tr.SecurityStats().PassthroughAllowed != 0 {
		t.Fatal("policy update raced past admission")
	}
}

func TestPassthroughGuardFailuresAndBounds(t *testing.T) {
	tr := &Traffic{}
	cfg := DefaultSecurityConfig()
	cfg.PassthroughMode = "allow"
	cfg.UnattributedRequests = 1
	tr.SetSecurityConfig(cfg)
	tr.markUninspectable("target.test:443", time.Now())
	tr.SetSecretSource(func(context.Context) ([]string, error) { return []string{"isolated-platform-secret"}, nil })
	request := func(header string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("CONNECT", "http://target.test:443", nil)
		r.Host = "target.test:443"
		r.Header.Set("X-Test", header)
		tr.authenticateProxy(w, r)
		return w
	}
	if w := request("isolated-platform-secret"); w.Header().Get("X-Artex-Security") != "platform_credential" {
		t.Fatal("header credential escaped")
	}
	request("")
	if w := request(""); w.Header().Get("X-Artex-Security") != "task_budget" {
		t.Fatal("public budget escaped")
	}
	tr.SetSecretSource(func(context.Context) ([]string, error) { return nil, errors.New("unavailable") })
	if w := request(""); w.Header().Get("X-Artex-Security") != "secret_source_unavailable" {
		t.Fatal("unavailable secrets allowed")
	}
	tr.SetSecurityUnavailable(true)
	if w := request(""); w.Header().Get("X-Artex-Security") != "policy_unavailable" {
		t.Fatal("unavailable policy allowed")
	}
	if err := func() error { bad := cfg; bad.PassthroughMode = "invalid"; return tr.SetSecurityConfig(bad) }(); err == nil {
		t.Fatal("invalid mode accepted")
	}
	// Full registry fails safely: no additional compatibility permission granted.
	tr.security.mu.Lock()
	for i := 0; i < 4096; i++ {
		tr.security.failedAuthorities[fmt.Sprint(i)+":443"] = time.Now().Add(time.Minute)
	}
	tr.security.mu.Unlock()
	tr.markUninspectable("overflow.test:443", time.Now())
	if tr.uninspectable("overflow.test:443", time.Now()) {
		t.Fatal("unbounded registry")
	}
	if strings.Contains(fmt.Sprint(tr.SecurityStats()), "target.test") {
		t.Fatal("raw authority in statistics")
	}
}

func TestPassthroughUsesConfiguredUpstream(t *testing.T) {
	tr := captureTestProxy(t)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("via upstream")) }))
	defer target.Close()
	var connects atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "only-via-upstream.invalid:443" {
			t.Error("unexpected upstream request")
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("task identity leaked to upstream")
		}
		dest, err := net.DialTimeout("tcp", target.Listener.Addr().String(), time.Second)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer dest.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		connects.Add(1)
		fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { io.Copy(dest, buffered); dest.Close() }()
		io.Copy(client, dest)
	}))
	defer upstream.Close()
	if err := tr.SetUpstreamProxy(upstream.URL); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultSecurityConfig()
	cfg.PassthroughMode = "allow"
	tr.SetSecurityConfig(cfg)
	tr.markUninspectable("only-via-upstream.invalid:443", time.Now())
	client := captureClient(t, tr.TaskProxyAddr("7"))
	resp, err := client.Get("https://only-via-upstream.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()
	if err != nil || string(body) != "via upstream" || connects.Load() != 1 {
		t.Fatalf("upstream not preserved: %q %v %d", body, err, connects.Load())
	}
}
