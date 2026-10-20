package traffic

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSecurityPolicyTaskAndHostIsolation(t *testing.T) {
	tr := &Traffic{}
	c := DefaultSecurityConfig()
	c.TaskRequests = 2
	c.UnattributedRequests = 1
	c.CooldownSeconds = 10
	if err := tr.SetSecurityConfig(c); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	g := &tr.security
	for _, host := range []string{"a:80", "b:80"} {
		if why, _ := g.admitTask("1", host, "GET", "/", now); why != "" {
			t.Fatal(why)
		}
	}
	if why, _ := g.admitTask("1", "c:80", "GET", "/", now); why != "task_budget" {
		t.Fatal("cross-host task quota", why)
	}
	if why, _ := g.admitTask("2", "a:80", "GET", "/", now); why != "" {
		t.Fatal("task contamination", why)
	}
	g.admitTask("", "a:80", "GET", "/", now)
	if why, _ := g.admitTask("", "b:80", "GET", "/", now); why != "task_budget" {
		t.Fatal("unattributed escape", why)
	}
	c.TaskRequests = 5
	tr.SetSecurityConfig(c)
	if why, _ := g.admitTask("1", "c:80", "GET", "/", now); why != "task_budget" {
		t.Fatal("config erased cooldown")
	}
	if why, _ := g.admitTask("1", "c:80", "GET", "/", now.Add(61*time.Second)); why != "" {
		t.Fatal("cooldown never clears", why)
	}
	for _, u := range []string{"http://EXAMPLE.test/", "http://example.test.:80/"} {
		p, _ := url.Parse(u)
		if canonicalAuthority(p) != "example.test:80" {
			t.Fatal("authority split")
		}
	}
	for _, invalid := range []SecurityConfig{{}, func() SecurityConfig { v := c; v.MaxBodyKiB = 5121; return v }(), func() SecurityConfig { v := c; v.HostURLs = v.HostRequests + 1; return v }()} {
		if tr.SetSecurityConfig(invalid) == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}
func TestTaskProxyCredentialsAndPromptSafeAddress(t *testing.T) {
	tr := &Traffic{addr: "127.0.0.1:1234"}
	u, _ := url.Parse(tr.TaskProxyAddr("42"))
	p, _ := u.User.Password()
	r := httptest.NewRequest("GET", "http://target.test", nil)
	r.SetBasicAuth(u.User.Username(), p)
	r.Header.Set("Proxy-Authorization", r.Header.Get("Authorization"))
	r.Header.Del("Authorization")
	if id, e := tr.proxyTask(r); e != nil || id != "42" || r.Header.Get("Proxy-Authorization") != "" {
		t.Fatal(id, e)
	}
	r.SetBasicAuth("task-43", p)
	r.Header.Set("Proxy-Authorization", r.Header.Get("Authorization"))
	if _, e := tr.proxyTask(r); e == nil {
		t.Fatal("task identity forged")
	}
}
func TestTaskBudgetRealHTTPAndHTTPS(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := ln.Addr().String()
	ln.Close()
	tr, e := Open(t.TempDir(), addr)
	if e != nil {
		t.Fatal(e)
	}
	defer tr.Close()
	c := DefaultSecurityConfig()
	c.TaskRequests = 2
	if e = tr.SetSecurityConfig(c); e != nil {
		t.Fatal(e)
	}
	go tr.Start()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", addr, 20*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	target := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("capability leaked to target")
		}
		w.Write([]byte("ok"))
	})
	plain := httptest.NewServer(target)
	defer plain.Close()
	secure := httptest.NewTLSServer(target)
	defer secure.Close()
	for _, id := range []string{"1", "2"} {
		p, _ := url.Parse(tr.TaskProxyAddr(id))
		transport := &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // local synthetic MITM fixture
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		for i, raw := range []string{plain.URL, secure.URL, secure.URL} {
			resp, e := client.Get(raw)
			if e != nil {
				t.Fatal(e)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			want := 200
			if i == 2 {
				want = 429
			}
			if resp.StatusCode != want {
				t.Fatalf("task %s request %d got %d", id, i, resp.StatusCode)
			}
		}
	}
	stats := tr.SecurityStats()
	if stats.Blocked["task_budget"] != 2 || stats.Allowed != 4 {
		t.Fatal(stats)
	}
}
func TestPolicyConcurrencyAndBodyLimit(t *testing.T) {
	tr := &Traffic{}
	c := DefaultSecurityConfig()
	c.TaskRequests = 50
	tr.SetSecurityConfig(c)
	var wg sync.WaitGroup
	now := time.Now()
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); tr.security.admitTask("1", "test:80", "POST", "/", now); tr.SecurityStats() }()
	}
	wg.Wait()
	tr.security.mu.Lock()
	n := tr.security.tasks["1"].total
	tr.security.mu.Unlock()
	if n != 50 {
		t.Fatal("concurrent budget overrun", n)
	}
	if strings.Contains(tr.TaskProxyAddr("invalid"), "@") {
		t.Fatal("invalid identity minted")
	}
}
