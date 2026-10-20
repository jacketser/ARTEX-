package traffic

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type taskProxyContextKey struct{}

func (t *Traffic) taskSignature(id string) string {
	t.security.mu.Lock()
	defer t.security.mu.Unlock()
	if len(t.security.taskKey) == 0 {
		t.security.taskKey = make([]byte, 32)
		if _, err := rand.Read(t.security.taskKey); err != nil {
			panic(err)
		}
	}
	h := hmac.New(sha256.New, t.security.taskKey)
	h.Write([]byte("artex-task:" + id))
	return hex.EncodeToString(h.Sum(nil))
}

// TaskProxyAddr adds a process-local attribution capability. It is not a sandbox.
func (t *Traffic) TaskProxyAddr(id string) string {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return t.ProxyAddr()
	}
	u, _ := url.Parse(t.ProxyAddr())
	u.User = url.UserPassword("task-"+id, t.taskSignature(id))
	return u.String()
}
func (t *Traffic) proxyTask(r *http.Request) (string, error) {
	auth := r.Header.Get("Proxy-Authorization")
	r.Header.Del("Proxy-Authorization") // never forward proxy capabilities to a target
	if auth == "" {
		return "", nil
	}
	clone := &http.Request{Header: http.Header{"Authorization": {auth}}}
	user, pass, ok := clone.BasicAuth()
	if !ok || !strings.HasPrefix(user, "task-") {
		return "", errors.New("invalid proxy task credential")
	}
	id := strings.TrimPrefix(user, "task-")
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != id || !hmac.Equal([]byte(pass), []byte(t.taskSignature(id))) {
		return "", errors.New("invalid proxy task credential")
	}
	return id, nil
}
func (t *Traffic) authenticateProxy(w http.ResponseWriter, r *http.Request) (bool, error) {
	id, err := t.proxyTask(r)
	if err != nil {
		t.security.block("task_credential")
		return false, err
	}
	*r = *r.WithContext(context.WithValue(r.Context(), taskProxyContextKey{}, id))
	return true, nil
}
func (s *sink) flowTask(f *mproxy.Flow) (string, error) {
	r := f.Request
	if raw := r.Raw(); raw != nil {
		if id, ok := raw.Context().Value(taskProxyContextKey{}).(string); ok {
			if r.Method == http.MethodConnect && f.ConnContext != nil && f.ConnContext.ClientConn != nil {
				s.t.security.owners.Store(f.ConnContext.ClientConn.Id, id)
			}
			return id, nil
		}
	}
	// Decrypted HTTPS requests inherit their CONNECT identity, not client headers.
	if r.Method != http.MethodConnect && f.ConnContext != nil && f.ConnContext.ClientConn != nil {
		if id, ok := s.t.security.owners.Load(f.ConnContext.ClientConn.Id); ok {
			r.Header.Del("Proxy-Authorization")
			return id.(string), nil
		}
	}
	return s.t.proxyTask(&http.Request{Header: r.Header})
}
func (s *sink) ClientDisconnected(c *mproxy.ClientConn) { s.t.security.owners.Delete(c.Id) }

func canonicalAuthority(u *url.URL) string {
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	p := u.Port()
	if p == "" {
		if strings.EqualFold(u.Scheme, "https") {
			p = "443"
		} else {
			p = "80"
		}
	}
	if n, e := strconv.Atoi(p); e == nil {
		p = strconv.Itoa(n)
	}
	return net.JoinHostPort(h, p)
}
func windowFor(all map[string]*hostWindow, key string, now time.Time) *hostWindow {
	w := all[key]
	if w != nil && (now.Before(w.blockedUntil) || now.Sub(w.start) < time.Minute) {
		return w
	}
	if w == nil && len(all) >= 4096 {
		for k, v := range all {
			if now.Sub(v.start) >= time.Minute && !now.Before(v.blockedUntil) {
				delete(all, k)
			}
		}
		if len(all) >= 4096 {
			return nil
		}
	}
	w = &hostWindow{start: now, urls: map[[32]byte]int{}}
	all[key] = w
	return w
}
func (g *securityGuard) admitTask(task, host, method, uri string, now time.Time) (string, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.policyLocked()
	if g.hosts == nil {
		g.hosts = map[string]*hostWindow{}
	}
	if g.tasks == nil {
		g.tasks = map[string]*hostWindow{}
	}
	key := task
	limit := c.TaskRequests
	if key == "" {
		key = "unattributed"
		limit = c.UnattributedRequests
	}
	tw := windowFor(g.tasks, key, now)
	if tw == nil {
		return "budget_capacity", c.CooldownSeconds
	}
	if now.Before(tw.blockedUntil) {
		return "task_budget", int(tw.blockedUntil.Sub(now).Seconds()) + 1
	}
	if tw.total >= limit {
		tw.blockedUntil = now.Add(time.Duration(c.CooldownSeconds) * time.Second)
		return "task_budget", c.CooldownSeconds
	}
	w := windowFor(g.hosts, host, now)
	if w == nil {
		return "budget_capacity", c.CooldownSeconds
	}
	if now.Before(w.blockedUntil) {
		return "crawl_budget", int(w.blockedUntil.Sub(now).Seconds()) + 1
	}
	hash := sha256.Sum256([]byte(method + " " + uri))
	safe := method == http.MethodGet || method == http.MethodHead
	if w.total >= c.HostRequests || (safe && (w.urls[hash] >= c.URLRequests || (w.urls[hash] == 0 && len(w.urls) >= c.HostURLs))) {
		w.blockedUntil = now.Add(time.Duration(c.CooldownSeconds) * time.Second)
		return "crawl_budget", c.CooldownSeconds
	}
	tw.total++
	w.total++
	if safe {
		w.urls[hash]++
	}
	return "", 0
}
