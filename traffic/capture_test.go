package traffic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func captureTestProxy(t *testing.T) *Traffic {
	t.Helper()
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
	t.Cleanup(func() { tr.Close() })
	go tr.Start()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, e := net.DialTimeout("tcp", addr, 20*time.Millisecond)
		if e == nil {
			conn.Close()
			return tr
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy start timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func captureClient(t *testing.T, proxy string) *http.Client {
	t.Helper()
	u, err := url.Parse(proxy)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // synthetic TLS fixture
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func TestCaptureSwitchPreservesProtectionAndHistory(t *testing.T) {
	tr := captureTestProxy(t)
	tr.SetSecretSource(func(context.Context) ([]string, error) { return []string{"isolated-platform-secret"}, nil })
	policy := DefaultSecurityConfig()
	policy.TaskRequests = 2
	if err := tr.SetSecurityConfig(policy); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credential forwarded")
		}
		w.Write([]byte("normal response"))
	})
	plain, secure := httptest.NewServer(handler), httptest.NewTLSServer(handler)
	defer plain.Close()
	defer secure.Close()
	var stored int
	for i, capture := range []bool{true, false, true, false} {
		tr.SetCaptureEnabled(capture)
		client := captureClient(t, tr.TaskProxyAddr(fmt.Sprint(i+1)))
		for j, target := range []string{plain.URL, secure.URL, secure.URL} {
			resp, err := client.Get(target)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			want := 200
			if j == 2 {
				want = 429
			}
			if resp.StatusCode != want {
				t.Fatalf("capture=%t: got %d want %d", capture, resp.StatusCode, want)
			}
		}
		for _, target := range []string{plain.URL, secure.URL} {
			req, _ := http.NewRequest("GET", target, nil)
			req.Header.Set("Authorization", "Bearer isolated-platform-secret")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 403 {
				t.Fatalf("capture=%t: credential status %d", capture, resp.StatusCode)
			}
		}
		n, err := tr.Count()
		if err != nil {
			t.Fatal(err)
		}
		if capture && n <= stored {
			t.Fatal("capture enabled but no history saved")
		}
		if !capture && n != stored {
			t.Fatalf("capture disabled changed history: %d -> %d", stored, n)
		}
		stored = n
	}
	if hits.Load() != 8 {
		t.Fatalf("blocked requests reached target: hits=%d", hits.Load())
	}
	stats := tr.SecurityStats()
	if stats.Allowed != 8 || stats.Blocked["task_budget"] != 4 || stats.Blocked["platform_credential"] != 8 {
		t.Fatal(stats)
	}
	// Switching capture must not reset the last task's exhausted budget.
	tr.SetCaptureEnabled(true)
	resp, err := captureClient(t, tr.TaskProxyAddr("4")).Get(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatal("capture switch reset task budget")
	}
}

func TestCaptureSwitchDoesNotSaveInflightResponse(t *testing.T) {
	tr := captureTestProxy(t)
	for _, initial := range []bool{false, true} {
		tr.SetCaptureEnabled(initial)
		client := captureClient(t, tr.ProxyAddr())
		arrived, release := make(chan struct{}), make(chan struct{})
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(arrived)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			w.Write([]byte("must not be persisted across toggle"))
		}))
		t.Cleanup(target.Close)
		done := make(chan error, 1)
		go func() {
			resp, err := client.Get(target.URL)
			if err == nil {
				_, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			done <- err
		}()
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("target not reached")
		}
		if initial {
			tr.SetCaptureEnabled(false)
		}
		tr.SetCaptureEnabled(true)
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if n, err := tr.Count(); err != nil || n != 0 {
			t.Fatalf("in-flight response saved: count=%d err=%v", n, err)
		}
		target.Close()
	}
}

func TestCaptureAtGuardBodyLimit(t *testing.T) {
	tr := captureTestProxy(t)
	payload := bytes.Repeat([]byte("x"), maxGuardBody)
	expected := sha256.Sum256(payload)
	var hits atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, e := io.ReadAll(r.Body)
		if e != nil || sha256.Sum256(b) != expected {
			t.Error("request body changed", e)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(payload) // Both request and response sit at the exact buffer boundary.
	})
	plain, secure := httptest.NewServer(handler), httptest.NewTLSServer(handler)
	defer plain.Close()
	defer secure.Close()
	for _, origin := range []string{plain.URL, secure.URL} {
		client := captureClient(t, tr.ProxyAddr())
		// SQLite and full-body sanitization are instrumented under -race.
		client.Timeout = 90 * time.Second
		for _, chunked := range []bool{false, true} {
			before, e := tr.Count()
			if e != nil {
				t.Fatal(e)
			}
			var body io.Reader = bytes.NewReader(payload)
			if chunked {
				body = io.NopCloser(body)
			}
			req, _ := http.NewRequest("POST", origin, body)
			req.Header.Set("Content-Type", "text/plain")
			resp, e := client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(resp.Body)
			resp.Body.Close()
			if e != nil || resp.StatusCode != 200 || sha256.Sum256(b) != expected {
				t.Fatal("response changed", e)
			}
			after, e := tr.Count()
			if e != nil || after != before+1 {
				t.Fatalf("exact-limit capture missing: chunked=%t before=%d after=%d err=%v", chunked, before, after, e)
			}
			var id string
			if e = tr.db.QueryRow(`SELECT id FROM exchanges ORDER BY rowid DESC LIMIT 1`).Scan(&id); e != nil {
				t.Fatal(e)
			}
			if e = tr.ReadEvidence(t.Context(), []string{id}, func(saved EvidenceExchange) error {
				for _, reader := range []io.Reader{saved.Request, saved.Response} {
					h := sha256.New()
					n, e := io.Copy(h, reader)
					if e != nil || n != maxGuardBody || !bytes.Equal(h.Sum(nil), expected[:]) {
						return fmt.Errorf("saved exact-limit body incomplete: bytes=%d err=%v", n, e)
					}
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
		}
		before := hits.Load()
		resp, e := client.Post(origin, "text/plain", io.NopCloser(bytes.NewReader(append(append([]byte{}, payload...), 'x'))))
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 413 || hits.Load() != before {
			t.Fatal("oversized chunked request reached target")
		}
	}
}
