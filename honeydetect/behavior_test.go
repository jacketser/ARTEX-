package honeydetect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBehaviorOriginAndConfig(t *testing.T) {
	for raw, want := range map[string]string{"https://Example.test:443/x?q=1": "https://example.test", "http://lab.test:8080/foo": "http://lab.test:8080", "http://[fd12::1]:8080/": "http://[fd12::1]:8080"} {
		got, e := Origin(raw)
		if e != nil || got != want {
			t.Fatalf("%q => %q %v", raw, got, e)
		}
	}
	for _, raw := range []string{"file:///etc/passwd", "http://a:b@example.test/", "http://localhost:70000", "http://example.test/#fragment"} {
		if _, e := Origin(raw); e == nil {
			t.Fatal("invalid origin accepted", raw)
		}
	}
	if c := DefaultBehaviorConfig(); c.Validate() != nil || c.Enabled {
		t.Fatal(c)
	}
	for _, c := range []BehaviorConfig{{true, nil}, {true, []string{"http://example.test/path"}}, {true, []string{"http://example.test", "http://example.test"}}} {
		if c.Validate() == nil {
			t.Fatal("invalid allowlist", c)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::1", "169.254.169.254", "100.100.100.200", "::ffff:127.0.0.1", "fd00:ec2::254", "0.0.0.0", "224.0.0.1"} {
		if safeProbeIP(netip.MustParseAddr(ip)) {
			t.Fatal("unsafe IP", ip)
		}
	}
}
func TestBehaviorLocalAddressBlocked(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	if _, err := Probe(t.Context(), srv.URL, DefaultRules(), nil); err == nil || hits.Load() != 0 {
		t.Fatal("loopback reached", err, hits.Load())
	}
}
func TestBehaviorEvidenceAndFalsePositives(t *testing.T) {
	for _, tc := range []struct {
		name             string
		marker, wildcard bool
		want             string
	}{{"normal", false, false, "no_signal"}, {"spa", false, true, "needs_review"}, {"marked-wildcard", true, true, "suspected"}, {"product-page", true, false, "needs_review"}} {
		t.Run(tc.name, func(t *testing.T) {
			var count atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("credentials sent")
				}
				if strings.HasPrefix(r.URL.Path, "/artex-behavior-check-") && !tc.wildcard {
					http.NotFound(w, r)
					return
				}
				if tc.marker {
					w.Header().Set("Server", "Cowrie")
				}
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte("same-page-contents"))
			}))
			defer srv.Close()
			c := srv.Client()
			c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			out := probeWithClient(t.Context(), c, srv.URL, DefaultRules(), nil)
			if out.Outcome != tc.want || count.Load() != 4 {
				t.Fatalf("%+v requests=%d", out, count.Load())
			}
			b, _ := json.Marshal(out)
			if strings.Contains(string(b), "same-page-contents") || strings.Contains(string(b), "Cowrie") {
				t.Fatal("response content persisted")
			}
		})
	}
}
func TestBehaviorStopsAtRedirectBudgetOrCancellation(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Location", "http://127.0.0.1:1/secret")
		w.WriteHeader(302)
	}))
	defer srv.Close()
	c := srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	out := probeWithClient(t.Context(), c, srv.URL, DefaultRules(), nil)
	if count.Load() != 1 || out.Outcome != "inconclusive" {
		t.Fatal(out)
	}
	count.Store(0)
	out = probeWithClient(t.Context(), c, srv.URL, DefaultRules(), func(context.Context, string, string) error { return errors.New("blocked") })
	if count.Load() != 0 || out.Observations[0].Error != "security_budget_or_policy" {
		t.Fatal("budget bypass", out)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	probeWithClient(ctx, c, srv.URL, DefaultRules(), nil)
	if time.Since(start) > time.Second || count.Load() != 0 {
		t.Fatal("cancelled request sent")
	}
}
func TestBehaviorTruncatedAndDynamicAreInconclusive(t *testing.T) {
	for _, huge := range []bool{false, true} {
		t.Run(map[bool]string{false: "dynamic", true: "large"}[huge], func(t *testing.T) {
			var n atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				v := n.Add(1)
				if huge {
					w.Write([]byte(strings.Repeat("a", ProbeMaxBytes+5)))
				} else {
					w.Write([]byte(strings.Repeat("b", int(v))))
				}
			}))
			defer srv.Close()
			out := probeWithClient(t.Context(), srv.Client(), srv.URL, DefaultRules(), nil)
			if out.Outcome != "inconclusive" {
				t.Fatal(out)
			}
		})
	}
}
