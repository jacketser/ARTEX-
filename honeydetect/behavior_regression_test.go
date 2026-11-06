package honeydetect

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Synthetic compatibility cases, not a labeled real-world honeypot dataset.
func TestBehaviorCompatibilitySamples(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		status, headStatus   int
		headServer, encoding string
		want                 string
		requests             int32
	}{
		{"authentication", 401, 200, "", "", "inconclusive", 1},
		{"forbidden", 403, 200, "", "", "inconclusive", 1},
		{"rate-limit", 429, 200, "", "", "inconclusive", 1},
		{"unavailable", 503, 200, "", "", "inconclusive", 1},
		{"redirect", 302, 200, "", "", "inconclusive", 1},
		{"unexpected-compression", 200, 200, "", "gzip", "inconclusive", 1},
		{"head-not-supported", 200, 405, "", "", "no_signal", 4},
		{"head-status-difference", 200, 204, "", "", "needs_review", 4},
		{"gateway-server-difference", 200, 200, "other-gateway", "", "needs_review", 4},
		{"empty-success", 204, 204, "", "", "no_signal", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Server", "normal-server")
				code := tc.status
				if r.Method == "HEAD" {
					code = tc.headStatus
					if tc.headServer != "" {
						w.Header().Set("Server", tc.headServer)
					}
				} else if strings.HasPrefix(r.URL.Path, "/artex-behavior-check-") {
					code = 404
				}
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.Header().Set("Location", "/must-not-follow")
				w.WriteHeader(code)
				if r.Method != "HEAD" && code != 204 {
					_, _ = w.Write([]byte("ordinary service"))
				}
			}))
			defer srv.Close()
			client := srv.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			out := probeWithClient(t.Context(), client, srv.URL, DefaultRules(), nil)
			if out.Outcome != tc.want || hits.Load() != tc.requests {
				t.Fatalf("outcome=%s requests=%d; want %s/%d", out.Outcome, hits.Load(), tc.want, tc.requests)
			}
			if out.Confidence == "medium" || out.Confidence == "high" {
				t.Fatal("normal service treated as suspected honeypot")
			}
		})
	}
}

func TestBehaviorAuthorizationRevokedBetweenRequests(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ordinary service"))
	}))
	defer srv.Close()
	out := probeWithClient(t.Context(), srv.Client(), srv.URL, DefaultRules(), func(context.Context, string, string) error {
		if hits.Load() > 0 {
			return errors.New("authorization withdrawn")
		}
		return nil
	})
	if hits.Load() != 1 || out.Outcome != "inconclusive" || len(out.Observations) != 2 || out.Observations[1].Error != "security_budget_or_policy" {
		t.Fatalf("probe continued after withdrawal: %+v hits=%d", out, hits.Load())
	}
}
