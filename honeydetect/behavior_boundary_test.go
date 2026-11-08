package honeydetect

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The observed documentation + fallback counterexample applies to every name,
// including user-defined rules. Multiple names/repeated pages aren't evidence
// of multiple independent deployments.
func TestBehaviorDocumentationFallbackNames(t *testing.T) {
	rules := DefaultRules()
	rules.Rules = append(rules.Rules, Rule{ID: "custom", Pattern: "labmarker", Match: "token", Source: "test", Fields: []string{}})
	for _, rule := range rules.Rules {
		t.Run(rule.ID, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "ordinary-server")
				_, _ = w.Write([]byte("<title>Documentation</title>" + rule.Pattern + " deployment guide"))
			}))
			defer srv.Close()
			out := probeWithClient(t.Context(), srv.Client(), srv.URL, rules, nil)
			if out.Outcome != "needs_review" || out.Confidence != "low" || len(out.Signals) != 2 {
				t.Fatalf("documentation escalated or evidence lost: %+v", out)
			}
		})
	}
}

func TestBehaviorHeaderCorroboration(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"persistent-server", "suspected"}, {"persistent-powered-by", "suspected"},
		{"body-multiple-names", "needs_review"}, {"first-get-only", "inconclusive"},
		{"head-only", "needs_review"}, {"missing-path-only", "needs_review"},
		{"different-header-fields", "needs_review"}, {"different-rules", "needs_review"},
		{"no-behavior", "needs_review"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n++
				w.Header().Set("Server", "ordinary-server")
				switch tc.name {
				case "persistent-server", "no-behavior":
					w.Header().Set("Server", "Cowrie")
				case "persistent-powered-by":
					w.Header().Set("X-Powered-By", "Cowrie")
				case "first-get-only":
					if n == 1 {
						w.Header().Set("Server", "Cowrie")
					}
				case "head-only":
					if r.Method == "HEAD" {
						w.Header().Set("Server", "Cowrie")
					}
				case "missing-path-only":
					if n == 4 {
						w.Header().Set("Server", "Cowrie")
					}
				case "different-header-fields":
					if r.Method == "HEAD" {
						w.Header().Set("X-Powered-By", "Cowrie")
					} else {
						w.Header().Set("Server", "Cowrie")
					}
				case "different-rules":
					if r.Method == "HEAD" {
						w.Header().Set("Server", "Dionaea")
					} else {
						w.Header().Set("Server", "Cowrie")
					}
				}
				if tc.name == "no-behavior" && strings.HasPrefix(r.URL.Path, "/artex-behavior-check-") {
					w.WriteHeader(404)
				}
				_, _ = w.Write([]byte("Cowrie Dionaea OpenCanary documentation"))
			}))
			defer srv.Close()
			out := probeWithClient(t.Context(), srv.Client(), srv.URL, DefaultRules(), nil)
			if out.Outcome != tc.want || n != 4 {
				t.Fatalf("%+v requests=%d", out, n)
			}
		})
	}
}

// A gateway can serve identical bytes while rotating backend identifiers.
// A stable name in a different header does not turn that rotation into a
// method-specific anomaly. These are synthetic counterexamples, not a corpus.
func TestBehaviorServerBaselineStability(t *testing.T) {
	rules := RuleSet{Rules: []Rule{{ID: "fixture", Pattern: "testmarker", Match: "token", Source: "synthetic test", Fields: []string{"powered_by"}}}}
	for _, tc := range []struct {
		name, first, second, head, want string
		marker, wildcard               bool
	}{
		{"rotating-gateway", "gateway-a", "gateway-b", "gateway-b", "inconclusive", false, false},
		{"rotation-with-stable-name", "gateway-a", "gateway-b", "gateway-b", "inconclusive", true, false},
		{"rotation-with-fallback", "gateway-a", "gateway-b", "gateway-b", "inconclusive", true, true},
		{"disappearing-header", "gateway-a", "", "gateway-b", "inconclusive", true, false},
		{"appearing-header", "", "gateway-b", "gateway-b", "inconclusive", true, false},
		{"stable-method-difference", "gateway-a", "gateway-a", "gateway-b", "suspected", true, false},
		{"stable-normal", "gateway-a", "gateway-a", "gateway-a", "no_signal", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				server := tc.first
				if hits == 2 {
					server = tc.second
				}
				if r.Method == "HEAD" {
					server = tc.head
				}
				w.Header().Set("Server", server)
				w.Header().Set("Content-Type", "text/html")
				if tc.marker {
					w.Header().Set("X-Powered-By", "testmarker")
				}
				if r.URL.Path != "/" && !tc.wildcard {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if r.Method != "HEAD" {
					_, _ = w.Write([]byte("<div hidden>Client registration with heartbeat</div>"))
				}
			}))
			defer srv.Close()
			out := probeWithClient(t.Context(), srv.Client(), srv.URL, rules, nil)
			if hits != 4 || out.Outcome != tc.want {
				t.Fatalf("outcome=%s, want=%s, requests=%d", out.Outcome, tc.want, hits)
			}
			if len(out.ContentWarnings) != 1 {
				t.Fatalf("independent content warning lost: %+v", out)
			}
			if tc.want == "inconclusive" {
				if out.Confidence != "none" || !containsSignal(out.Signals, "重复主页 GET 的 Server 标记不稳定，无法将差异归因于 HEAD 方法；也可能来自网关或负载均衡") {
					t.Fatalf("unstable baseline not explained: %+v", out)
				}
			}
		})
	}
}
