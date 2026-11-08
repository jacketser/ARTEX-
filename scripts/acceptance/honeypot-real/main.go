// Evaluate unchanged production detectors against labeled local deployments.
// Labels and container names are never supplied to either detector.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/honeydetect"
	"golang.org/x/net/html"
)

type sample struct {
	ID, Origin, Label, Family, Configuration, Evidence, Split string
	LabelBasis                                                string `json:"label_basis"`
	ExpectedRootStatus                                        int    `json:"expected_root_status"`
}
type metadata struct {
	Evaluated   bool                `json:"evaluated"`
	Status      int                 `json:"status"`
	Bytes       int                 `json:"bytes"`
	Truncated   bool                `json:"truncated"`
	Title       string              `json:"title"`
	Server      string              `json:"server"`
	BodySHA256  string              `json:"body_sha256,omitempty"`
	InputSHA256 string              `json:"input_sha256,omitempty"`
	Error       string              `json:"error,omitempty"`
	Result      *honeydetect.Result `json:"result,omitempty"`
}
type measurement struct {
	SampleID           string                     `json:"sample_id"`
	Repetition         int                        `json:"repetition"`
	Metadata           metadata                   `json:"metadata"`
	Behavior           honeydetect.BehaviorResult `json:"behavior"`
	BehaviorError      string                     `json:"behavior_error,omitempty"`
	AuthorizedRequests int                        `json:"authorized_requests"`
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func save(name string, v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	must(e)
	must(os.WriteFile("/output/"+name, b, 0600))
}

func title(b []byte) string {
	z := html.NewTokenizer(strings.NewReader(string(b)))
	inside := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken:
			t := z.Token()
			inside = t.Data == "title"
		case html.TextToken:
			if inside {
				return strings.TrimSpace(z.Token().Data)
			}
		}
	}
}
func collect(origin string, rules honeydetect.RuleSet) (metadata, *honeydetect.Input) {
	// Same strict TLS, bounded body, no redirects, no cookies or credentials.
	tr := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 * 1024}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequest("GET", origin+"/", nil)
	must(e)
	req.Header.Set("User-Agent", "ARTEX-Labeled-Evaluation/1.0")
	req.Header.Set("Accept-Encoding", "identity")
	r, e := c.Do(req)
	if e != nil {
		return metadata{Error: e.Error()}, nil
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, honeydetect.ProbeMaxBytes+1))
	must(e)
	m := metadata{Status: r.StatusCode, Bytes: len(b), Truncated: len(b) > honeydetect.ProbeMaxBytes, Server: r.Header.Get("Server")}
	if m.Truncated {
		b = b[:honeydetect.ProbeMaxBytes]
	}
	m.BodySHA256 = sha(b)
	m.Title = title(b)
	in := honeydetect.Input{Service: "http", Title: m.Title, ServerHeader: m.Server, PoweredBy: r.Header.Get("X-Powered-By"), ResponseSummary: string(b)}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		in.TLSSubject = cert.Subject.String()
		in.TLSIssuer = cert.Issuer.String()
		in.TLSFingerprint = sha(cert.Raw)
	}
	result := honeydetect.DetectWithRules(in, rules)
	m.Evaluated = true
	m.Result = &result
	m.InputSHA256 = honeydetect.Fingerprint(in)
	return m, &in
}
func main() {
	started := time.Now().UTC()
	b, e := os.ReadFile("/output/samples.json")
	must(e)
	var samples []sample
	must(json.Unmarshal(b, &samples))
	expected := map[string]int{"tuning": 7, "holdout": 5, "holdout-20261107": 4, "holdout-20261108": 4}
	if len(samples) == 0 || expected[samples[0].Split] != len(samples) {
		panic("expected complete predeclared corpus")
	}
	seen := map[string]bool{}
	for _, s := range samples {
		if s.Split != samples[0].Split || seen[s.ID] || (s.Label != "honeypot" && s.Label != "benign") {
			panic("invalid or mixed corpus")
		}
		seen[s.ID] = true
	}
	rules := honeydetect.DefaultRules()
	must(rules.Validate())
	save("rules.json", rules)
	// Preflight is TCP only, including the HTTPS case whose certificate should
	// be rejected by both actual HTTP paths. Never silently drop broken targets.
	for _, s := range samples {
		u, e := url.Parse(s.Origin)
		must(e)
		deadline := time.Now().Add(60 * time.Second)
		for {
			c, e := net.DialTimeout("tcp", u.Host, time.Second)
			if e == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				panic("fixture not ready: " + s.ID)
			}
			time.Sleep(time.Second)
		}
	}
	rows := []measurement{}
	inputs := map[string]*honeydetect.Input{}
	for repeat := 1; repeat <= 3; repeat++ {
		for _, s := range samples {
			m, input := collect(s.Origin, rules)
			if input != nil {
				inputs[fmt.Sprintf("%s/%d", s.ID, repeat)] = input
			}
			if m.Error != "" && s.ID != "qeeqbox-https" {
				panic("metadata collection failed: " + s.ID + ": " + m.Error)
			}
			if s.ID == "qeeqbox-https" && !strings.Contains(m.Error, "x509:") {
				panic("expected default certificate validation failure was not observed: " + m.Error)
			}
			if s.ID != "qeeqbox-https" && (m.Status != s.ExpectedRootStatus || m.Truncated) {
				panic("unhealthy or truncated fixture: " + s.ID)
			}
			n := 0
			behavior, e := honeydetect.Probe(context.Background(), s.Origin, rules, func(_ context.Context, method, target string) error {
				origin, err := honeydetect.Origin(target)
				if err != nil || origin != s.Origin || (method != "GET" && method != "HEAD") || n >= 4 {
					return fmt.Errorf("outside labeled evaluation scope")
				}
				n++
				return nil
			})
			row := measurement{SampleID: s.ID, Repetition: repeat, Metadata: m, Behavior: behavior, AuthorizedRequests: n}
			if e != nil {
				row.BehaviorError = e.Error()
			}
			if e != nil || n < 1 || len(behavior.Observations) < 1 {
				panic("probe infrastructure failure: " + s.ID)
			}
			for _, o := range behavior.Observations {
				if o.Error != "" && s.ID != "qeeqbox-https" {
					panic("unexpected observation error: " + s.ID + ": " + o.Error)
				}
			}
			if s.ID == "qeeqbox-https" && (behavior.Outcome != "inconclusive" || len(behavior.Observations) != 1 || behavior.Observations[0].Error != "network_tls_or_timeout") {
				panic("expected strict TLS abstention from behavior probe")
			}
			rows = append(rows, row)
			save("measurements.json", rows)
			save("metadata-inputs.json", inputs)
			confidence := "not_evaluated"
			if m.Result != nil {
				confidence = m.Result.Confidence
			}
			fmt.Printf("%s repeat=%d metadata=%s behavior=%s observations=%d\n", s.ID, repeat, confidence, behavior.Outcome, len(behavior.Observations))
		}
	}
	save("evaluation-complete.json", map[string]any{"started_at": started, "finished_at": time.Now().UTC(), "split": samples[0].Split, "samples": len(samples), "repetitions": 3, "measurements": len(rows), "rule_revision": rules.Revision(), "metadata_version": honeydetect.Version, "behavior_version": honeydetect.BehaviorVersion})
}
