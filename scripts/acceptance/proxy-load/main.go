// A bounded, synthetic full-chain load test. Only used on the internal Compose network.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const platformKey = "isolated-platform-load-key-abcdefghijklmnopqrstuvwxyz"
const targetAuth = "Bearer synthetic-target-auth-not-platform"
const upstreamAuth = "Basic cHJvYmU6aXNvbGF0ZWQtbG9hZC1vbmx5" // probe:isolated-load-only
var targetResponses = map[int][]byte{1024: bytes.Repeat([]byte("y"), 1024), 65536: bytes.Repeat([]byte("y"), 65536)}

type fixtureStats struct {
	Requests map[string]int `json:"requests"`
	Leaks    int            `json:"leaks"`
	BadBody  int            `json:"bad_body"`
	BadAuth  int            `json:"bad_auth"`
	Upstream int            `json:"upstream"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	must(json.NewEncoder(w).Encode(v))
}
func serve() {
	var mu sync.Mutex
	stats := fixtureStats{Requests: map[string]int{}}
	target := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			mu.Lock()
			defer mu.Unlock()
			writeJSON(w, stats)
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, 6<<20))
		if e != nil {
			http.Error(w, "body read", 400)
			return
		}
		mu.Lock()
		stats.Requests[r.Header.Get("X-Load-Case")]++
		if strings.Contains(r.URL.String()+fmt.Sprint(r.Header)+string(body), platformKey) || r.Header.Get("Proxy-Authorization") != "" {
			stats.Leaks++
		}
		if digest(body) != r.Header.Get("X-Body-SHA256") {
			stats.BadBody++
		}
		if r.Header.Get("Authorization") != targetAuth {
			stats.BadAuth++
		}
		mu.Unlock()
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		response, ok := targetResponses[n]
		if !ok {
			http.Error(w, "response size", 400)
			return
		}
		ctype := "application/octet-stream"
		if r.Header.Get("X-Load-Text") == "1" {
			ctype = "text/plain"
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Content-Length", strconv.Itoa(len(response)))
		w.Write(response)
	})
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(e)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, DNSNames: []string{"fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	must(e)
	must(os.WriteFile("/load/fixture-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	listener, e := tls.Listen("tcp", ":8443", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	must(e)
	go func() { must(http.Serve(listener, target)) }()
	transport := &http.Transport{MaxIdleConns: 64, MaxIdleConnsPerHost: 32}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != upstreamAuth {
			http.Error(w, "proxy authentication", 407)
			return
		}
		host := r.URL.Host
		if r.Method == http.MethodConnect {
			host = r.Host
		}
		if host != "fixture:8080" && host != "fixture:8443" {
			http.Error(w, "fixture only", 403)
			return
		}
		mu.Lock()
		stats.Upstream++
		mu.Unlock()
		if r.Method == http.MethodConnect {
			dest, e := net.DialTimeout("tcp", host, 5*time.Second)
			if e != nil {
				http.Error(w, "connect", 502)
				return
			}
			client, rw, e := w.(http.Hijacker).Hijack()
			if e != nil {
				dest.Close()
				return
			}
			defer client.Close()
			defer dest.Close()
			client.SetDeadline(time.Now().Add(180 * time.Second))
			dest.SetDeadline(time.Now().Add(180 * time.Second))
			rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			rw.Flush()
			done := make(chan struct{})
			go func() { io.Copy(dest, rw); dest.Close(); close(done) }()
			io.Copy(client, dest)
			client.Close()
			<-done
			return
		}
		req := r.Clone(r.Context())
		req.RequestURI = ""
		req.Header.Del("Proxy-Authorization")
		resp, e := transport.RoundTrip(req)
		if e != nil {
			http.Error(w, "upstream", 502)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
	go func() {
		must((&http.Server{Addr: ":8081", Handler: upstream, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
	}()
	must((&http.Server{Addr: ":8080", Handler: target, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}

type driver struct {
	token     string
	roots     *x509.CertPool
	apiClient *http.Client
	results   []result
}

func (d *driver) api(method, path string, in, out any) {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		must(e)
		body = bytes.NewReader(b)
	}
	r, e := http.NewRequest(method, "http://app:8787"+path, body)
	must(e)
	r.Header.Set("Content-Type", "application/json")
	if d.token != "" {
		r.Header.Set("Authorization", "Bearer "+d.token)
	}
	resp, e := d.apiClient.Do(r)
	must(e)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		panic(fmt.Sprintf("API %s %s: status %d", method, path, resp.StatusCode))
	}
	if out != nil {
		must(json.NewDecoder(resp.Body).Decode(out))
	} else {
		io.Copy(io.Discard, resp.Body)
	}
}
func (d *driver) client(proxy bool, c int) *http.Client {
	tr := &http.Transport{MaxIdleConns: 64, MaxIdleConnsPerHost: c, MaxConnsPerHost: c, TLSClientConfig: &tls.Config{RootCAs: d.roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: false, DisableCompression: true, IdleConnTimeout: 15 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
	if proxy {
		u, _ := url.Parse("http://app:8788")
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}
}
func metrics() fixtureStats {
	r, e := http.Get("http://fixture:8080/metrics")
	must(e)
	defer r.Body.Close()
	var m fixtureStats
	must(json.NewDecoder(r.Body).Decode(&m))
	return m
}
func (d *driver) count() int {
	var s struct{ Count int }
	d.api("GET", "/api/traffic?size=1", nil, &s)
	return s.Count
}
func (d *driver) settings(capture, upstream bool) {
	u := ""
	if upstream {
		u = "http://probe:isolated-load-only@fixture:8081"
	}
	d.api("PUT", "/api/settings", map[string]any{"traffic_capture": capture, "global_proxy": u}, nil)
}

type scenario struct {
	Text          bool   `json:"text"`
	Name          string `json:"name"`
	Scheme        string `json:"scheme"`
	Proxy         bool   `json:"proxy"`
	Capture       bool   `json:"capture"`
	Upstream      bool   `json:"upstream"`
	Concurrency   int    `json:"concurrency"`
	BodyBytes     int    `json:"body_bytes"`
	ResponseBytes int    `json:"response_bytes"`
	Requests      int    `json:"request_limit"`
	Seconds       int    `json:"duration_limit_seconds"`
	Rate          int    `json:"rate_limit_rps"`
}
type captureProfile struct {
	Stages map[string]struct {
		Calls       uint64 `json:"calls"`
		Nanoseconds uint64 `json:"nanoseconds"`
	} `json:"stages"`
	Written uint64 `json:"written"`
	Failed  uint64 `json:"failed"`
}

func (d *driver) profile() captureProfile {
	var v struct {
		Capture captureProfile `json:"capture"`
	}
	d.api("GET", "/api/proxy-security/stats", nil, &v)
	return v.Capture
}

type result struct {
	ProfileBefore    captureProfile `json:"capture_before"`
	ProfileAfter     captureProfile `json:"capture_after"`
	Scenario         scenario       `json:"scenario"`
	Start            time.Time      `json:"start"`
	End              time.Time      `json:"end"`
	Requests         int            `json:"requests"`
	Errors           int            `json:"errors"`
	ErrorKinds       map[string]int `json:"error_kinds"`
	Seconds          float64        `json:"seconds"`
	RPS              float64        `json:"rps"`
	P50              float64        `json:"p50_ms"`
	P95              float64        `json:"p95_ms"`
	P99              float64        `json:"p99_ms"`
	TargetRequests   int            `json:"target_requests"`
	Captured         int            `json:"captured"`
	UpstreamRequests int            `json:"upstream_requests"`
}

func targetURL(scheme string, n int) string {
	port := "8080"
	if scheme == "https" {
		port = "8443"
	}
	return fmt.Sprintf("%s://fixture:%s/echo?bytes=%d", scheme, port, n)
}
func makeRequest(s scenario, body []byte) *http.Request {
	r, e := http.NewRequest("POST", targetURL(s.Scheme, s.ResponseBytes), bytes.NewReader(body))
	must(e)
	r.Header.Set("X-Load-Case", s.Name)
	r.Header.Set("X-Body-SHA256", digest(body))
	r.Header.Set("Authorization", targetAuth)
	r.Header.Set("Content-Type", "application/octet-stream")
	return r
}
func (d *driver) runCase(s scenario) {
	d.settings(s.Capture, s.Upstream)
	before := d.count()
	m0 := metrics()
	body := bytes.Repeat([]byte("x"), s.BodyBytes)
	want := digest(targetResponses[s.ResponseBytes])
	bodyHash := digest(body)
	client := d.client(s.Proxy, s.Concurrency)
	defer client.CloseIdleConnections()
	r := result{ProfileBefore: d.profile(), Scenario: s, ErrorKinds: map[string]int{}, Start: time.Now().UTC()}
	var mu sync.Mutex
	latencies := []float64{}
	var next atomic.Int64
	var stop atomic.Bool
	var wg sync.WaitGroup
	var ticks <-chan time.Time
	var ticker *time.Ticker
	if s.Rate > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(s.Rate))
		defer ticker.Stop()
		ticks = ticker.C
	}
	for range s.Concurrency {
		wg.Go(func() {
			for {
				if stop.Load() || time.Since(r.Start) > 120*time.Second {
					return
				}
				if s.Seconds > 0 && time.Since(r.Start) >= time.Duration(s.Seconds)*time.Second {
					return
				}
				if int(next.Add(1)) > s.Requests {
					return
				}
				if ticks != nil {
					<-ticks
					if time.Since(r.Start) >= time.Duration(s.Seconds)*time.Second {
						return
					}
				}
				req, e := http.NewRequest("POST", targetURL(s.Scheme, s.ResponseBytes), bytes.NewReader(body))
				must(e)
				req.Header.Set("X-Load-Case", s.Name)
				req.Header.Set("X-Body-SHA256", bodyHash)
				req.Header.Set("Authorization", targetAuth)
				req.Header.Set("Content-Type", "application/octet-stream")
				if s.Text {
					req.Header.Set("Content-Type", "text/plain")
					req.Header.Set("X-Load-Text", "1")
				}
				started := time.Now()
				resp, e := client.Do(req)
				kind := ""
				if e != nil {
					kind = "transport"
				} else {
					b, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(s.ResponseBytes)+4096))
					resp.Body.Close()
					if resp.StatusCode != 200 {
						kind = fmt.Sprintf("status_%d", resp.StatusCode)
					} else if readErr != nil || len(b) != s.ResponseBytes || digest(b) != want {
						kind = "response_integrity"
					}
				}
				ms := float64(time.Since(started).Microseconds()) / 1000
				mu.Lock()
				latencies = append(latencies, ms)
				if kind != "" {
					r.Errors++
					r.ErrorKinds[kind]++
					if r.Errors >= 10 {
						stop.Store(true)
					}
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	r.End = time.Now().UTC()
	r.Seconds = r.End.Sub(r.Start).Seconds()
	r.Requests = len(latencies)
	r.RPS = float64(r.Requests) / r.Seconds
	sort.Float64s(latencies)
	percentile := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		return latencies[int(float64(len(latencies)-1)*p)]
	}
	r.P50, r.P95, r.P99 = percentile(.5), percentile(.95), percentile(.99)
	// Response completion precedes capture commit; wait for durable row count.
	deadline := time.Now().Add(10 * time.Second)
	for {
		r.Captured = d.count() - before
		if !s.Proxy || !s.Capture || r.Captured >= r.Requests || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	m1 := metrics()
	r.ProfileAfter = d.profile()
	if r.ProfileAfter.Stages != nil && (r.ProfileAfter.Failed != r.ProfileBefore.Failed || r.ProfileAfter.Written-r.ProfileBefore.Written != uint64(r.Captured)) {
		panic("capture accounting inconsistent")
	}
	r.TargetRequests = m1.Requests[s.Name] - m0.Requests[s.Name]
	r.UpstreamRequests = m1.Upstream - m0.Upstream
	d.results = append(d.results, r)
	d.save()
	fmt.Printf("%s requests=%d errors=%d rps=%.1f p95=%.1fms captured=%d\n", s.Name, r.Requests, r.Errors, r.RPS, r.P95, r.Captured)
	if r.Requests == 0 || (s.Seconds == 0 && r.Requests != s.Requests) || r.Errors != 0 || r.TargetRequests != r.Requests || (s.Proxy && s.Capture && r.Captured != r.Requests) || ((!s.Proxy || !s.Capture) && r.Captured != 0) || (s.Upstream && r.UpstreamRequests == 0) || (!s.Upstream && r.UpstreamRequests != 0) || m1.Leaks != 0 || m1.BadBody != 0 || m1.BadAuth != 0 {
		panic("load case assertion failed: " + s.Name)
	}
}
func (d *driver) save() {
	b, e := json.MarshalIndent(d.results, "", "  ")
	must(e)
	must(os.WriteFile("/load/results.json", b, 0600))
}
func (d *driver) guardChecks() {
	for _, scheme := range []string{"http", "https"} {
		s := scenario{Name: "guard-" + scheme, Scheme: scheme, ResponseBytes: 1024}
		c := d.client(true, 8)
		before := metrics().Requests[s.Name]
		var wg sync.WaitGroup
		var failures atomic.Int64
		gate := make(chan struct{}, 8)
		for i := range 40 {
			gate <- struct{}{}
			wg.Go(func() {
				defer func() { <-gate }()
				variant := []string{"normal", "header", "body", "base64", "oversize"}[i%5]
				body := []byte("normal")
				if variant == "body" {
					body = []byte(platformKey)
				}
				if variant == "base64" {
					body = []byte(base64.StdEncoding.EncodeToString([]byte(platformKey)))
				}
				if variant == "oversize" {
					body = bytes.Repeat([]byte("x"), (5<<20)+1)
				}
				req := makeRequest(s, body)
				if variant == "header" {
					req.Header.Set("X-Test-Key", platformKey)
				}
				resp, e := c.Do(req)
				if e != nil {
					failures.Add(1)
					return
				}
				defer resp.Body.Close()
				b, e := io.ReadAll(io.LimitReader(resp.Body, 8192))
				want := 403
				if variant == "normal" {
					want = 200
				}
				if variant == "oversize" {
					want = 413
				}
				if e != nil || resp.StatusCode != want || (want == 200 && !bytes.Equal(b, targetResponses[1024])) {
					failures.Add(1)
				}
			})
		}
		wg.Wait()
		c.CloseIdleConnections()
		m := metrics()
		if failures.Load() != 0 || m.Requests[s.Name]-before != 8 || m.Leaks != 0 || m.BadBody != 0 || m.BadAuth != 0 {
			panic("mixed guard requests failed: " + scheme)
		}
	}
	must(os.WriteFile("/load/guard.json", []byte(`{"concurrency":8,"ordinary":16,"expected_403":48,"expected_413":16,"target_leaks":0}`), 0600))
	fmt.Println("Mixed HTTP/HTTPS: 16 ordinary requests passed, 64 credentials/oversize requests blocked before target")
}
func run() {
	d := &driver{apiClient: &http.Client{Timeout: 10 * time.Second}, roots: x509.NewCertPool()}
	for _, name := range []string{"fixture-ca.pem", "proxy-ca.pem"} {
		b, e := os.ReadFile("/load/" + name)
		must(e)
		if !d.roots.AppendCertsFromPEM(b) {
			panic("CA certificate missing")
		}
	}
	var status struct{ Initialized bool }
	d.api("GET", "/api/auth/status", nil, &status)
	if status.Initialized {
		panic("fresh isolated instance required")
	}
	var auth struct{ Token string }
	d.api("POST", "/api/auth/init", map[string]string{"password": "synthetic-proxy-load-password"}, &auth)
	d.token = auth.Token
	var health map[string]any
	d.api("GET", "/api/health", nil, &health)
	b, _ := json.Marshal(health)
	must(os.WriteFile("/load/health.json", b, 0600))
	policy := map[string]any{"host_requests_per_minute": 30000, "host_distinct_urls_per_minute": 3000, "url_requests_per_minute": 30000, "task_requests_per_minute": 30000, "unattributed_requests_per_minute": 30000, "cooldown_seconds": 1, "max_body_kib": 5120, "passthrough_mode": "block"}
	d.api("PUT", "/api/settings/proxy-security", policy, nil)

	if os.Getenv("ARTEX_LOAD_MODE") == "profile" {
		for _, scheme := range []string{"http", "https"} {
			for _, c := range []int{1, 16} {
				d.runCase(scenario{Name: fmt.Sprintf("profile-%s-1k-c%d", scheme, c), Scheme: scheme, Proxy: true, Capture: true, Concurrency: c, BodyBytes: 1024, ResponseBytes: 1024, Requests: 1000})
			}
			d.runCase(scenario{Name: "profile-" + scheme + "-text64k", Scheme: scheme, Proxy: true, Capture: true, Text: true, Concurrency: 8, BodyBytes: 65536, ResponseBytes: 65536, Requests: 100})
			d.runCase(scenario{Name: "profile-" + scheme + "-5m", Scheme: scheme, Proxy: true, Capture: true, Concurrency: 4, BodyBytes: 5 << 20, ResponseBytes: 65536, Requests: 24})
		}
	} else {
		for _, scheme := range []string{"http", "https"} {
			d.runCase(scenario{Name: "proxy-smoke-" + scheme, Scheme: scheme, Proxy: true, Concurrency: 1, BodyBytes: 1024, ResponseBytes: 1024, Requests: 1})
		}
		for _, scheme := range []string{"http", "https"} {
			for _, c := range []int{1, 16} {
				d.runCase(scenario{Name: fmt.Sprintf("direct-%s-1k-c%d", scheme, c), Scheme: scheme, Concurrency: c, BodyBytes: 1024, ResponseBytes: 1024, Requests: 2000})
			}
			d.runCase(scenario{Name: "direct-" + scheme + "-64k", Scheme: scheme, Concurrency: 8, BodyBytes: 65536, ResponseBytes: 65536, Requests: 500})
			d.runCase(scenario{Name: "direct-" + scheme + "-5m", Scheme: scheme, Concurrency: 4, BodyBytes: 5 << 20, ResponseBytes: 65536, Requests: 24})
		}
		for _, capture := range []bool{false, true} {
			for _, scheme := range []string{"http", "https"} {
				for _, c := range []int{1, 16} {
					d.runCase(scenario{Name: fmt.Sprintf("%s-capture-%t-1k-c%d", scheme, capture, c), Scheme: scheme, Proxy: true, Capture: capture, Concurrency: c, BodyBytes: 1024, ResponseBytes: 1024, Requests: 2000})
				}
				d.runCase(scenario{Name: fmt.Sprintf("%s-capture-%t-64k", scheme, capture), Scheme: scheme, Proxy: true, Capture: capture, Concurrency: 8, BodyBytes: 65536, ResponseBytes: 65536, Requests: 500})
				d.runCase(scenario{Name: fmt.Sprintf("%s-capture-%t-5m", scheme, capture), Scheme: scheme, Proxy: true, Capture: capture, Concurrency: 4, BodyBytes: 5 << 20, ResponseBytes: 65536, Requests: 24})
			}
		}
		for _, capture := range []bool{false, true} {
			for _, scheme := range []string{"http", "https"} {
				d.runCase(scenario{Name: fmt.Sprintf("%s-upstream-capture-%t", scheme, capture), Scheme: scheme, Proxy: true, Capture: capture, Upstream: true, Concurrency: 8, BodyBytes: 65536, ResponseBytes: 65536, Requests: 500})
			}
		}
		d.runCase(scenario{Name: "https-upstream-soak", Scheme: "https", Proxy: true, Capture: true, Upstream: true, Concurrency: 8, BodyBytes: 65536, ResponseBytes: 65536, Requests: 10000, Seconds: 90, Rate: 80})
	}

	d.guardChecks()
	// Intentional quota rejection must be distinguished from false positives.
	policy["unattributed_requests_per_minute"] = 1
	d.api("PUT", "/api/settings/proxy-security", policy, nil)
	c := d.client(true, 1)
	s := scenario{Name: "quota", Scheme: "http", ResponseBytes: 1024}
	before := metrics().Requests[s.Name]
	resp, e := c.Do(makeRequest(s, []byte("quota")))
	must(e)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	c.CloseIdleConnections()
	if resp.StatusCode != 429 || metrics().Requests[s.Name] != before {
		panic("quota did not block before target")
	}
	var stats map[string]any
	d.api("GET", "/api/proxy-security/stats", nil, &stats)
	out, _ := json.MarshalIndent(stats, "", "  ")
	must(os.WriteFile("/load/security-stats.json", out, 0600))
	fmt.Println("Intentional quota rejection passed; all ordinary synthetic requests preserved")
	// Allow connection expiry/GC observations without active requests.
	time.Sleep(20 * time.Second)
}
func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: proxy-load serve|run")
	}
	if os.Args[1] == "serve" {
		serve()
	} else if os.Args[1] == "run" {
		run()
	} else {
		log.Fatal("unknown mode")
	}
}
