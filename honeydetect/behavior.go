package honeydetect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const BehaviorVersion = "http-behavior-v1"
const ProbeMaxBytes = 64 * 1024

// A manually configured allowlist and explicit per-run consent bound active checks.
type BehaviorConfig struct {
	Enabled        bool     `json:"enabled"`
	AllowedOrigins []string `json:"allowed_origins"`
}

func DefaultBehaviorConfig() BehaviorConfig { return BehaviorConfig{AllowedOrigins: []string{}} }
func Origin(raw string) (string, error) {
	if len(raw) > 8192 {
		return "", errors.New("服务 URL 过长")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.Fragment != "" {
		return "", errors.New("仅支持不带凭据的 HTTP/HTTPS 服务")
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if strings.ContainsAny(h, "% \\\r\n\t") {
		return "", errors.New("主机名无效")
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return "", errors.New("端口无效")
		}
		port = strconv.Itoa(n)
	}
	if port == "" || (port == "80" && u.Scheme == "http") || (port == "443" && u.Scheme == "https") {
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
	} else {
		h = net.JoinHostPort(h, port)
	}
	return u.Scheme + "://" + h, nil
}
func (c BehaviorConfig) Validate() error {
	if c.AllowedOrigins == nil || len(c.AllowedOrigins) > 100 || (c.Enabled && len(c.AllowedOrigins) == 0) {
		return errors.New("启用前请填写 1–100 个已授权服务来源")
	}
	seen := map[string]bool{}
	for _, raw := range c.AllowedOrigins {
		o, e := Origin(raw)
		if e != nil || o != raw || seen[o] {
			return errors.New("授权来源须为不重复的规范 scheme://host[:port]，不能包含路径、查询或凭据")
		}
		seen[o] = true
	}
	return nil
}
func (c BehaviorConfig) Allows(raw string) bool {
	for _, o := range c.AllowedOrigins {
		if o == raw {
			return c.Enabled
		}
	}
	return false
}

type Observation struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Status      int    `json:"status"`
	BodySHA256  string `json:"body_sha256,omitempty"`
	Bytes       int    `json:"bytes"`
	Truncated   bool   `json:"truncated"`
	DurationMS  int64  `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
	server      string
	contentType string
	markers     []string
}
type BehaviorResult struct {
	Version      string        `json:"version"`
	Outcome      string        `json:"outcome"`
	Confidence   string        `json:"confidence"`
	Observations []Observation `json:"observations"`
	Signals      []string      `json:"signals"`
	Limitations  string        `json:"limitations"`
}

func emptyBehavior() BehaviorResult {
	return BehaviorResult{Version: BehaviorVersion, Outcome: "inconclusive", Confidence: "none", Observations: []Observation{}, Signals: []string{}, Limitations: "最多四次无凭据 HTTP 请求；协议差异、统一页面或名称标记均可能来自正常服务。结果不是蜜罐定论，不触发目标跳过、伪装、规避或任务调度改变。未发现线索不代表安全。"}
}

// safeProbeIP blocks metadata, local control planes and non-unicast addresses.
// Private lab networks are permitted only through the exact administrator allowlist.
func safeProbeIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, cidr := range []string{"100.64.0.0/10", "0.0.0.0/8", "192.0.0.0/24", "198.18.0.0/15", "2001:db8::/32", "2001::/23", "fd00:ec2::254/128"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

// probeClient pins the checked DNS answer. Redirects, proxy-env, cookies,
// compression and TLS verification bypass are deliberately unsupported.
func probeClient(ctx context.Context, origin string) (*http.Client, error) {
	u, _ := url.Parse(origin)
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
	if err != nil || len(ips) == 0 || len(ips) > 32 {
		return nil, errors.New("DNS 解析失败或地址过多")
	}
	local := map[netip.Addr]bool{}
	addrs, e := net.InterfaceAddrs()
	if e != nil {
		return nil, errors.New("无法核对本机地址")
	}
	for _, a := range addrs {
		if p, e := netip.ParsePrefix(a.String()); e == nil {
			local[p.Addr().Unmap()] = true
		}
	}
	for _, ip := range ips {
		if !safeProbeIP(ip) || local[ip.Unmap()] {
			return nil, errors.New("禁止探测回环、本机、链路本地或保留地址")
		}
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	addr := net.JoinHostPort(ips[0].String(), port)
	tr := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 * 1024, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
		DialContext: func(c context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(c, "tcp", addr)
		}}
	return &http.Client{Transport: tr, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// Probe does not expose an arbitrary URL/body/header request facility.
func Probe(ctx context.Context, origin string, rules RuleSet, before func(context.Context, string, string) error) (BehaviorResult, error) {
	out := emptyBehavior()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	client, err := probeClient(ctx, origin)
	if err != nil {
		return out, err
	}
	defer client.CloseIdleConnections()
	return probeWithClient(ctx, client, origin, rules, before), nil
}
func probeWithClient(ctx context.Context, client *http.Client, origin string, rules RuleSet, before func(context.Context, string, string) error) BehaviorResult {
	out := emptyBehavior()
	nonce := make([]byte, 12)
	if _, e := rand.Read(nonce); e != nil {
		return out
	}
	randomPath := "/artex-behavior-check-" + hex.EncodeToString(nonce)
	plans := []struct{ method, path string }{{"GET", "/"}, {"GET", "/"}, {"HEAD", "/"}, {"GET", randomPath}}
	for i, p := range plans {
		if i > 0 {
			select {
			case <-ctx.Done():
				return out
			case <-time.After(250 * time.Millisecond):
			}
		}
		o := Observation{Method: p.method, Path: p.path}
		if before != nil {
			if err := before(ctx, p.method, origin+p.path); err != nil {
				o.Error = "security_budget_or_policy"
				out.Observations = append(out.Observations, o)
				return out
			}
		}
		req, err := http.NewRequestWithContext(ctx, p.method, origin+p.path, nil)
		if err != nil {
			return out
		}
		req.Header.Set("User-Agent", "ARTEX-Behavior-Check/1.0 (manual authorized diagnostics)")
		req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.1")
		req.Header.Set("Accept-Encoding", "identity")
		start := time.Now()
		resp, err := client.Do(req)
		o.DurationMS = time.Since(start).Milliseconds()
		if err != nil {
			o.Error = "network_tls_or_timeout"
			out.Observations = append(out.Observations, o)
			return out
		}
		o.Status = resp.StatusCode
		o.server = resp.Header.Get("Server")
		o.contentType = resp.Header.Get("Content-Type")
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, ProbeMaxBytes+1))
		resp.Body.Close()
		o.DurationMS = time.Since(start).Milliseconds()
		if readErr != nil {
			o.Error = "body_read"
		} else if len(b) > ProbeMaxBytes {
			o.Truncated = true
			b = b[:ProbeMaxBytes]
		}
		o.Bytes = len(b)
		sum := sha256.Sum256(b)
		o.BodySHA256 = hex.EncodeToString(sum[:])
		if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
			o.Error = "encoded_body_not_analyzed"
		}
		if o.Error == "" && !o.Truncated {
			r := DetectWithRules(Input{ServerHeader: o.server, PoweredBy: resp.Header.Get("X-Powered-By"), ResponseSummary: string(b)}, rules)
			o.markers = r.Signals
		}
		out.Observations = append(out.Observations, o)
		if o.Error != "" || o.Status >= 300 && o.Status < 400 || o.Status == 401 || o.Status == 403 || o.Status == 429 || o.Status >= 500 {
			return out
		}
	}
	return analyzeBehavior(out)
}
func analyzeBehavior(out BehaviorResult) BehaviorResult {
	if len(out.Observations) != 4 {
		return out
	}
	a, b, h, n := out.Observations[0], out.Observations[1], out.Observations[2], out.Observations[3]
	for _, o := range out.Observations {
		if o.Error != "" || o.Truncated {
			return out
		}
	}
	if a.Status != b.Status || a.BodySHA256 != b.BodySHA256 {
		out.Signals = append(out.Signals, "重复请求响应不稳定，无法建立可靠对照")
		return out
	}
	if a.Status >= 200 && a.Status < 300 && n.Status == a.Status && n.BodySHA256 == a.BodySHA256 && a.Bytes > 0 {
		out.Signals = append(out.Signals, "随机不存在路径与主页返回相同成功响应；也常见于 SPA、统一错误页或反向代理")
	}
	if h.Status != a.Status && h.Status != 405 && h.Status != 501 {
		out.Signals = append(out.Signals, "HEAD 与 GET 状态不一致；也可能是服务器配置差异")
	}
	if a.server != "" && h.server != "" && a.server != h.server {
		out.Signals = append(out.Signals, "HEAD 与 GET 的 Server 标记不一致；也可能来自网关或负载均衡")
	}
	// Never turn ordinary wildcard routes/protocol quirks into a honeypot verdict.
	behavioral := len(out.Signals) > 0
	markers := map[string]bool{}
	for _, o := range out.Observations {
		for _, m := range o.markers {
			markers[m] = true
		}
	}
	if len(markers) > 0 {
		out.Signals = append(out.Signals, "实时响应命中已配置的名称规则；也可能是产品介绍或模拟内容")
	}
	out.Outcome = "no_signal"
	if len(out.Signals) > 0 {
		out.Outcome = "needs_review"
		out.Confidence = "low"
	}
	if behavioral && len(markers) > 0 {
		out.Outcome = "suspected"
		out.Confidence = "medium"
	}
	return out
}
