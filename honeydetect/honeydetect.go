// Package honeydetect provides metadata matching and bounded manual HTTP diagnostics.
// No credential attempts, evasion or automatic target skipping.
package honeydetect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"unicode"
)

const Version = "metadata-v2"

type Input struct {
	TLSSubject      string   `json:"tls_subject"`
	TLSIssuer       string   `json:"tls_issuer"`
	TLSFingerprint  string   `json:"tls_fingerprint"`
	Service         string   `json:"service"`
	Title           string   `json:"title"`
	Technologies    []string `json:"technologies"`
	Banner          string   `json:"banner"`
	ServerHeader    string   `json:"server_header"`
	PoweredBy       string   `json:"powered_by"`
	ResponseSummary string   `json:"response_summary"`
}
type Result struct {
	RuleRevision string   `json:"rule_revision"`
	Sources      []string `json:"sources"`
	Stale        bool     `json:"stale"`
	AssessedAt   int64    `json:"assessed_at"`
	Version      string   `json:"version"`
	Fingerprint  string   `json:"fingerprint"`
	Matched      bool     `json:"matched"`
	Score        int      `json:"score"`
	Confidence   string   `json:"confidence"`
	Provider     string   `json:"provider,omitempty"`
	Signals      []string `json:"signals"`
	Evidence     []string `json:"evidence"`
	Limitations  string   `json:"limitations"`
}

func Normalize(in Input) Input {
	clip := func(s string) string {
		r := []rune(s)
		if len(r) > 8192 {
			r = r[:8192]
		}
		return strings.ToLower(strings.TrimSpace(string(r)))
	}
	in.TLSSubject = clip(in.TLSSubject)
	in.TLSIssuer = clip(in.TLSIssuer)
	in.TLSFingerprint = clip(in.TLSFingerprint)
	in.Service = clip(in.Service)
	in.Title = clip(in.Title)
	in.Banner = clip(in.Banner)
	in.ServerHeader = clip(in.ServerHeader)
	in.PoweredBy = clip(in.PoweredBy)
	in.ResponseSummary = clip(in.ResponseSummary)
	ts := []string{}
	for i, t := range in.Technologies {
		if i >= 100 {
			break
		}
		ts = append(ts, clip(t))
	}
	sort.Strings(ts)
	in.Technologies = ts
	return in
}
func Fingerprint(in Input) string {
	raw, _ := json.Marshal(Normalize(in))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func containsToken(s, token string) bool {
	if token == "蜜罐" {
		return strings.Contains(s, token)
	}
	for _, word := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' }) {
		if word == token {
			return true
		}
	}
	return false
}
func Detect(input Input) Result { return DetectWithRules(input, DefaultRules()) }
func DetectWithRules(input Input, rules RuleSet) Result {
	in := Normalize(input)
	revision := rules.Revision()
	sum := sha256.Sum256([]byte(Fingerprint(in) + ":" + revision))
	out := Result{RuleRevision: revision, Sources: []string{}, Version: Version, Fingerprint: hex.EncodeToString(sum[:]), Confidence: "none", Signals: []string{}, Evidence: []string{}, Limitations: "仅按规则检查已保存元数据；评分不是概率，标记不代表确认。未发现签名不代表不是蜜罐；需人工核对，不影响任务执行或拦截规则。"}
	fields := []struct{ name, value string }{{"service", in.Service}, {"title", in.Title}, {"technologies", strings.Join(in.Technologies, " ")}, {"banner", in.Banner}, {"server_header", in.ServerHeader}, {"powered_by", in.PoweredBy}, {"response_summary", in.ResponseSummary}, {"tls_subject", in.TLSSubject}, {"tls_issuer", in.TLSIssuer}, {"tls_fingerprint", in.TLSFingerprint}}
	providers := map[string]bool{}
	sources := map[string]bool{}
	surfaces := map[string]bool{}
	values := map[string]bool{}
	for _, field := range fields {
		// Count the same string once even if copied into multiple asset fields.
		matched := false
		for _, rule := range rules.Rules {
			marker := rule.ID
			if !rule.matches(field.name, field.value) {
				continue
			}
			matched = true
			out.Signals = append(out.Signals, field.name+":"+marker)
			if !sources[rule.ID] {
				out.Sources = append(out.Sources, rule.ID+": "+rule.Source)
				sources[rule.ID] = true
			}
			out.Evidence = append(out.Evidence, field.name+" 命中规则「"+marker+"」（仍可能是正常产品介绍或模拟内容）")
			if rule.Provider != "" && marker != "honeypot" && marker != "蜜罐" {
				providers[rule.Provider] = true
			}
		}
		if matched && !values[field.value] {
			values[field.value] = true
			group := "application"
			if field.name == "banner" || field.name == "service" {
				group = "service"
			}
			if strings.HasPrefix(field.name, "tls_") {
				group = "tls"
			}
			if field.name == "server_header" || field.name == "powered_by" {
				group = "headers"
			}
			surfaces[group] = true
		}
	}
	if len(surfaces) > 0 {
		out.Matched = true
		out.Score = 35
		out.Confidence = "low"
	}
	if len(surfaces) > 1 {
		out.Score = 65
		out.Confidence = "medium"
	}
	if len(surfaces) > 2 {
		out.Score = 85
		out.Confidence = "high"
	}
	names := []string{}
	for p := range providers {
		names = append(names, p)
	}
	sort.Strings(names)
	out.Provider = strings.Join(names, ", ")
	return out
}
