// Package honeydetect flags explicit self-identification in saved metadata.
// No requests, probes, credential checks, evasion or automatic target skipping.
package honeydetect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"unicode"
)

const Version = "metadata-v1"

type Input struct {
	Service         string   `json:"service"`
	Title           string   `json:"title"`
	Technologies    []string `json:"technologies"`
	Banner          string   `json:"banner"`
	ServerHeader    string   `json:"server_header"`
	PoweredBy       string   `json:"powered_by"`
	ResponseSummary string   `json:"response_summary"`
}
type Result struct {
	Stale       bool     `json:"stale"`
	AssessedAt  int64    `json:"assessed_at"`
	Version     string   `json:"version"`
	Fingerprint string   `json:"fingerprint"`
	Matched     bool     `json:"matched"`
	Score       int      `json:"score"`
	Confidence  string   `json:"confidence"`
	Provider    string   `json:"provider,omitempty"`
	Signals     []string `json:"signals"`
	Evidence    []string `json:"evidence"`
	Limitations string   `json:"limitations"`
}

func Normalize(in Input) Input {
	clip := func(s string) string {
		r := []rune(s)
		if len(r) > 8192 {
			r = r[:8192]
		}
		return strings.ToLower(strings.TrimSpace(string(r)))
	}
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
func Detect(input Input) Result {
	in := Normalize(input)
	out := Result{Version: Version, Fingerprint: Fingerprint(in), Confidence: "none", Signals: []string{}, Evidence: []string{}, Limitations: "仅检查已保存元数据中的显式名称；评分不是概率，标记不代表确认。未发现签名不代表不是蜜罐；需人工核对，不影响任务执行或拦截规则。"}
	fields := []struct{ name, value string }{{"service", in.Service}, {"title", in.Title}, {"technologies", strings.Join(in.Technologies, " ")}, {"banner", in.Banner}, {"server_header", in.ServerHeader}, {"powered_by", in.PoweredBy}, {"response_summary", in.ResponseSummary}}
	providers := map[string]bool{}
	surfaces := map[string]bool{}
	values := map[string]bool{}
	for _, field := range fields {
		// Count the same string once even if copied into multiple asset fields.
		matched := false
		for _, marker := range []string{"cowrie", "dionaea", "hfish", "honeypot", "蜜罐"} {
			if !containsToken(field.value, marker) {
				continue
			}
			matched = true
			out.Signals = append(out.Signals, field.name+":"+marker)
			out.Evidence = append(out.Evidence, field.name+" 包含显式标记「"+marker+"」（仍可能是产品介绍或模拟内容）")
			if marker != "honeypot" && marker != "蜜罐" {
				providers[marker] = true
			}
		}
		if matched && !values[field.value] {
			values[field.value] = true
			group := "application"
			if field.name == "banner" || field.name == "service" {
				group = "service"
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
