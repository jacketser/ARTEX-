package honeydetect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type Rule struct {
	ID       string   `json:"id"`
	Pattern  string   `json:"pattern"`
	Provider string   `json:"provider"`
	Source   string   `json:"source"`
	Match    string   `json:"match"`
	Fields   []string `json:"fields"`
}
type RuleSet struct {
	Rules []Rule `json:"rules"`
}

var fields = map[string]bool{"service": true, "title": true, "technologies": true, "banner": true, "server_header": true, "powered_by": true, "response_summary": true, "tls_subject": true, "tls_issuer": true, "tls_fingerprint": true}

func DefaultRules() RuleSet {
	r := RuleSet{Rules: []Rule{}}
	for _, p := range []string{"cowrie", "dionaea", "hfish", "opencanary", "kippo", "glastopf", "honeypot", "蜜罐"} {
		r.Rules = append(r.Rules, Rule{ID: p, Pattern: p, Provider: p, Source: "内置显式名称规则；仅匹配元数据自述，非已验证产品指纹", Match: "token", Fields: []string{}})
	}
	return r
}
func (r RuleSet) Validate() error {
	if len(r.Rules) == 0 || len(r.Rules) > 100 {
		return fmt.Errorf("规则数量需为 1–100")
	}
	seen := map[string]bool{}
	for _, v := range r.Rules {
		if len(v.ID) == 0 || len(v.ID) > 80 || seen[v.ID] || len(v.Pattern) < 3 || len(v.Pattern) > 256 || len(v.Provider) > 80 || strings.TrimSpace(v.Source) == "" || len(v.Source) > 600 {
			return fmt.Errorf("规则 ID 需唯一，模式为 3–256 字节且必须注明来源")
		}
		seen[v.ID] = true
		if v.Match != "token" && v.Match != "contains" && v.Match != "exact" {
			return fmt.Errorf("匹配方式需为 token、contains 或 exact")
		}
		if strings.TrimSpace(v.Pattern) != v.Pattern {
			return fmt.Errorf("模式首尾不得包含空白")
		}
		if len(v.Fields) > len(fields) {
			return fmt.Errorf("匹配字段过多")
		}
		for _, f := range v.Fields {
			if !fields[f] {
				return fmt.Errorf("未知元数据字段 %q", f)
			}
		}
	}
	return nil
}
func (r RuleSet) Revision() string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (r Rule) matches(field, value string) bool {
	if len(r.Fields) > 0 {
		found := false
		for _, f := range r.Fields {
			found = found || f == field
		}
		if !found {
			return false
		}
	}
	p := strings.ToLower(r.Pattern)
	switch r.Match {
	case "exact":
		return value == p
	case "contains":
		return strings.Contains(value, p)
	default:
		return containsToken(value, p)
	}
}
