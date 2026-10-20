package honeydetect

import "testing"

func TestCustomRulesTLSAndRevision(t *testing.T) {
	r := RuleSet{Rules: []Rule{{ID: "cert", Pattern: "ab:cd:ef", Provider: "fixture", Source: "local certificate fixture", Match: "exact", Fields: []string{"tls_fingerprint"}}}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	got := DetectWithRules(Input{TLSFingerprint: " AB:CD:EF "}, r)
	if !got.Matched || len(got.Sources) != 1 || got.Provider != "fixture" {
		t.Fatal(got)
	}
	if DetectWithRules(Input{Banner: "ab:cd:ef"}, r).Matched {
		t.Fatal("field restriction ignored")
	}
	if DetectWithRules(Input{TLSFingerprint: "xab:cd:ef"}, r).Matched {
		t.Fatal("exact ignored")
	}
	r.Rules[0].Source = "revised source"
	next := DetectWithRules(Input{TLSFingerprint: " AB:CD:EF "}, r)
	if got.Fingerprint == next.Fingerprint || got.RuleRevision == next.RuleRevision {
		t.Fatal("review not invalidated")
	}
	r.Rules[0].Source = " "
	if r.Validate() == nil {
		t.Fatal("source required")
	}
	r = DefaultRules()
	r.Rules[0].Fields = []string{"unknown"}
	if r.Validate() == nil {
		t.Fatal("unknown field")
	}
	r = DefaultRules()
	r.Rules[0].Pattern = "   "
	if r.Validate() == nil {
		t.Fatal("empty pattern")
	}
}
