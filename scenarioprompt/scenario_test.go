package scenarioprompt

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSelectAndBound(t *testing.T) {
	c := Default()
	for _, tt := range []struct{ raw, source, want string }{
		{`{"summary":"Web API 权限"}`, "keyword", "api,web"},
		{`{"summary":"Web API","chain_tags":["recon"]}`, "explicit", "recon"},
		{`{"summary":"unknown"}`, "fallback", "meta"},
		{`{"chain_tags":["bad"]}`, "unavailable", ""},
	} {
		got := Select(json.RawMessage(tt.raw), c)
		if got.Source != tt.source || strings.Join(got.Tags, ",") != tt.want {
			t.Fatal(got)
		}
	}
	c.MaxChars = 256
	c.Profiles[0].Prompt = strings.Repeat("证", 3000)
	got := Select(json.RawMessage(`{"chain_tags":["web","api"]}`), c)
	if !got.Truncated || utf8.RuneCountInString(got.Text) > 256 || !strings.Contains(got.Text, "固定边界") {
		t.Fatal(got)
	}
	c.Enabled = false
	if Select(json.RawMessage(`{"summary":"web"}`), c).Text != "" {
		t.Fatal("disabled injection")
	}
	for _, tags := range [][]string{{"bad"}, {"web", "web"}, {"web", "api", "app"}} {
		if ValidateTags(tags) == nil {
			t.Fatal(tags)
		}
	}
	c = Default()
	c.MaxChars = 0
	if c.Validate() == nil {
		t.Fatal("invalid limit")
	}
	c = Default()
	c.Profiles = append(c.Profiles, c.Profiles[0])
	if c.Validate() == nil {
		t.Fatal("duplicate profile")
	}
}
