package report

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestSharedFindingsTextAndSourceIntegrity(t *testing.T) {
	secret := "synthetic-share,+ /\"`key-12345"
	variants := []string{secret, url.QueryEscape(secret), url.PathEscape(secret), base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret)), hex.EncodeToString([]byte(secret))}
	for _, value := range variants {
		f := &db.DBFinding{ID: 12, Name: "ordinary " + value, VulnClass: value, Severity: "low", Status: "pending", TaskDescription: value, Summary: value, Evidence: value, Report: value,
			TrafficBindings: []db.FindingTrafficBinding{{ID: 34, Role: value, Note: "note\n" + value, Snapshot: db.TrafficEvidenceSnapshot{Method: "GET", URL: "https://example.test/" + value, Status: 200}}}}
		f.Review = &db.FindingReview{Verdict: "supported", Fingerprint: db.FindingFingerprint(f), Sources: value, Reproduction: value, CounterEvidence: value, Limitations: value}
		before, _ := json.Marshal(f)
		md := SharedFindingsMarkdown([]*db.DBFinding{f}, time.Time{}, []string{secret})
		if strings.Contains(md, value) || strings.Contains(md, strings.ReplaceAll(value, "`", "%60")) || !strings.Contains(md, "ordinary") || !strings.Contains(md, "证据 #34") || !strings.Contains(md, "脱敏分享副本") {
			t.Fatal("Markdown leaked secret or lost ordinary content/notice/reference")
		}
		if strings.Contains(md, "复核已过期") || !strings.Contains(md, "现有证据支持结论") {
			t.Fatal("redaction changed source review freshness")
		}
		data := SharedFindingsCSV([]*db.DBFinding{f}, []string{secret})
		rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\xef\xbb\xbf"))).ReadAll()
		if err != nil || len(rows) != 2 || len(rows[0]) != 13 || rows[1][11] != "false" || !strings.Contains(rows[1][12], "脱敏分享副本") {
			t.Fatal("invalid CSV or changed source review status", err)
		}
		for _, cell := range rows[1] {
			if strings.Contains(cell, value) {
				t.Fatal("CSV leaked a decoded secret")
			}
		}
		after, _ := json.Marshal(f)
		if string(before) != string(after) {
			t.Fatal("source finding, review or binding mutated")
		}
		// ZIP still uses the unsanitized single-finding renderer, independently.
		if !strings.Contains(SingleFindingMarkdown(f, time.Time{}), value) {
			t.Fatal("raw renderer changed")
		}
		f.Review.Fingerprint = "outdated"
		if !strings.Contains(SharedFindingsMarkdown([]*db.DBFinding{f}, time.Time{}, []string{secret}), "复核已过期") {
			t.Fatal("stale source review became current")
		}
	}
}

func TestSharedFindingsStructuredFieldsAndEmptyExport(t *testing.T) {
	f := &db.DBFinding{ID: 7, Severity: "low", Name: "普通发现", Summary: `{"password":"unknown-json-value","ok":9007199254740993}`, Evidence: "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----", Report: `{"nested":{"api_key":"unknown-api-value"},"ok":"正常信息"}`}
	md := SharedFindingsMarkdown([]*db.DBFinding{f}, time.Time{}, nil)
	for _, value := range []string{"unknown-json-value", "unknown-api-value", "private-material"} {
		if strings.Contains(md, value) {
			t.Fatal("structured credential/PEM remained")
		}
	}
	if !strings.Contains(md, "9007199254740993") || !strings.Contains(md, "正常信息") {
		t.Fatal("ordinary JSON information changed")
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(SharedFindingsCSV([]*db.DBFinding{f}, nil)), "\xef\xbb\xbf"))).ReadAll()
	if err != nil || strings.Contains(rows[1][7], "unknown-json-value") || !strings.Contains(rows[1][7], "9007199254740993") {
		t.Fatal("CSV JSON field redaction failed", err)
	}
	if !strings.Contains(SharedFindingsMarkdown(nil, time.Time{}, nil), "脱敏分享副本") || !strings.Contains(string(SharedFindingsCSV(nil, nil)), "脱敏副本说明") {
		t.Fatal("empty export is not labeled")
	}
	// An embedded JSON fragment is not a complete JSON field; do not imply coverage.
	f.Summary = "discussion: password might be an unknown phrase"
	if !strings.Contains(SharedFindingsMarkdown([]*db.DBFinding{f}, time.Time{}, nil), f.Summary) {
		t.Fatal("ordinary prose unexpectedly rewritten")
	}
}
