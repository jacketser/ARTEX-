package report

import (
	"github.com/Autumn-27/artex/db"
	"strings"
	"testing"
	"time"
)

func TestReviewExportDoesNotHideUncertainty(t *testing.T) {
	f := &db.DBFinding{ID: 1, Summary: "example", Severity: "low", Evidence: "log"}
	if !strings.Contains(SingleFindingMarkdown(f, time.Now()), "尚未人工复核") {
		t.Fatal("missing review presented without qualification")
	}
	f.Review = &db.FindingReview{Verdict: "inconclusive", Fingerprint: db.FindingFingerprint(f), Limitations: "missing baseline"}
	report := SingleFindingMarkdown(f, time.Now())
	if !strings.Contains(report, "无法确认") || !strings.Contains(report, "missing baseline") {
		t.Fatal("uncertainty omitted")
	}
	f.Evidence = "new log"
	if !strings.Contains(SingleFindingMarkdown(f, time.Now()), "复核已过期") {
		t.Fatal("stale review not labelled")
	}
}
