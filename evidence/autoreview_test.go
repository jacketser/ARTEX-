package evidence

import (
	"encoding/json"
	"github.com/Autumn-27/artex/db"
	"testing"
)

func reviewedFinding() *db.DBFinding {
	f := &db.DBFinding{VulnClass: "XSS", Severity: "low", Summary: "fixture", Evidence: "observed output", EvidenceVersion: 2}
	f.Review = &db.FindingReview{Fingerprint: db.FindingFingerprint(f), Verdict: "supported", Sources: "log #1", Reproduction: "fixture with baseline", CounterEvidence: "encoding checked", Limitations: "offline only"}
	return f
}
func retestFor(f *db.DBFinding, verdict string) *db.FindingRetest {
	raw, _ := json.Marshal(map[string]any{"finding": map[string]any{"vulnclass": f.VulnClass, "severity": f.Severity, "summary": f.Summary, "evidence": f.Evidence, "evidence_version": f.EvidenceVersion}})
	return &db.FindingRetest{ID: 1, Status: "completed", Verdict: verdict, Summary: "checked", Evidence: "fixture result", Snapshot: raw}
}
func TestAutoReviewEvidenceAndStaleness(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*db.DBFinding)
		want string
	}{
		{"current human conclusion", func(f *db.DBFinding) {}, "supported"},
		{"no human review", func(f *db.DBFinding) { f.Review = nil }, "inconclusive"},
		{"empty evidence", func(f *db.DBFinding) { f.Evidence = "" }, "inconclusive"},
		{"changed severity", func(f *db.DBFinding) { f.Severity = "high" }, "inconclusive"},
		{"changed version", func(f *db.DBFinding) { f.EvidenceVersion++ }, "inconclusive"},
		{"missing counter", func(f *db.DBFinding) { f.Review.CounterEvidence = "" }, "inconclusive"},
		{"human refuted", func(f *db.DBFinding) { f.Review.Verdict = "refuted" }, "refuted"},
		{"traffic without baseline", func(f *db.DBFinding) { f.TrafficCount = 1 }, "inconclusive"},
		{"same snapshot is not independent", func(f *db.DBFinding) {
			f.TrafficCount = 2
			f.TrafficBindings = []db.FindingTrafficBinding{{Role: "proof", SnapshotID: "same"}, {Role: "baseline", SnapshotID: "same"}}
		}, "inconclusive"},
		{"distinct snapshots", func(f *db.DBFinding) {
			f.TrafficCount = 2
			f.TrafficBindings = []db.FindingTrafficBinding{{Role: "proof", SnapshotID: "proof"}, {Role: "baseline", SnapshotID: "baseline"}}
		}, "supported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := reviewedFinding()
			tc.edit(f)
			out := ReviewFinding(f, nil)
			if out.Verdict != tc.want {
				t.Fatalf("%+v", out)
			}
			if len(out.Suggestions) < 3 {
				t.Fatal("missing XSS-specific suggestions")
			}
		})
	}
	if got := ReviewFinding(nil, nil); got.Verdict != "inconclusive" || got.Checks == nil {
		t.Fatal(got)
	}
}
func TestAutoReviewLatestRetest(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*db.DBFinding, *db.FindingRetest)
		want string
	}{
		{"reproduced", func(f *db.DBFinding, r *db.FindingRetest) {}, "supported"},
		{"fixed is not refuted", func(f *db.DBFinding, r *db.FindingRetest) { r.Verdict = "fixed" }, "inconclusive"},
		{"failed staged verdict", func(f *db.DBFinding, r *db.FindingRetest) { r.Status = "failed" }, "inconclusive"},
		{"running staged verdict", func(f *db.DBFinding, r *db.FindingRetest) { r.Status = "running" }, "inconclusive"},
		{"inconclusive", func(f *db.DBFinding, r *db.FindingRetest) { r.Verdict = "inconclusive" }, "inconclusive"},
		{"missing output", func(f *db.DBFinding, r *db.FindingRetest) { r.Evidence = "" }, "inconclusive"},
		{"old snapshot", func(f *db.DBFinding, r *db.FindingRetest) {
			f.EvidenceVersion++
			f.Review.Fingerprint = db.FindingFingerprint(f)
		}, "inconclusive"},
		{"unknown snapshot", func(f *db.DBFinding, r *db.FindingRetest) { r.Snapshot = nil }, "inconclusive"},
		{"contradiction", func(f *db.DBFinding, r *db.FindingRetest) { f.Review.Verdict = "refuted" }, "inconclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := reviewedFinding()
			r := retestFor(f, "reproduced")
			tc.edit(f, r)
			if out := ReviewFinding(f, []*db.FindingRetest{r}); out.Verdict != tc.want {
				t.Fatalf("%+v", out)
			}
		})
	}
	f := reviewedFinding()
	old := retestFor(f, "reproduced")
	latest := retestFor(f, "reproduced")
	latest.ID = 2
	latest.Status = "pending"
	if ReviewFinding(f, []*db.FindingRetest{old, nil, latest}).Verdict != "inconclusive" {
		t.Fatal("older success hid latest pending attempt")
	}
}
