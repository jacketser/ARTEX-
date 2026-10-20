package evidence

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestTrafficComparisonIntegrityAndBounds(t *testing.T) {
	s := New(nil, nil, t.TempDir())
	makeSnapshot := func(body string) db.TrafficEvidenceSnapshot {
		t.Helper()
		hash, err := s.writeBody(strings.NewReader(body), int64(len(body)), "")
		if err != nil {
			t.Fatal(err)
		}
		return db.TrafficEvidenceSnapshot{ReqHash: hash, RespHash: hash, ReqLen: int64(len(body)), RespLen: int64(len(body))}
	}
	a := makeSnapshot("original")
	b := makeSnapshot("original")
	if got := s.compareBody(a, b, "response"); got.Status != "equal" {
		t.Fatal(got)
	}
	b = makeSnapshot("origin")
	if got := s.compareBody(a, b, "response"); got.Status != "different" || got.FirstDifference == nil || *got.FirstDifference != 6 {
		t.Fatal(got)
	}
	path, _ := hashPath(s.Dir, b.RespHash)
	if err := os.WriteFile(path, []byte("BROKEN"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := s.compareBody(a, b, "response"); got.Status != "unavailable" {
		t.Fatal(got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := s.compareBody(a, b, "response"); got.Status != "unavailable" {
		t.Fatal(got)
	}
	b.RespLen = 256*1024 + 1
	if got := s.compareBody(a, b, "response"); got.Status != "skipped" {
		t.Fatal(got)
	}
	bindings := []db.FindingTrafficBinding{{ID: 1, SnapshotID: "base", Role: "baseline", Snapshot: a}}
	for i := 0; i < 12; i++ {
		bindings = append(bindings, db.FindingTrafficBinding{ID: int64(i + 2), SnapshotID: "proof", Role: "proof", Snapshot: a})
	}
	if got := s.CompareTraffic(bindings); len(got) != 8 {
		t.Fatal(len(got))
	}
	a.ReqHead = "Authorization: secret-a\nCookie: private-cookie\n"
	b.ReqHead = "Authorization: secret-b\nCookie: private-cookie\n"
	b.RespLen = a.RespLen
	raw, err := json.Marshal(s.CompareTraffic([]db.FindingTrafficBinding{{ID: 1, SnapshotID: "a", Role: "baseline", Snapshot: a}, {ID: 2, SnapshotID: "b", Role: "proof", Snapshot: b}}))
	if err != nil || strings.Contains(string(raw), "secret-") || strings.Contains(string(raw), "private-cookie") || !strings.Contains(string(raw), "authorization") {
		t.Fatal(string(raw), err)
	}
}

func TestUnavailableComparisonCannotInheritConclusiveReview(t *testing.T) {
	r := AutoReview{Verdict: "supported"}
	r.ApplyComparisons([]TrafficComparison{{Bodies: []BodyDifference{{Status: "unavailable"}, {Status: "skipped"}}}})
	if r.Verdict != "inconclusive" || len(r.Missing) != 1 || len(r.Warnings) != 1 {
		t.Fatal(r)
	}
}
