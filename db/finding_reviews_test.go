package db

import (
	"context"
	"errors"
	"testing"
)

func TestFindingReviewValidation(t *testing.T) {
	if (FindingReview{Verdict: "supported"}).Validate() == nil {
		t.Fatal("unsupported assertion accepted")
	}
	if (FindingReview{Verdict: "inconclusive"}).Validate() == nil {
		t.Fatal("missing limitations accepted")
	}
	if err := (FindingReview{Verdict: "inconclusive", Limitations: "Missing original response"}).Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestFindingReviewStaleness(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	id, err := d.AddFinding(0, 0, "sample", "sample", "low", "example", "original evidence", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id=$1`, id)
	f, err := d.GetFinding(id)
	if err != nil {
		t.Fatal(err)
	}
	review := FindingReview{Fingerprint: FindingFingerprint(f), Verdict: "supported", Sources: "log reference", Reproduction: "observed condition", CounterEvidence: "compared normal baseline"}
	if err := d.SaveFindingReview(context.Background(), id, review); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetFindingReview(id)
	if err != nil || got == nil || got.Verdict != "supported" {
		t.Fatalf("saved review: %+v %v", got, err)
	}
	_, err = d.Exec(`UPDATE findings SET evidence='new evidence' WHERE id=$1`, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SaveFindingReview(context.Background(), id, review); !errors.Is(err, ErrReviewStale) {
		t.Fatalf("stale review accepted: %v", err)
	}
	f, _ = d.GetFinding(id)
	if f.Status != FindingPending {
		t.Fatal("review changed triage status")
	}
}
