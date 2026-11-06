package db

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func historyArchiveFixture(t *testing.T) (*DB, *Task, int64) {
	t.Helper()
	d, e := Open(testDSN(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Close() })
	if e = d.EnsureLLMRecordsTable(); e != nil {
		t.Fatal(e)
	}
	if e = d.EnsureLLMUsageTable(); e != nil {
		t.Fatal(e)
	}
	task, e := d.CreateTask("history archive", "fixture", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID); d.DeleteTask(task.ID) })
	f, e := d.Exploration(task.ExplorationID).RecordFinding(t.Context(), RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Name: "fixture", Summary: "summary", Severity: "low"})
	if e != nil {
		t.Fatal(e)
	}
	if e = d.SetPaused(task.ID, true); e != nil {
		t.Fatal(e)
	}
	return d, task, f.FindingID
}
func archiveHistory(t *testing.T, d *DB, taskID int64) (*TaskArchive, *TaskArchiveSnapshot) {
	t.Helper()
	job, e := d.QueueTaskArchive(taskID)
	if e != nil {
		t.Fatal(e)
	}
	claimed, e := d.ClaimTaskArchiveJob(t.Context())
	if e != nil || claimed == nil || claimed.ID != job.ID {
		t.Fatal(claimed, e)
	}
	s, e := d.SnapshotTaskArchive(taskID)
	if e != nil {
		t.Fatal(e)
	}
	if e = d.CompleteTaskArchive(job.ID, s, "/tmp/history-fixture.tar.zst", "fixture", 1, 1); e != nil {
		t.Fatal(e)
	}
	return job, s
}
func beginHistoryRestore(t *testing.T, d *DB, id int64) {
	t.Helper()
	if _, e := d.QueueTaskArchiveRestore(id); e != nil {
		t.Fatal(e)
	}
	j, e := d.ClaimTaskArchiveJob(t.Context())
	if e != nil || j == nil || j.ID != id {
		t.Fatal(j, e)
	}
}
func seedArchiveHistory(t *testing.T, d *DB, fid int64) []int64 {
	t.Helper()
	var conversations []int64
	for _, state := range []string{"completed", "failed", "stopped"} {
		r, c, _, e := d.CreateFindingRetest(t.Context(), fid, "historical notes")
		if e != nil {
			t.Fatal(e)
		}
		conversations = append(conversations, c.ID)
		t.Cleanup(func() { d.Exec(`DELETE FROM conversations WHERE id=$1`, c.ID) })
		if _, e = d.StartFindingRetest(t.Context(), r.ID); e != nil {
			t.Fatal(e)
		}
		if e = d.RecordFindingRetestResult(t.Context(), c.ID, "inconclusive", "observed", "limited evidence"); e != nil {
			t.Fatal(e)
		}
		if e = d.FinishFindingRetest(r.ID, state, "original reason"); e != nil {
			t.Fatal(e)
		}
	}
	f, e := d.GetFinding(fid)
	if e != nil {
		t.Fatal(e)
	}
	r := FindingReview{Fingerprint: FindingFingerprint(f), Verdict: "inconclusive", Limitations: "historical limitation"}
	if e = d.SaveFindingReview(t.Context(), fid, r); e != nil {
		t.Fatal(e)
	}
	r.Limitations = "second historical limitation"
	if e = d.SaveFindingReview(t.Context(), fid, r); e != nil {
		t.Fatal(e)
	}
	if e = d.SaveAutomaticReview(t.Context(), fid, r.Fingerprint, json.RawMessage(`{"verdict":"inconclusive","n":9007199254740993}`)); e != nil {
		t.Fatal(e)
	}
	// An old review must remain stale after restore, not be blessed with a new hash.
	if _, e = d.Exec(`UPDATE findings SET evidence_version=evidence_version+1,status='confirmed' WHERE id=$1`, fid); e != nil {
		t.Fatal(e)
	}
	return conversations
}
func TestFindingHistoryArchiveRoundTripRollbackAndMissingConversations(t *testing.T) {
	d, task, fid := historyArchiveFixture(t)
	conversations := seedArchiveHistory(t, d, fid)
	before, e := d.GetFindingReview(fid)
	if e != nil {
		t.Fatal(e)
	}
	job, s := archiveHistory(t, d, task.ID)
	if s.FormatVersion != 4 || s.DataCounts["finding_retests"] != 3 || s.DataCounts["finding_reviews"] != 1 || s.DataCounts["finding_review_history"] != 3 {
		t.Fatal(s.DataCounts)
	}
	for _, table := range archiveFindingHistoryTables {
		var n int
		if e = d.QueryRow("SELECT count(*) FROM "+table+" WHERE finding_id=$1", fid).Scan(&n); e != nil || n != 0 {
			t.Fatal("hot history retained", table, n, e)
		}
	}
	if _, e = d.Exec(`DELETE FROM conversations WHERE id=$1`, conversations[1]); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Exec(`UPDATE conversations SET agent_key='assistant' WHERE id=$1`, conversations[2]); e != nil {
		t.Fatal(e)
	}
	beginHistoryRestore(t, d, job.ID)
	if _, e = d.Exec(`CREATE FUNCTION fail_archive_history() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$; CREATE TRIGGER fail_archive_history BEFORE INSERT ON finding_review_history FOR EACH ROW EXECUTE FUNCTION fail_archive_history()`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Exec(`DROP FUNCTION IF EXISTS fail_archive_history() CASCADE`) })
	if _, e = d.RestoreTaskArchive(job.ID, s, 0); e == nil {
		t.Fatal("restore failure accepted")
	}
	if f, e := d.GetFinding(fid); e != nil || f != nil {
		t.Fatal("partial restore", e)
	}
	if _, e = d.Exec(`DROP FUNCTION fail_archive_history() CASCADE`); e != nil {
		t.Fatal(e)
	}
	warnings, e := d.RestoreTaskArchive(job.ID, s, 0)
	if e != nil || len(warnings) != 2 {
		t.Fatal(warnings, e)
	}
	for _, table := range archiveFindingHistoryTables {
		original, e := decodeArchiveRows(s.Tables[table])
		if e != nil {
			t.Fatal(e)
		}
		if table == "finding_retests" {
			for _, row := range original {
				cid, _ := jsonInt64(row["conversation_id"])
				if cid != conversations[0] {
					row["conversation_id"] = nil
				}
			}
		}
		key := "id"
		if table == "finding_reviews" {
			key = "finding_id"
		}
		var raw []byte
		if e = d.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY "+key+"),'[]') FROM "+table+" r WHERE finding_id=$1", fid).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		got, e := decodeArchiveRows(raw)
		if e != nil || !reflect.DeepEqual(original, got) {
			t.Fatal("history altered or duplicated", table, e)
		}
	}
	after, e := d.GetFindingReview(fid)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("review changed", e)
	}
	f, e := d.GetFinding(fid)
	if e != nil || f.Status != "confirmed" || FindingFingerprint(f) == after.Fingerprint {
		t.Fatal("staleness or triage lost", e)
	}
	if e = d.CompleteTaskArchiveRestore(job.ID); e != nil {
		t.Fatal(e)
	}
	next := *after
	next.Fingerprint = FindingFingerprint(f)
	if e = d.SaveFindingReview(t.Context(), fid, next); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = d.QueryRow(`SELECT count(*) FROM finding_review_history WHERE finding_id=$1`, fid).Scan(&count); e != nil || count != 4 {
		t.Fatal("history trigger not restored", count, e)
	}
}

func TestFindingHistoryArchiveFreezesWritersAndRejectsActiveRetest(t *testing.T) {
	d, task, fid := historyArchiveFixture(t)
	r, c, _, e := d.CreateFindingRetest(t.Context(), fid, "pending")
	if e != nil {
		t.Fatal(e)
	}
	defer d.Exec(`DELETE FROM conversations WHERE id=$1`, c.ID)
	if _, e = d.QueueTaskArchive(task.ID); !errors.Is(e, ErrTaskArchiveActiveRetest) {
		t.Fatal("pending retest allowed", e)
	}
	if _, e = d.StartFindingRetest(t.Context(), r.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = d.QueueTaskArchive(task.ID); !errors.Is(e, ErrTaskArchiveActiveRetest) {
		t.Fatal("running retest allowed", e)
	}
	if e = d.FinishFindingRetest(r.ID, "stopped", "operator stopped"); e != nil {
		t.Fatal(e)
	}
	if _, e = d.QueueTaskArchive(task.ID); e != nil {
		t.Fatal(e)
	}
	f, e := d.GetFinding(fid)
	if e != nil {
		t.Fatal(e)
	}
	review := FindingReview{Fingerprint: FindingFingerprint(f), Verdict: "inconclusive", Limitations: "fixture"}
	if _, _, _, e = d.CreateFindingRetest(t.Context(), fid, ""); !errors.Is(e, ErrTaskArchiveState) {
		t.Fatal("late retest allowed", e)
	}
	if e = d.SaveFindingReview(t.Context(), fid, review); !errors.Is(e, ErrTaskArchiveState) {
		t.Fatal("late manual review allowed", e)
	}
	if e = d.SaveAutomaticReview(t.Context(), fid, review.Fingerprint, map[string]string{"verdict": "inconclusive"}); !errors.Is(e, ErrTaskArchiveState) {
		t.Fatal("late automatic review allowed", e)
	}
}

func TestFindingHistoryArchiveConcurrentRetestQueue(t *testing.T) {
	d, task, fid := historyArchiveFixture(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	var queueErr, createErr error
	var c *Conversation
	wg.Go(func() { <-start; _, queueErr = d.QueueTaskArchive(task.ID) })
	wg.Go(func() { <-start; _, c, _, createErr = d.CreateFindingRetest(t.Context(), fid, "race") })
	close(start)
	wg.Wait()
	if c != nil {
		defer d.Exec(`DELETE FROM conversations WHERE id=$1`, c.ID)
	}
	if !((queueErr == nil && errors.Is(createErr, ErrTaskArchiveState)) || (createErr == nil && errors.Is(queueErr, ErrTaskArchiveActiveRetest))) {
		t.Fatal("queue/write race", queueErr, createErr)
	}
}

func TestFindingHistoryArchiveValidationAndLegacy(t *testing.T) {
	d, task, fid := historyArchiveFixture(t)
	seedArchiveHistory(t, d, fid)
	_, s := archiveHistory(t, d, task.ID)
	raw, _ := json.Marshal(s)
	for _, test := range []string{"missing", "count", "foreign", "duplicate", "running", "streamed", "legacy-extension"} {
		t.Run(test, func(t *testing.T) {
			var bad TaskArchiveSnapshot
			json.Unmarshal(raw, &bad)
			rows, _ := decodeArchiveRows(bad.Tables["finding_retests"])
			switch test {
			case "missing":
				delete(bad.Tables, "finding_reviews")
			case "count":
				bad.DataCounts["finding_reviews"]++
			case "foreign":
				rows[0]["finding_id"] = json.Number("999999999")
			case "duplicate":
				rows[1]["id"] = rows[0]["id"]
			case "running":
				rows[0]["status"] = "running"
			case "streamed":
				bad.StreamedTables = map[string]string{"finding_reviews": "database/reviews.ndjson"}
			case "legacy-extension":
				bad.FormatVersion = 3
			}
			bad.Tables["finding_retests"], _ = json.Marshal(rows)
			if e := ValidateArchiveFindingHistory(&bad); e == nil {
				t.Fatal("invalid archive accepted")
			}
		})
	}
	for _, v := range []int{1, 2, 3} {
		copy := *s
		copy.FormatVersion = v
		copy.Tables = map[string]json.RawMessage{"findings": s.Tables["findings"]}
		copy.DataCounts = map[string]int64{}
		if e := ValidateArchiveFindingHistory(&copy); e != nil {
			t.Fatal("legacy missing history rejected", v, e)
		}
	}
	// Large integers in nested historical results must survive decoder round trips.
	rows, _ := decodeArchiveRows(s.Tables["finding_review_history"])
	b, _ := json.Marshal(rows)
	if !bytes.Contains(b, []byte("9007199254740993")) {
		t.Fatal("historical JSON lost integer precision")
	}
}

func TestFindingHistoryArchiveIDCollisionRollsBack(t *testing.T) {
	d, task, fid := historyArchiveFixture(t)
	seedArchiveHistory(t, d, fid)
	job, s := archiveHistory(t, d, task.ID)
	other, e := d.CreateTask("unrelated history", "fixture", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer d.DeleteTask(other.ID)
	f, e := d.Exploration(other.ExplorationID).RecordFinding(t.Context(), RecordFindingInput{TaskID: other.ID, ExplorationID: other.ExplorationID, Name: "other", Summary: "unrelated", Severity: "low"})
	if e != nil {
		t.Fatal(e)
	}
	rows, e := decodeArchiveRows(s.Tables["finding_retests"])
	if e != nil {
		t.Fatal(e)
	}
	id, _ := jsonInt64(rows[0]["id"])
	if _, e = d.Exec(`INSERT INTO finding_retests(id,finding_id,status,snapshot,summary) VALUES($1,$2,'completed','{}','unrelated record')`, id, f.FindingID); e != nil {
		t.Fatal(e)
	}
	beginHistoryRestore(t, d, job.ID)
	if _, e = d.RestoreTaskArchive(job.ID, s, 0); e == nil {
		t.Fatal("ID collision accepted")
	}
	if got, e := d.GetFinding(fid); e != nil || got != nil {
		t.Fatal("partial restore after collision", e)
	}
	var owner int64
	var summary string
	if e = d.QueryRow(`SELECT finding_id,summary FROM finding_retests WHERE id=$1`, id).Scan(&owner, &summary); e != nil || owner != f.FindingID || summary != "unrelated record" {
		t.Fatal("unrelated history overwritten", e)
	}
}
