package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/historyprivacy"
	"github.com/Autumn-27/artex/traffic"
)

// Exercise the real writer and restore extractor, not a maintenance-only codec.
func TestTaskArchivePrivacyPackageCompatibility(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("PostgreSQL required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTask("archive privacy compatibility", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	data := t.TempDir()
	payload := t.TempDir()
	body := []byte(`{"token":"original-token","number":9007199254740993}`)
	snapshot := traffic.ArchiveSnapshot{Version: 1, Exchanges: []traffic.ArchiveExchange{{ID: "cold-compatible", TS: 19, Host: "fixture.test", Method: "GET", URL: "http://fixture.test/", URLTemplate: "/", Status: 200, ContentType: "application/json", ReqHead: "GET / HTTP/1.1\nHost: fixture.test\n", RespHead: "HTTP 200\nContent-Type: application/json\n", RespBody: body, RespLen: len(body)}}}
	trafficJSON, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"traffic/traffic.json": trafficJSON, fmt.Sprintf("files/tasks/%d/note.txt", task.ID): []byte("workspace unchanged"), "database/llm_records.ndjson": []byte("{\"id\":9007199254740993}\n")}
	for name, b := range files {
		p := filepath.Join(payload, name)
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := &db.TaskArchiveSnapshot{FormatVersion: db.TaskArchiveFormatVersion, TaskID: task.ID, ExplorationID: task.ExplorationID, DataCounts: map[string]int64{"traffic": 1}, StreamedTables: map[string]string{"llm_records": db.TaskArchiveLLMRecordsPath}}
	originalPath := taskArchivePath(data, 1, fmt.Sprint(task.ID))
	original, compressed, hash, err := writeTaskArchivePackage(originalPath, payload, manifest)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err = pg.QueryRow(`INSERT INTO task_archives(task_id,state,format_version,archive_path,sha256,original_size,compressed_size) VALUES($1,'ready',$2,$3,$4,$5,$6) RETURNING id`, task.ID, manifest.FormatVersion, originalPath, hash, original, compressed).Scan(&id); err != nil {
		t.Fatal(err)
	}
	defer pg.Exec(`DELETE FROM task_archives WHERE id=$1`, id)
	opts := historyprivacy.Options{DSN: dsn, Data: data, Scope: "archive-traffic", ArchiveID: id}
	preview, err := historyprivacy.Run(t.Context(), opts)
	if err != nil || preview.Changes != 1 {
		t.Fatal(preview, err)
	}
	opts.Apply = preview.Fingerprint
	if r, e := historyprivacy.Run(t.Context(), opts); e != nil || !r.Applied {
		t.Fatal(r, e)
	}
	var safePath, safeHash string
	if err = pg.QueryRow(`SELECT archive_path,sha256 FROM task_archives WHERE id=$1`, id).Scan(&safePath, &safeHash); err != nil {
		t.Fatal(err)
	}
	extracted := filepath.Join(t.TempDir(), "extracted")
	if err = extractTaskArchivePackage(safePath, safeHash, extracted); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "database/llm_records.ndjson"} {
		before, e := os.ReadFile(filepath.Join(payload, name))
		if e != nil {
			t.Fatal(e)
		}
		after, e := os.ReadFile(filepath.Join(extracted, name))
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("nontraffic changed", name, e)
		}
	}
	restored, err := installTaskArchiveFiles(data, extracted, fmt.Sprint(task.ID), id)
	if err != nil {
		t.Fatal(err)
	}
	if b, e := os.ReadFile(filepath.Join(data, "tasks", fmt.Sprint(task.ID), "note.txt")); e != nil || string(b) != "workspace unchanged" {
		t.Fatal("workspace restore failed", e)
	}
	tr, err := traffic.Open(filepath.Join(data, "traffic"), ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if n, e := tr.ImportArchive(filepath.Join(extracted, "traffic")); e != nil || n != 1 {
		t.Fatal("traffic restore failed", n, e)
	}
	if err = restored.commit(); err != nil {
		t.Fatal(err)
	}
	_, resp, err := tr.Get("cold-compatible")
	if err != nil || bytes.Contains([]byte(resp), []byte("original-token")) || !bytes.Contains([]byte(resp), []byte("9007199254740993")) {
		t.Fatal("bad restored content", err)
	}
}

func TestTaskArchiveEvidencePrivacyRestoreAndSharedHotSnapshot(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	s.ctx = context.Background()
	secret := "synthetic-cold-evidence-credential"
	body := []byte(`{"token":"archive-unknown-token","number":9007199254740993,"value":"` + secret + `"}`)
	seedServerEvidenceFlow(t, s, "archive-evidence-source", body)
	if _, e := s.m.traffic.DB().Exec(`UPDATE exchange_bodies SET req_head=?,resp_head=? WHERE id=?`, "POST / HTTP/1.1\nAuthorization: Bearer "+secret+"\n", "HTTP/1.1 200 OK\nContent-Type: application/json\n", "archive-evidence-source"); e != nil {
		t.Fatal(e)
	}
	list, e := s.evidenceStore().Bind(s.ctx, f.FindingID, []db.TrafficRef{{TrafficID: "archive-evidence-source", Role: "proof", Note: secret}})
	if e != nil {
		t.Fatal(e)
	}
	finding, e := s.m.pg.GetFinding(f.FindingID)
	if e != nil {
		t.Fatal(e)
	}
	tid := *finding.TaskID
	if _, e = s.m.pg.Exec(`UPDATE findings SET name=$2,evidence=$2,report=$2,status='confirmed',report_evidence_version=evidence_version WHERE id=$1`, f.FindingID, secret); e != nil {
		t.Fatal(e)
	}
	// Preserve terminal retests and both manual/automatic review events through
	// the real archive writer, offline sanitizer and restore worker.
	rt, conversation, _, e := s.m.pg.CreateFindingRetest(s.ctx, f.FindingID, secret)
	if e != nil {
		t.Fatal(e)
	}
	defer s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, conversation.ID)
	if _, e = s.m.pg.StartFindingRetest(s.ctx, rt.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.m.pg.RecordFindingRetestResult(s.ctx, conversation.ID, "inconclusive", secret, secret); e != nil {
		t.Fatal(e)
	}
	if e = s.m.pg.FinishFindingRetest(rt.ID, "completed", ""); e != nil {
		t.Fatal(e)
	}
	finding, e = s.m.pg.GetFinding(f.FindingID)
	if e != nil {
		t.Fatal(e)
	}
	review := db.FindingReview{Fingerprint: db.FindingFingerprint(finding), Verdict: "inconclusive", Sources: secret, Reproduction: secret, CounterEvidence: secret, Limitations: secret}
	if e = s.m.pg.SaveFindingReview(s.ctx, f.FindingID, review); e != nil {
		t.Fatal(e)
	}
	if e = s.m.pg.SaveAutomaticReview(s.ctx, f.FindingID, review.Fingerprint, json.RawMessage(`{"verdict":"inconclusive","note":"`+secret+`","n":9007199254740993}`)); e != nil {
		t.Fatal(e)
	}
	// An independent live task shares the exact same original snapshot and blob.
	sharedTask, e := s.m.CreateTask("shared privacy evidence", "fixture", nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	sharedID, e := strconv.ParseInt(sharedTask.ID, 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	defer s.m.pg.DeleteTask(sharedID)
	shared, e := s.evidenceStore().Record(s.ctx, db.RecordFindingInput{TaskID: sharedID, ExplorationID: sharedTask.ExpID, Summary: "shared", Severity: "low"}, []db.TrafficRef{{TrafficID: "archive-evidence-source"}})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.m.SetTaskPaused(fmt.Sprint(tid), true); e != nil {
		t.Fatal(e)
	}
	job, e := s.m.pg.QueueTaskArchive(tid)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.runOneTaskArchiveJob(); e != nil {
		t.Fatal(e)
	}
	archived, e := s.m.pg.GetTaskArchive(job.ID)
	if e != nil {
		t.Fatal(e)
	}
	beforeDir := t.TempDir()
	if e = extractTaskArchivePackage(archived.ArchivePath, archived.SHA256, beforeDir); e != nil {
		t.Fatal(e)
	}
	originalManifest, e := os.ReadFile(filepath.Join(beforeDir, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var original db.TaskArchiveSnapshot
	if e = json.Unmarshal(originalManifest, &original); e != nil {
		t.Fatal(e)
	}
	dsn, _, e := db.DSN()
	if e != nil {
		t.Fatal(e)
	}
	opts := historyprivacy.Options{DSN: dsn, Data: s.m.dir, Scope: "archive-evidence", ArchiveID: job.ID, Secrets: []string{secret}}
	preview, e := historyprivacy.Run(t.Context(), opts)
	if e != nil || preview.Changes != 7 {
		t.Fatal(preview, e)
	}
	opts.Apply = preview.Fingerprint
	if r, e := historyprivacy.Run(t.Context(), opts); e != nil || !r.Applied {
		t.Fatal(r, e)
	}
	opts.Apply = ""
	if r, e := historyprivacy.Run(t.Context(), opts); e != nil || r.Changes != 0 {
		t.Fatal("repeat preview", r, e)
	}
	changed, e := s.m.pg.GetTaskArchive(job.ID)
	if e != nil {
		t.Fatal(e)
	}
	afterDir := t.TempDir()
	if e = extractTaskArchivePackage(changed.ArchivePath, changed.SHA256, afterDir); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(afterDir, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var sanitized db.TaskArchiveSnapshot
	if e = json.Unmarshal(raw, &sanitized); e != nil {
		t.Fatal(e)
	}
	for name, old := range original.Tables {
		if name == "findings" || name == "traffic_evidence_snapshots" || name == "finding_traffic_bindings" || name == "finding_retests" || name == "finding_reviews" || name == "finding_review_history" {
			continue
		}
		var a, b bytes.Buffer
		if e = json.Compact(&a, old); e != nil {
			t.Fatal(e)
		}
		if e = json.Compact(&b, sanitized.Tables[name]); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Fatal("unrelated table changed", name)
		}
	}
	// Validate both archive cleanup and preservation of the independently live copy.
	oldSnap := list.Bindings[0].Snapshot
	if _, e = os.Stat(filepath.Join(afterDir, "evidence", "blobs", oldSnap.RespHash[:2], oldSnap.RespHash+".bin")); !os.IsNotExist(e) {
		t.Fatal("original cold blob retained", e)
	}
	if e = s.evidenceStore().WithBinding(s.ctx, shared.FindingID, shared.Traffic.Bindings[0].ID, func(b db.FindingTrafficBinding) error {
		r, _, e := s.evidenceStore().OpenBody(b.Snapshot, "response")
		if e != nil {
			return e
		}
		defer r.Close()
		got, e := io.ReadAll(r)
		if !bytes.Equal(got, body) {
			t.Fatal("shared hot evidence changed")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.m.pg.QueueTaskArchiveRestore(job.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.runOneTaskArchiveJob(); e != nil {
		t.Fatal(e)
	}
	restored, e := s.m.pg.GetFindingTraffic(s.ctx, f.FindingID)
	if e != nil {
		t.Fatal(e)
	}
	if restored.Version != list.Version+1 || restored.ReportVersion != list.Version || len(restored.Bindings) != 1 {
		t.Fatal("staleness lost", restored)
	}
	if sanitized.FormatVersion != 4 || sanitized.DataCounts["finding_retests"] != 1 || sanitized.DataCounts["finding_reviews"] != 1 || sanitized.DataCounts["finding_review_history"] != 2 {
		t.Fatal("missing history", sanitized.DataCounts)
	}
	for _, table := range []string{"finding_retests", "finding_reviews", "finding_review_history"} {
		var got []byte
		key := "id"
		if table == "finding_reviews" {
			key = "finding_id"
		}
		if e = s.m.pg.QueryRow("SELECT jsonb_agg(to_jsonb(r) ORDER BY "+key+") FROM "+table+" r WHERE finding_id=$1", f.FindingID).Scan(&got); e != nil {
			t.Fatal(e)
		}
		var expected, actual any
		decode := func(raw []byte, dst *any) {
			d := json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			if e := d.Decode(dst); e != nil {
				t.Fatal(e)
			}
		}
		decode(sanitized.Tables[table], &expected)
		decode(got, &actual)
		if !reflect.DeepEqual(expected, actual) || bytes.Contains(got, []byte(secret)) {
			t.Fatal("restored history altered or not sanitized", table)
		}
	}
	savedReview, e := s.m.pg.GetFindingReview(f.FindingID)
	if e != nil || savedReview.Fingerprint != review.Fingerprint {
		t.Fatal("original fingerprint lost", e)
	}
	current, e := s.m.pg.GetFinding(f.FindingID)
	if e != nil || db.FindingFingerprint(current) == savedReview.Fingerprint {
		t.Fatal("sanitized review should be stale", e)
	}
	savedReview.Fingerprint = db.FindingFingerprint(current)
	if e = s.m.pg.SaveFindingReview(s.ctx, f.FindingID, *savedReview); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = s.m.pg.QueryRow(`SELECT count(*) FROM finding_review_history WHERE finding_id=$1`, f.FindingID).Scan(&count); e != nil || count != 3 {
		t.Fatal("review trigger not active after restore", count, e)
	}
	b := restored.Bindings[0]
	if b.ID != list.Bindings[0].ID || b.SnapshotID == oldSnap.ID || b.Role != "proof" || strings.Contains(b.Note, secret) {
		t.Fatal("restored binding invalid")
	}
	found, e := s.m.pg.GetFinding(f.FindingID)
	if e != nil || found.Status != "confirmed" || strings.Contains(found.Report, secret) || strings.Contains(found.Evidence, secret) {
		t.Fatal("restored finding invalid", e)
	}
	if e = s.evidenceStore().WithBinding(s.ctx, f.FindingID, b.ID, func(b db.FindingTrafficBinding) error {
		r, _, e := s.evidenceStore().OpenBody(b.Snapshot, "response")
		if e != nil {
			return e
		}
		defer r.Close()
		got, e := io.ReadAll(r)
		if bytes.Contains(got, []byte(secret)) || bytes.Contains(got, []byte("archive-unknown-token")) || !bytes.Contains(got, []byte("9007199254740993")) {
			t.Fatal("restored evidence incorrect")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
