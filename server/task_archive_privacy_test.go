package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
