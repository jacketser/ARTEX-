package historyprivacy

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func evidenceMembers(t *testing.T, taskID int64) ([]archiveMember, db.TrafficEvidenceSnapshot) {
	t.Helper()
	req := []byte{}
	resp := []byte(`{"token":"cold-evidence-token","n":9007199254740993,"value":"` + testSecret + `"}`)
	snap := db.TrafficEvidenceSnapshot{SourceTrafficID: "original-evidence", CapturedAt: 123, URL: "http://fixture.test/?token=query-secret", Method: "GET", Status: 200, ContentType: "application/json", ReqHead: "GET / HTTP/1.1\nAuthorization: Bearer header-secret\n", RespHead: "HTTP 200\nContent-Type: application/json\n", ReqHash: bodyHash(req), RespHash: bodyHash(resp), RespLen: int64(len(resp)), CreatedAt: time.Unix(123, 0).UTC()}
	snap.ID = db.TrafficSnapshotID(snap)
	raw, _ := json.Marshal(snap)
	var sr archiveRow
	json.Unmarshal(raw, &sr)
	sr["unreferenced_at"] = json.RawMessage("null")
	finding := archiveRow{}
	for k, v := range map[string]any{"id": int64(9007199254740993), "task_id": taskID, "name": "finding " + testSecret, "summary": "summary", "evidence": "evidence " + testSecret, "report": "report " + testSecret, "evidence_version": int64(7), "report_evidence_version": int64(7), "status": "confirmed", "asset_ids": []int64{9007199254740993}} {
		setArchiveField(finding, k, v)
	}
	binding := archiveRow{}
	for k, v := range map[string]any{"id": int64(9007199254740995), "finding_id": int64(9007199254740993), "snapshot_id": snap.ID, "role": "proof", "note": "note " + testSecret, "position": 0, "created_at": "2026-01-01T00:00:00Z"} {
		setArchiveField(binding, k, v)
	}
	tables := map[string]any{"findings": []archiveRow{finding}, "traffic_evidence_snapshots": []archiveRow{sr}, "finding_traffic_bindings": []archiveRow{binding}, "activity": json.RawMessage(`[{"id":9007199254740993,"text":"unprocessed log"}]`)}
	manifest, _ := json.Marshal(map[string]any{"format_version": 3, "task_id": taskID, "tables": tables, "data_counts": map[string]int64{"findings": 1, "traffic_evidence_snapshots": 1, "finding_traffic_bindings": 1, "activity": 1}, "aggregate_stats": json.RawMessage(`{"n":9007199254740993}`)})
	return []archiveMember{archiveFile("manifest.json", manifest), archiveFile(evidenceArchivePath(snap.ReqHash), req), archiveFile(evidenceArchivePath(snap.RespHash), resp), archiveFile("traffic/traffic.json", []byte(`{"version":1,"exchanges":[],"blobs":[]}`)), archiveFile("files/tasks/note.txt", []byte("not processed "+testSecret))}, snap
}
func evidenceManifest(t *testing.T, m []archiveMember) (archiveRow, map[string][]archiveRow) {
	t.Helper()
	var manifest archiveRow
	var tables map[string][]archiveRow
	if e := json.Unmarshal(m[0].Body, &manifest); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(manifest["tables"], &tables); e != nil {
		t.Fatal(e)
	}
	return manifest, tables
}
func saveEvidenceManifest(t *testing.T, m []archiveMember, manifest archiveRow, tables map[string][]archiveRow) {
	t.Helper()
	setArchiveField(manifest, "tables", tables)
	raw, e := json.Marshal(manifest)
	if e != nil {
		t.Fatal(e)
	}
	m[0] = archiveFile("manifest.json", raw)
}
func TestArchiveEvidenceReferencesVersionsAndPrecision(t *testing.T) {
	m, old := evidenceMembers(t, 42)
	p := &plan{secrets: []string{testSecret}}
	safe, e := redactArchiveEvidence(m, archiveCatalog{TaskID: 42, Version: 3}, p)
	if e != nil || p.report.Rows != 3 || p.report.Changes != 3 {
		t.Fatal(p.report, e)
	}
	manifest, tables := evidenceManifest(t, safe)
	finding := tables["findings"][0]
	binding := tables["finding_traffic_bindings"][0]
	ev, _ := rowInt(finding, "evidence_version", false)
	rv, _ := rowInt(finding, "report_evidence_version", false)
	id, _ := rowInt(finding, "id", false)
	if ev != 8 || rv != 7 || id != 9007199254740993 || string(finding["asset_ids"]) != "[9007199254740993]" || string(finding["status"]) != `"confirmed"` {
		t.Fatal("version, precision or disposition changed", finding)
	}
	if string(manifest["aggregate_stats"]) != `{"n":9007199254740993}` || string(tables["activity"][0]["id"]) != "9007199254740993" {
		t.Fatal("unrelated manifest changed")
	}
	raw, _ := json.Marshal(tables["traffic_evidence_snapshots"][0])
	var snapshot db.TrafficEvidenceSnapshot
	if e = json.Unmarshal(raw, &snapshot); e != nil {
		t.Fatal(e)
	}
	sid, _ := rowString(binding, "snapshot_id", false)
	if snapshot.ID == old.ID || db.TrafficSnapshotID(snapshot) != snapshot.ID || sid != snapshot.ID || snapshot.CapturedAt != old.CapturedAt || !snapshot.CreatedAt.Equal(old.CreatedAt) {
		t.Fatal("invalid snapshot identity")
	}
	for _, member := range safe {
		name := member.Header.Name
		if name == evidenceArchivePath(old.RespHash) {
			t.Fatal("raw evidence retained")
		}
		if strings.HasPrefix(name, "evidence/") || name == "manifest.json" {
			for _, secret := range []string{testSecret, "cold-evidence-token", "header-secret", "query-secret"} {
				if bytes.Contains(member.Body, []byte(secret)) {
					t.Fatal("secret remains", name)
				}
			}
		} else {
			found := false
			for _, before := range m {
				if before.Header.Name == name {
					found = true
					if !bytes.Equal(member.Body, before.Body) {
						t.Fatal("non-evidence member changed")
					}
				}
			}
			if !found {
				t.Fatal("unexpected member")
			}
		}
	}
	again := &plan{secrets: []string{testSecret}}
	if _, e = redactArchiveEvidence(safe, archiveCatalog{TaskID: 42, Version: 3}, again); e != nil || again.report.Changes != 0 {
		t.Fatal("not idempotent", again.report, e)
	}
}

func TestArchiveEvidenceRejectsInvalidRelationsAndExtensions(t *testing.T) {
	for _, name := range []string{"count", "missing-body", "corrupt-body", "unknown-file", "unknown-field", "dangling-binding", "external-finding", "duplicate-binding", "duplicate-snapshot", "unbound-snapshot", "future-version", "overflow", "invalid-version", "legacy-snapshot", "review-extension", "streamed-evidence", "collision"} {
		t.Run(name, func(t *testing.T) {
			m, snap := evidenceMembers(t, 42)
			manifest, tables := evidenceManifest(t, m)
			var counts map[string]int64
			json.Unmarshal(manifest["data_counts"], &counts)
			switch name {
			case "count":
				counts["findings"]++
			case "missing-body":
				m = append(m[:2], m[3:]...)
			case "corrupt-body":
				m[2] = archiveFile(m[2].Header.Name, []byte("corrupt"))
			case "unknown-file":
				m = append(m, archiveFile("evidence/unknown.txt", []byte("secret")))
			case "unknown-field":
				setArchiveField(tables["findings"][0], "future_secret", "secret")
			case "dangling-binding":
				setArchiveField(tables["finding_traffic_bindings"][0], "snapshot_id", strings.Repeat("a", 64))
			case "external-finding":
				setArchiveField(tables["findings"][0], "task_id", 43)
			case "duplicate-binding":
				tables["finding_traffic_bindings"] = append(tables["finding_traffic_bindings"], tables["finding_traffic_bindings"][0])
				counts["finding_traffic_bindings"]++
			case "duplicate-snapshot":
				tables["traffic_evidence_snapshots"] = append(tables["traffic_evidence_snapshots"], tables["traffic_evidence_snapshots"][0])
				counts["traffic_evidence_snapshots"]++
			case "unbound-snapshot":
				tables["finding_traffic_bindings"] = nil
				counts["finding_traffic_bindings"] = 0
			case "future-version":
				setArchiveField(tables["findings"][0], "report_evidence_version", 9)
			case "overflow":
				setArchiveField(tables["findings"][0], "evidence_version", int64(math.MaxInt64))
			case "invalid-version":
				setArchiveField(tables["findings"][0], "evidence_version", nil)
			case "legacy-snapshot":
				setArchiveField(manifest, "format_version", 2)
			case "review-extension":
				tables["finding_reviews"] = []archiveRow{{"finding_id": json.RawMessage("1")}}
			case "streamed-evidence":
				setArchiveField(manifest, "streamed_tables", map[string]string{"findings": "database/findings.ndjson"})
			case "collision":
				snap.URL = "http://fixture.test/?token=other-secret"
				snap.ID = db.TrafficSnapshotID(snap)
				b, _ := json.Marshal(snap)
				var row archiveRow
				json.Unmarshal(b, &row)
				tables["traffic_evidence_snapshots"] = append(tables["traffic_evidence_snapshots"], row)
				counts["traffic_evidence_snapshots"]++
			}
			setArchiveField(manifest, "data_counts", counts)
			saveEvidenceManifest(t, m, manifest, tables)
			version := 3
			if name == "legacy-snapshot" {
				version = 2
			}
			if _, e := redactArchiveEvidence(m, archiveCatalog{TaskID: 42, Version: version}, &plan{secrets: []string{testSecret}}); e == nil {
				t.Fatal("unsafe evidence accepted")
			}
		})
	}
}

func TestArchiveEvidencePublicationFailureAndRetry(t *testing.T) {
	opts, pg, c, _ := archiveFixture(t)
	opts.Scope = "archive-evidence"
	m, _ := evidenceMembers(t, c.TaskID)
	packed, size, e := encodePrivacyArchive(m)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(c.Path, packed, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = pg.Exec(`UPDATE task_archives SET sha256=$1,original_size=$2,compressed_size=$3 WHERE id=$4`, bodyHash(packed), size, len(packed), c.ID); e != nil {
		t.Fatal(e)
	}
	r, e := Run(t.Context(), opts)
	if e != nil || r.Changes != 3 {
		t.Fatal(r, e)
	}
	files, _ := os.ReadDir(filepath.Dir(c.Path))
	if len(files) != 1 {
		t.Fatal("preview wrote package")
	}
	opts.Apply = r.Fingerprint
	if _, e = pg.Exec(`CREATE FUNCTION reject_evidence_package() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$ LANGUAGE plpgsql; CREATE TRIGGER reject_evidence_package BEFORE UPDATE ON task_archives FOR EACH ROW EXECUTE FUNCTION reject_evidence_package()`); e != nil {
		t.Fatal(e)
	}
	if r, e = Run(t.Context(), opts); e == nil || r.Applied {
		t.Fatal("failed publication marked complete")
	}
	current, e := os.ReadFile(c.Path)
	if e != nil || !bytes.Equal(current, packed) {
		t.Fatal("failed publication damaged original")
	}
	if _, e = pg.Exec(`DROP TRIGGER reject_evidence_package ON task_archives`); e != nil {
		t.Fatal(e)
	}
	if r, e = Run(t.Context(), opts); e != nil || !r.Applied {
		t.Fatal("retry failed", r, e)
	}
	opts.Apply = ""
	if r, e = Run(t.Context(), opts); e != nil || r.Changes != 0 {
		t.Fatal("not idempotent", r, e)
	}
}

func TestArchiveEvidenceLegacyTextAndEmpty(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		m, _ := evidenceMembers(t, 42)
		manifest, tables := evidenceManifest(t, m)
		tables["traffic_evidence_snapshots"], tables["finding_traffic_bindings"] = nil, nil
		delete(tables["findings"][0], "evidence_version")
		delete(tables["findings"][0], "report_evidence_version")
		setArchiveField(manifest, "format_version", version)
		setArchiveField(manifest, "data_counts", map[string]int64{"findings": 1})
		m = append(m[:1], m[3:]...)
		saveEvidenceManifest(t, m, manifest, tables)
		safe, e := redactArchiveEvidence(m, archiveCatalog{TaskID: 42, Version: version}, &plan{secrets: []string{testSecret}})
		if e != nil {
			t.Fatal(e)
		}
		_, out := evidenceManifest(t, safe)
		ev, _ := rowInt(out["findings"][0], "evidence_version", false)
		if ev != 1 {
			t.Fatal("missing legacy version not advanced")
		}
		tables["findings"] = nil
		setArchiveField(manifest, "data_counts", map[string]int64{})
		saveEvidenceManifest(t, m, manifest, tables)
		p := &plan{}
		if _, e = redactArchiveEvidence(m, archiveCatalog{TaskID: 42, Version: version}, p); e != nil || p.report.Changes != 0 {
			t.Fatal("empty archive rejected", e)
		}
	}
}

func TestArchiveEvidenceSharedBodyAndSingleVersionIncrement(t *testing.T) {
	m, snap := evidenceMembers(t, 42)
	manifest, tables := evidenceManifest(t, m)
	snap.SourceTrafficID = "second-source"
	snap.ID = db.TrafficSnapshotID(snap)
	raw, _ := json.Marshal(snap)
	var row archiveRow
	json.Unmarshal(raw, &row)
	tables["traffic_evidence_snapshots"] = append(tables["traffic_evidence_snapshots"], row)
	b := archiveRow{}
	for k, v := range tables["finding_traffic_bindings"][0] {
		b[k] = v
	}
	setArchiveField(b, "id", int64(9007199254740996))
	setArchiveField(b, "snapshot_id", snap.ID)
	setArchiveField(b, "position", 1)
	setArchiveField(b, "role", "baseline")
	tables["finding_traffic_bindings"] = append(tables["finding_traffic_bindings"], b)
	untouched := archiveRow{}
	for k, v := range tables["findings"][0] {
		untouched[k] = v
	}
	setArchiveField(untouched, "id", int64(9007199254740997))
	for _, k := range []string{"name", "summary", "report", "evidence"} {
		setArchiveField(untouched, k, "clean text")
	}
	tables["findings"] = append(tables["findings"], untouched)
	setArchiveField(manifest, "data_counts", map[string]int64{"findings": 2, "traffic_evidence_snapshots": 2, "finding_traffic_bindings": 2})
	saveEvidenceManifest(t, m, manifest, tables)
	p := &plan{secrets: []string{testSecret}}
	safe, e := redactArchiveEvidence(m, archiveCatalog{TaskID: 42, Version: 3}, p)
	if e != nil || p.report.Rows != 6 || p.report.Changes != 5 {
		t.Fatal(p.report, e)
	}
	_, out := evidenceManifest(t, safe)
	ev, _ := rowInt(out["findings"][0], "evidence_version", false)
	clean, _ := rowInt(out["findings"][1], "evidence_version", false)
	if ev != 8 || clean != 7 {
		t.Fatal("version advanced more than once or untouched finding changed")
	}
	blobs := 0
	for _, member := range safe {
		if strings.HasPrefix(member.Header.Name, "evidence/blobs/") {
			blobs++
		}
	}
	if blobs != 2 {
		t.Fatal("shared bodies not deduplicated", blobs)
	}
}

func TestArchiveEvidenceV4HistoryRedaction(t *testing.T) {
	m, _ := evidenceMembers(t, 42)
	manifest, tables := evidenceManifest(t, m)
	fid := int64(9007199254740993)
	row := func(values map[string]any) archiveRow {
		r := archiveRow{}
		for k, v := range values {
			setArchiveField(r, k, v)
		}
		return r
	}
	tables["finding_retests"] = []archiveRow{row(map[string]any{"id": fid + 10, "finding_id": fid, "conversation_id": nil, "status": "completed", "verdict": "inconclusive", "notes": testSecret, "summary": testSecret, "evidence": testSecret, "error": testSecret, "snapshot": map[string]any{"token": "nested-secret", "n": fid, "summary": testSecret}, "created_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-02T00:00:00Z"})}
	tables["finding_reviews"] = []archiveRow{row(map[string]any{"finding_id": fid, "fingerprint": "original-historical-fingerprint", "verdict": "inconclusive", "sources": testSecret, "reproduction": testSecret, "counter_evidence": testSecret, "limitations": testSecret, "updated_at": "2026-01-01T00:00:00Z"})}
	tables["finding_review_history"] = []archiveRow{row(map[string]any{"id": fid + 20, "finding_id": fid, "kind": "automatic", "fingerprint": "original-historical-fingerprint", "result": map[string]any{"token": "nested-secret", "n": fid, "note": testSecret}, "created_at": "2026-01-01T00:00:00Z"})}
	counts := map[string]int64{}
	for name, rows := range tables {
		counts[name] = int64(len(rows))
	}
	setArchiveField(manifest, "format_version", 4)
	setArchiveField(manifest, "data_counts", counts)
	saveEvidenceManifest(t, m, manifest, tables)
	p := &plan{secrets: []string{testSecret}}
	safe, e := redactArchiveEvidence(m, archiveCatalog{TaskID: 42, Version: 4}, p)
	if e != nil || p.report.Rows != 6 || p.report.Changes != 6 {
		t.Fatal(p.report, e)
	}
	_, out := evidenceManifest(t, safe)
	for _, name := range []string{"finding_retests", "finding_reviews", "finding_review_history"} {
		raw, _ := json.Marshal(out[name])
		if bytes.Contains(raw, []byte(testSecret)) || bytes.Contains(raw, []byte("nested-secret")) {
			t.Fatal("history secret retained", name)
		}
		for _, key := range []string{"id", "finding_id", "conversation_id", "status", "verdict", "fingerprint", "kind", "created_at", "finished_at", "updated_at"} {
			if !bytes.Equal(tables[name][0][key], out[name][0][key]) {
				t.Fatal("historical metadata changed", name, key)
			}
		}
	}
	if !bytes.Contains(out["finding_retests"][0]["snapshot"], []byte("9007199254740993")) || !bytes.Contains(out["finding_review_history"][0]["result"], []byte("9007199254740993")) {
		t.Fatal("nested integer precision lost")
	}
	ev, _ := rowInt(out["findings"][0], "evidence_version", false)
	if ev != 8 {
		t.Fatal("version incremented repeatedly", ev)
	}
	again := &plan{secrets: []string{testSecret}}
	if _, e = redactArchiveEvidence(safe, archiveCatalog{TaskID: 42, Version: 4}, again); e != nil || again.report.Changes != 0 {
		t.Fatal("history redaction not idempotent", again.report, e)
	}
}
