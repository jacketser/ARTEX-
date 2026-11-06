package historyprivacy

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func trafficDB(t *testing.T, opts Options) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", filepath.Join(opts.Data, "traffic", "_index", "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func applyBatch(t *testing.T, opts Options) Report {
	t.Helper()
	opts.Apply = ""
	preview, err := Run(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if preview.NextCursor != "" || preview.Applied {
		t.Fatal("preview advanced progress", preview)
	}
	opts.Apply = preview.Fingerprint
	done, err := Run(t.Context(), opts)
	if err != nil || !done.Applied || done.Rows != preview.Rows || done.More != preview.More {
		t.Fatal(done, err)
	}
	if done.More && done.NextCursor == "" {
		t.Fatal("missing continuation", done)
	}
	return done
}

func TestHistoryTrafficLargeBatchResumeAndIndex(t *testing.T) {
	opts, _ := fixture(t)
	_, _ = seedTraffic(t, opts, false)
	d := trafficDB(t, opts)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	// More than the former entire-store limit.
	for i := 1; i < 10001; i++ {
		id := fmt.Sprintf("batch-%05d", i)
		for _, q := range []string{
			`INSERT INTO exchanges SELECT ?,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path FROM exchanges WHERE id='one'`,
			`INSERT INTO exchange_bodies SELECT ?,req_head,req_body,req_blob,resp_head,resp_body,resp_blob FROM exchange_bodies WHERE id='one'`,
		} {
			if _, err = tx.Exec(q, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err = tx.Exec(`INSERT INTO ex_fts(rowid,content) SELECT rowid,'untouchedsentinel' FROM exchanges WHERE id='batch-10000'`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Row-bounded traversal and index updates must cover the complete store.
	opts.BatchSize = 4096
	first := applyBatch(t, opts)
	if !first.More || first.Rows != 4096 {
		t.Fatal("row bound not applied", first)
	}
	var hits int
	if err = d.QueryRow(`SELECT count(*) FROM ex_fts WHERE ex_fts MATCH 'untouchedsentinel'`).Scan(&hits); err != nil || hits != 1 {
		t.Fatal("other batch index lost", hits, err)
	}
	// Resume exclusively from a successfully persisted audit, as after process exit.
	if err = Audit(opts.Data, first, "complete"); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(opts.Data, "privacy-audit", "*.json"))
	b, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var saved Report
	if err = json.Unmarshal(b, &saved); err != nil {
		t.Fatal(err)
	}
	opts.Cursor = saved.NextCursor
	preview, err := Run(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	stale := opts
	stale.BatchSize = 1
	stale.Apply = preview.Fingerprint
	if r, e := Run(t.Context(), stale); e == nil || r.NextCursor != "" {
		t.Fatal("different batch applied", r, e)
	}
	moved := opts
	moved.Secrets = append(moved.Secrets, "changed-known-secret")
	if _, e := Run(t.Context(), moved); e == nil {
		t.Fatal("changed credentials accepted cursor")
	}
	if _, err = d.Exec(`CREATE TRIGGER fail_batch BEFORE UPDATE ON exchanges BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`); err != nil {
		t.Fatal(err)
	}
	opts.Apply = preview.Fingerprint
	if r, e := Run(t.Context(), opts); e == nil || r.Applied || r.NextCursor != "" {
		t.Fatal("failed batch advanced", r, e)
	}
	if _, err = d.Exec(`DROP TRIGGER fail_batch`); err != nil {
		t.Fatal(err)
	}
	// Same fingerprint remains usable after rollback.
	retried, err := Run(t.Context(), opts)
	if err != nil || !retried.Applied {
		t.Fatal(retried, err)
	}
	total := first.Rows + retried.Rows
	next := retried
	for batches := 0; next.More; batches++ {
		if batches > 100 {
			t.Fatal("cursor did not terminate")
		}
		opts.Cursor = next.NextCursor
		next = applyBatch(t, opts)
		total += next.Rows
	}
	if total != 10001 {
		t.Fatal("records skipped or repeated", total)
	}
	if err = d.QueryRow(`SELECT count(*) FROM exchange_bodies WHERE coalesce(resp_blob,'')<>'' OR instr(resp_body,?)>0`, testSecret).Scan(&hits); err != nil || hits != 0 {
		t.Fatal("unsanitized rows", hits, err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM ex_fts WHERE ex_fts MATCH 'untouchedsentinel'`).Scan(&hits); err != nil || hits != 0 {
		t.Fatal("final index not replaced", hits, err)
	}
	opts.Cursor = ""
	opts.Apply = ""
	last, err := Run(t.Context(), opts)
	if err != nil || last.Changes != 0 || !last.More {
		t.Fatal(last, err)
	}
	// A zero-change page still needs an acknowledged apply to obtain its cursor.
	done := applyBatch(t, opts)
	if done.Changes != 0 || done.NextCursor == "" {
		t.Fatal(done)
	}
}

func seedBatchEvidence(t *testing.T, opts Options, pg *db.DB, n int) []string {
	t.Helper()
	root := filepath.Join(opts.Data, "evidence")
	body := []byte(`{"password":"shared-target-secret","value":"` + testSecret + `"}`)
	old := []string{}
	for i := 0; i < n; i++ {
		v := db.TrafficEvidenceSnapshot{SourceTrafficID: fmt.Sprint(i), CapturedAt: 1, URL: "http://fixture.test/?token=secret", Method: "GET", Status: 200, ContentType: "application/json", ReqHead: "GET /?token=secret HTTP/1.1\nCookie: session=secret\n", RespHead: "HTTP 200\nContent-Type: application/json\n", ReqHash: bodyHash(nil), RespHash: bodyHash(body), RespLen: int64(len(body))}
		v.ID = db.TrafficSnapshotID(v)
		for _, b := range [][]byte{nil, body} {
			if err := writeBody(root, bodyHash(b), b); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pg.Exec(`INSERT INTO traffic_evidence_snapshots(id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, v.ID, v.SourceTrafficID, v.CapturedAt, v.URL, v.Method, v.Status, v.ContentType, v.ReqHead, v.RespHead, v.ReqHash, v.RespHash, v.ReqLen, v.RespLen); err != nil {
			t.Fatal(err)
		}
		var id int64
		if err := pg.QueryRow(`INSERT INTO findings(summary,report,evidence_version,report_evidence_version,status) VALUES($1,$1,4,4,'confirmed') RETURNING id`, testSecret).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := pg.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position) VALUES($1,$2,'proof',$3,0)`, id, v.ID, testSecret); err != nil {
			t.Fatal(err)
		}
		if _, err := pg.Exec(`INSERT INTO finding_reviews(finding_id,fingerprint,verdict,sources) VALUES($1,'old-fingerprint','supported',$2)`, id, testSecret); err != nil {
			t.Fatal(err)
		}
		if _, err := pg.Exec(`INSERT INTO finding_retests(finding_id,notes,snapshot) VALUES($1,$2,'{}')`, id, testSecret); err != nil {
			t.Fatal(err)
		}
		old = append(old, v.ID)
	}
	return old
}

func TestHistoryEvidenceBatchMutableIDsAndHistory(t *testing.T) {
	opts, pg := fixture(t)
	opts.Scope = "evidence"
	opts.BatchSize = 1
	old := seedBatchEvidence(t, opts, pg, 4)
	changes := 0
	for batches := 0; ; batches++ {
		if batches > 40 {
			t.Fatal("mutable snapshot cursor did not terminate")
		}
		done := applyBatch(t, opts)
		changes += done.Changes
		if done.Rows > 1 {
			t.Fatal("batch row limit ignored", done)
		}
		if !done.More {
			break
		}
		opts.Cursor = done.NextCursor
	}
	if changes != 24 {
		t.Fatal("missing or repeated mutations", changes)
	}
	for _, id := range old {
		var n int
		if err := pg.QueryRow(`SELECT count(*) FROM traffic_evidence_snapshots WHERE id=$1`, id).Scan(&n); err != nil || n != 0 {
			t.Fatal("old snapshot skipped", n, err)
		}
	}
	var invalid int
	if err := pg.QueryRow(`SELECT count(*) FROM findings WHERE evidence_version<=4 OR report_evidence_version<>4 OR status<>'confirmed' OR summary=$1`, testSecret).Scan(&invalid); err != nil || invalid != 0 {
		t.Fatal("finding state invalid", invalid, err)
	}
	for _, table := range []string{"findings", "finding_retests", "finding_reviews", "finding_review_history", "finding_traffic_bindings"} {
		if err := pg.QueryRow("SELECT count(*) FROM "+table+" t WHERE to_jsonb(t)::text LIKE $1", "%"+testSecret+"%").Scan(&invalid); err != nil || invalid != 0 {
			t.Fatal("text skipped", table, invalid, err)
		}
	}
	var count int
	if err := pg.QueryRow(`SELECT count(*) FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id`).Scan(&count); err != nil || count != 4 {
		t.Fatal("binding lost", count, err)
	}
	rows, err := pg.Query(`SELECT resp_hash FROM traffic_evidence_snapshots`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		if err = rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		b, e := readBody(filepath.Join(opts.Data, "evidence"), filepath.Join("blobs", h[:2], h+".bin"), h)
		if e != nil || bytes.Contains(b, []byte("shared-target-secret")) {
			t.Fatal("invalid body", e)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	opts.Cursor = ""
	opts.BatchSize = 100
	again := applyBatch(t, opts)
	if again.More || again.Changes != 0 {
		t.Fatal("not idempotent", again)
	}
}

func TestHistoryEvidenceOverFormerStoreLimit(t *testing.T) {
	opts, pg := fixture(t)
	opts.Scope = "evidence"
	opts.BatchSize = 5000
	if _, err := pg.Exec(`INSERT INTO findings(summary) SELECT $1 FROM generate_series(1,10001)`, testSecret); err != nil {
		t.Fatal(err)
	}
	count := 0
	for {
		r := applyBatch(t, opts)
		count += r.Rows
		if !r.More {
			break
		}
		opts.Cursor = r.NextCursor
	}
	if count != 10001 {
		t.Fatal("missed evidence", count)
	}
	var remaining int
	if err := pg.QueryRow(`SELECT count(*) FROM findings WHERE summary=$1`, testSecret).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal(remaining, err)
	}
}

func TestHistoryBatchRejectsMalformedCursor(t *testing.T) {
	for _, opts := range []Options{{Scope: "traffic", BatchSize: 10001}, {Scope: "traffic", BatchSize: -1}, {Scope: "evidence", Cursor: "private-value"}, {Scope: "traffic", Cursor: strings.Repeat("x", 4096)}} {
		if r, e := Run(t.Context(), opts); e == nil || r.NextCursor != "" || strings.Contains(e.Error(), "private-value") {
			t.Fatal(r, e)
		}
	}
}

func TestHistoryTrafficByteBudgetAndSharedBlob(t *testing.T) {
	opts, _ := fixture(t)
	hash, _ := seedTraffic(t, opts, true)
	d := trafficDB(t, opts)
	for _, q := range []string{
		`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<599) INSERT INTO exchanges SELECT 'copy-'||i,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path FROM exchanges,n WHERE id='one'`,
		`INSERT INTO exchange_bodies SELECT e.id,b.req_head,b.req_body,b.req_blob,b.resp_head,b.resp_body,b.resp_blob FROM exchanges e,exchange_bodies b WHERE e.id<>'one' AND b.id='one'`,
		`INSERT INTO blob_refs(hash,exchange_id) SELECT resp_blob,id FROM exchange_bodies WHERE id<>'one'`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	opts.BatchSize = 1000
	first := applyBatch(t, opts)
	if !first.More || first.Rows < 1 || first.Rows >= 600 {
		t.Fatal("byte bound ignored", first)
	}
	path := filepath.Join(opts.Data, "traffic", "_blobs", "sha256", hash[:2], hash+".bin")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("shared blob removed early", err)
	}
	opts.Cursor = first.NextCursor
	second := applyBatch(t, opts)
	if second.More || first.Rows+second.Rows != 600 {
		t.Fatal("byte-bound resume skipped data", first, second)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unreferenced shared blob retained", err)
	}
}

func TestHistoryBatchDoesNotSkipMissingBody(t *testing.T) {
	opts, _ := fixture(t)
	seedTraffic(t, opts, false)
	d := trafficDB(t, opts)
	if _, err := d.Exec(`INSERT INTO exchanges SELECT 'missing',ts,host,method,url_template,url,status,content_type,req_len,resp_len,path FROM exchanges WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	opts.BatchSize = 1
	first := applyBatch(t, opts)
	if !first.More {
		t.Fatal("missing body incorrectly treated as end", first)
	}
	opts.Cursor = first.NextCursor
	if r, e := Run(t.Context(), opts); e == nil || r.Applied || r.NextCursor != "" {
		t.Fatal("missing body skipped", r, e)
	}
	wrong := opts
	wrong.Scope = "evidence"
	if _, e := Run(t.Context(), wrong); e == nil {
		t.Fatal("cross-scope continuation accepted")
	}
}
