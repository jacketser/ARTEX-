package historyprivacy

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

const testSecret = "synthetic-history-secret-12345"

func fixture(t *testing.T) (Options, *db.DB) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN required")
	}
	parent, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("privacy_%d", time.Now().UnixNano())
	if _, err = parent.Exec("CREATE DATABASE " + name); err != nil {
		parent.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { parent.Exec("DROP DATABASE " + name + " WITH (FORCE)"); parent.Close() })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	pg, err := db.Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	return Options{DSN: u.String(), Data: t.TempDir(), Scope: "traffic", Secrets: []string{testSecret}}, pg
}
func seedTraffic(t *testing.T, opts Options, blob bool) (string, []byte) {
	t.Helper()
	root := filepath.Join(opts.Data, "traffic")
	tr, err := traffic.Open(root, ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	body := []byte(`{"token":"unknown-token","n":9007199254740993,"value":"` + testSecret + `"}`)
	hash := ""
	inline := body
	if blob {
		body = append(body, bytes.Repeat([]byte(" "), 300000)...)
		hash = bodyHash(body)
		path := filepath.Join(root, "_blobs", "sha256", hash[:2], hash+".bin")
		os.MkdirAll(filepath.Dir(path), 0700)
		if err = os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		inline = []byte("old preview " + testSecret)
	}
	if _, err = tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES('one',1,'lab.test','GET','/','http://lab.test/?token=unknown-query',200,'application/json',0,?,'')`, len(body)); err != nil {
		t.Fatal(err)
	}
	if _, err = tr.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body,resp_blob) VALUES('one',?,X'',?,?,?)`, "GET /?token=unknown-query HTTP/1.1\nAuthorization: Bearer unknown-header\nHost: lab.test\n", "HTTP 200\nContent-Type: application/json\nSet-Cookie: session=unknown-cookie\n", inline, hash); err != nil {
		t.Fatal(err)
	}
	if hash != "" {
		if _, err = tr.DB().Exec(`INSERT INTO blob_refs(hash,exchange_id) VALUES(?,'one')`, hash); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tr.DB().Exec(`INSERT INTO ex_fts(rowid,content) SELECT rowid,? FROM exchanges WHERE id='one'`, string(body)); err != nil {
		t.Fatal(err)
	}
	return hash, body
}

func TestHistoryTrafficPreviewApplyAndStalePlan(t *testing.T) {
	opts, _ := fixture(t)
	hash, original := seedTraffic(t, opts, true)
	r, err := Run(t.Context(), opts)
	if err != nil || r.Changes != 1 || r.Rows != 1 || r.Applied {
		t.Fatal(r, err)
	}
	b, _ := json.Marshal(r)
	if bytes.Contains(b, []byte(testSecret)) {
		t.Fatal("preview leaked")
	}
	d, err := sql.Open("sqlite", filepath.Join(opts.Data, "traffic", "_index", "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var body []byte
	if err = d.QueryRow(`SELECT resp_body FROM exchange_bodies`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(testSecret)) {
		t.Fatal("preview changed data")
	}
	if _, err = d.Exec(`UPDATE exchanges SET ts=2`); err != nil {
		t.Fatal(err)
	}
	opts.Apply = r.Fingerprint
	if _, err = Run(t.Context(), opts); err == nil {
		t.Fatal("stale plan applied")
	}
	opts.Apply = ""
	r, err = Run(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.Apply = r.Fingerprint

	r, err = Run(t.Context(), opts)
	if err != nil || !r.Applied {
		t.Fatal(r, err)
	}
	var head, rawURL string
	var blob sql.NullString
	if err = d.QueryRow(`SELECT resp_body,req_head,resp_blob FROM exchange_bodies`).Scan(&body, &head, &blob); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(body, original) || bytes.Contains(body, []byte(testSecret)) || strings.Contains(head, "unknown-header") || blob.Valid {
		t.Fatal("body/header not sanitized")
	}
	if !bytes.Contains(body, []byte("9007199254740993")) {
		t.Fatal("JSON number corrupted")
	}
	if err = d.QueryRow(`SELECT url FROM exchanges`).Scan(&rawURL); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rawURL, "unknown-query") {
		t.Fatal("URL not sanitized")
	}
	var hits int
	if err = d.QueryRow(`SELECT count(*) FROM ex_fts WHERE ex_fts MATCH '"synthetic-history-secret"'`).Scan(&hits); err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatal("FTS retained secret")
	}
	if _, err = os.Stat(filepath.Join(opts.Data, "traffic", "_blobs", "sha256", hash[:2], hash+".bin")); !os.IsNotExist(err) {
		t.Fatal("unreferenced old blob retained", err)
	}
	opts.Apply = ""
	again, err := Run(t.Context(), opts)
	if err != nil || again.Changes != 0 {
		t.Fatal("not idempotent", again, err)
	}
}

func TestHistoryTrafficRejectsMissingOrEscapingBody(t *testing.T) {
	opts, _ := fixture(t)
	hash, body := seedTraffic(t, opts, true)
	path := filepath.Join(opts.Data, "traffic", "_blobs", "sha256", hash[:2], hash+".bin")
	os.Remove(path)
	if _, err := Run(t.Context(), opts); err == nil {
		t.Fatal("missing blob accepted")
	}
	outside := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(outside, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(t.Context(), opts); err == nil {
		t.Fatal("escaping symlink accepted")
	}
}

func TestHistoryRuntimeGuardAndFingerprintSecrets(t *testing.T) {
	opts, _ := fixture(t)
	seedTraffic(t, opts, false)
	release, err := RuntimeGuard(t.Context(), opts.DSN)
	if err != nil {
		t.Fatal(err)
	}
	// Runtime maintenance protection must not deadlock normal startup work.
	check, err := sql.Open("pgx", opts.DSN)
	if err != nil {
		release()
		t.Fatal(err)
	}
	conn, err := check.Conn(t.Context())
	if err != nil {
		check.Close()
		release()
		t.Fatal(err)
	}
	for _, key := range []int64{7337741001, 7337741002, 7337741003, 7337741004, 7337741010, 722681, 722683} {
		var acquired bool
		if err = conn.QueryRowContext(t.Context(), `SELECT pg_try_advisory_lock($1)`, key).Scan(&acquired); err != nil || !acquired {
			conn.Close()
			check.Close()
			release()
			t.Fatal("maintenance conflicts with application lock", key, err)
		}
		conn.ExecContext(t.Context(), `SELECT pg_advisory_unlock($1)`, key)
	}
	conn.Close()
	check.Close()
	if _, err = Run(t.Context(), opts); err == nil {
		t.Fatal("maintenance raced live server")
	}
	release()
	r, err := Run(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.Secrets = append(opts.Secrets, "newly-configured-secret")
	opts.Apply = r.Fingerprint
	if _, err = Run(t.Context(), opts); err == nil {
		t.Fatal("changed credentials ignored")
	}
}

func TestHistoryEvidencePreservesHashesBindingsAndStalesReviews(t *testing.T) {
	opts, pg := fixture(t)
	opts.Scope = "evidence"
	root := filepath.Join(opts.Data, "evidence")
	req := []byte{}
	body := []byte(`{"password":"target-password","value":"` + testSecret + `"}`)
	v := db.TrafficEvidenceSnapshot{SourceTrafficID: "one", CapturedAt: 1, URL: "http://lab.test/?token=secret", Method: "GET", Status: 200, ContentType: "application/json", ReqHead: "GET /?token=secret HTTP/1.1\nCookie: session=target-cookie\n", RespHead: "HTTP 200\nContent-Type: application/json\n", ReqHash: bodyHash(req), RespHash: bodyHash(body), ReqLen: 0, RespLen: int64(len(body))}
	v.ID = db.TrafficSnapshotID(v)
	if err := writeBody(root, v.ReqHash, req); err != nil {
		t.Fatal(err)
	}
	if err := writeBody(root, v.RespHash, body); err != nil {
		t.Fatal(err)
	}
	_, err := pg.Exec(`INSERT INTO traffic_evidence_snapshots(id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, v.ID, v.SourceTrafficID, v.CapturedAt, v.URL, v.Method, v.Status, v.ContentType, v.ReqHead, v.RespHead, v.ReqHash, v.RespHash, v.ReqLen, v.RespLen)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err = pg.QueryRow(`INSERT INTO findings(summary,evidence,report,evidence_version,report_evidence_version,status) VALUES($1,$1,$1,4,4,'confirmed') RETURNING id`, testSecret).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position) VALUES($1,$2,'proof',$3,0)`, id, v.ID, testSecret); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`INSERT INTO finding_reviews(finding_id,fingerprint,verdict,sources) VALUES($1,'old-fingerprint','supported',$2)`, id, testSecret); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`INSERT INTO finding_retests(finding_id,notes,snapshot) VALUES($1,$2,$3::jsonb)`, id, testSecret, `{"evidence":"`+testSecret+`","number":9007199254740993}`); err != nil {
		t.Fatal(err)
	}
	r, err := Run(t.Context(), opts)
	if err != nil || r.Changes != 6 {
		t.Fatal(r, err)
	}
	var original string
	if err = pg.QueryRow(`SELECT summary FROM findings WHERE id=$1`, id).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if original != testSecret {
		t.Fatal("preview mutated findings")
	}
	opts.Apply = r.Fingerprint
	if _, err = pg.Exec(`CREATE FUNCTION deny_privacy_test_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$; CREATE TRIGGER deny_privacy_test_update BEFORE UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION deny_privacy_test_update()`); err != nil {
		t.Fatal(err)
	}
	if _, err = Run(t.Context(), opts); err == nil {
		t.Fatal("injected SQL failure ignored")
	}
	var retained string
	if err = pg.QueryRow(`SELECT snapshot_id FROM finding_traffic_bindings WHERE finding_id=$1`, id).Scan(&retained); err != nil || retained != v.ID {
		t.Fatal("failed transaction changed evidence", err)
	}
	if _, err = pg.Exec(`DROP TRIGGER deny_privacy_test_update ON findings; DROP FUNCTION deny_privacy_test_update()`); err != nil {
		t.Fatal(err)
	}
	r, err = Run(t.Context(), opts)
	if err != nil || !r.Applied {
		t.Fatal(r, err)
	}
	var version, report int
	var status, fingerprint string
	if err = pg.QueryRow(`SELECT evidence_version,report_evidence_version,status,summary FROM findings WHERE id=$1`, id).Scan(&version, &report, &status, &original); err != nil {
		t.Fatal(err)
	}
	if err = pg.QueryRow(`SELECT fingerprint FROM finding_reviews WHERE finding_id=$1`, id).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if version != 5 || report != 4 || status != "confirmed" || original == testSecret || fingerprint != "old-fingerprint" {
		t.Fatal("evidence/report state invalid", version, report, status)
	}
	var safe db.TrafficEvidenceSnapshot
	err = pg.QueryRow(`SELECT s.id,s.source_traffic_id,s.captured_at,s.url,s.method,s.status,s.content_type,s.req_head,s.resp_head,s.req_hash,s.resp_hash,s.req_len,s.resp_len FROM traffic_evidence_snapshots s JOIN finding_traffic_bindings b ON b.snapshot_id=s.id WHERE b.finding_id=$1`, id).Scan(&safe.ID, &safe.SourceTrafficID, &safe.CapturedAt, &safe.URL, &safe.Method, &safe.Status, &safe.ContentType, &safe.ReqHead, &safe.RespHead, &safe.ReqHash, &safe.RespHash, &safe.ReqLen, &safe.RespLen)
	if err != nil || safe.ID == v.ID || safe.ID != db.TrafficSnapshotID(safe) {
		t.Fatal("snapshot integrity", err)
	}
	clean, err := readBody(root, filepath.Join("blobs", safe.RespHash[:2], safe.RespHash+".bin"), safe.RespHash)
	if err != nil || bytes.Contains(clean, []byte(testSecret)) || bytes.Contains(clean, []byte("target-password")) {
		t.Fatal("evidence body not sanitized", err)
	}
	var leaks int
	if err = pg.QueryRow(`SELECT count(*) FROM finding_review_history WHERE result::text LIKE $1`, "%"+testSecret+"%").Scan(&leaks); err != nil {
		t.Fatal(err)
	}
	if leaks != 0 {
		t.Fatal("history retained secret")
	}
	opts.Apply = ""
	again, err := Run(t.Context(), opts)
	if err != nil || again.Changes != 0 {
		t.Fatal("not idempotent", again, err)
	}
}

func TestAuditDoesNotStoreRawData(t *testing.T) {
	dir := t.TempDir()
	r := Report{Scope: "traffic", Rows: 2, Changes: 1, Fingerprint: strings.Repeat("a", 64)}
	if err := Audit(dir, r, "complete"); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "privacy-audit", "*.json"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	info, _ := os.Stat(files[0])
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	var got struct {
		Report
		Status string
	}
	b, _ := os.ReadFile(files[0])
	if json.Unmarshal(b, &got) != nil || got.Status != "complete" {
		t.Fatal("audit invalid")
	}
}
