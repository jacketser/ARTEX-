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

	"github.com/Autumn-27/artex/traffic"
)

func seedLegacy(t *testing.T, opts Options, d *sql.DB, id string, body []byte, blob bool) (string, string) {
	t.Helper()
	rel := filepath.Join("legacy.test", "GET", id)
	dir := filepath.Join(opts.Data, "traffic", rel)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	stored, hash := body, ""
	if blob {
		hash = bodyHash(body)
		path := filepath.Join(opts.Data, "traffic", "_blobs", "sha256", hash[:2], hash[2:4], hash+".bin")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		stored = []byte(fmt.Sprintf("@blob sha256:%s (len=%d)", hash, len(body)))
	}
	req := []byte("GET /?token=old-query HTTP/1.1\nHost: legacy.test\nCookie: session=old-cookie\n\n")
	resp := append([]byte("HTTP 200\nContent-Type: application/json\n\n"), stored...)
	meta, err := json.Marshal(map[string]any{"id": id, "host": "legacy.test", "method": "GET", "url": "http://legacy.test/?token=old-query", "template": "/", "status": 200, "content_type": "application/json"})
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"request.http": req, "response.http": resp, "meta.json": meta, "notes.txt": []byte("user-owned file")} {
		if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = d.Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES(?,17,'legacy.test','GET','/','http://legacy.test/?token=old-query',200,'application/json',0,?,?)`, id, len(body), rel); err != nil {
		t.Fatal(err)
	}
	return dir, hash
}

func emptyLegacyStore(t *testing.T) (Options, *sql.DB) {
	opts, _ := fixture(t)
	tr, err := traffic.Open(filepath.Join(opts.Data, "traffic"), ":0")
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.Close(); err != nil {
		t.Fatal(err)
	}
	opts.MigrateLegacy = true
	return opts, trafficDB(t, opts)
}

func TestHistoryLegacyMixedBatchesAndSharedBlob(t *testing.T) {
	opts, _ := fixture(t)
	hash, body := seedTraffic(t, opts, true)
	d := trafficDB(t, opts)
	first, _ := seedLegacy(t, opts, d, "legacy-one", body, true)
	last, _ := seedLegacy(t, opts, d, "legacy-two", body, true)
	if _, e := Run(t.Context(), opts); e == nil {
		t.Fatal("implicit migration accepted")
	}
	opts.MigrateLegacy = true
	opts.BatchSize = 1
	// The modern first row shares a blob with legacy rows not in blob_refs.
	r := applyBatch(t, opts)
	if r.LegacyRows != 0 || !r.More {
		t.Fatal(r)
	}
	for _, path := range []string{filepath.Join(hash[:2], hash+".bin"), filepath.Join(hash[:2], hash[2:4], hash+".bin")} {
		if _, e := os.Stat(filepath.Join(opts.Data, "traffic", "_blobs", "sha256", path)); e != nil {
			t.Fatal("legacy blob deleted by modern batch", e)
		}
	}
	opts.Cursor = r.NextCursor
	disabled := opts
	disabled.MigrateLegacy = false
	if _, e := Run(t.Context(), disabled); e == nil {
		t.Fatal("cursor accepted changed migration mode")
	}
	r = applyBatch(t, opts)
	if r.LegacyRows != 1 || r.Changes != 1 || !r.More {
		t.Fatal(r)
	}
	for _, name := range []string{"request.http", "response.http", "meta.json"} {
		if _, e := os.Stat(filepath.Join(first, name)); !os.IsNotExist(e) {
			t.Fatal("migrated file retained", name, e)
		}
		if _, e := os.Stat(filepath.Join(last, name)); e != nil {
			t.Fatal("next batch file removed", name, e)
		}
	}
	if _, e := os.Stat(filepath.Join(first, "notes.txt")); e != nil {
		t.Fatal("user file removed", e)
	}
	opts.Cursor = r.NextCursor
	r = applyBatch(t, opts)
	if r.LegacyRows != 1 || r.More {
		t.Fatal(r)
	}
	var remaining int
	if e := d.QueryRow(`SELECT count(*) FROM exchanges WHERE path<>''`).Scan(&remaining); e != nil || remaining != 0 {
		t.Fatal(remaining, e)
	}
	for _, path := range []string{filepath.Join(hash[:2], hash+".bin"), filepath.Join(hash[:2], hash[2:4], hash+".bin")} {
		if _, e := os.Stat(filepath.Join(opts.Data, "traffic", "_blobs", "sha256", path)); !os.IsNotExist(e) {
			t.Fatal("last legacy blob retained", e)
		}
	}
	var head, rawURL string
	var safe []byte
	var ts int64
	if e := d.QueryRow(`SELECT b.req_head,b.resp_body,e.url,e.ts FROM exchange_bodies b JOIN exchanges e ON e.id=b.id WHERE e.id='legacy-two'`).Scan(&head, &safe, &rawURL, &ts); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(head, "old-cookie") || strings.Contains(rawURL, "old-query") || bytes.Contains(safe, []byte(testSecret)) || ts != 17 || !bytes.Contains(safe, []byte("9007199254740993")) {
		t.Fatal("migration corrupted/redaction missed data")
	}
	if e := d.QueryRow(`SELECT count(*) FROM ex_fts WHERE ex_fts MATCH '9007199254740993'`).Scan(&remaining); e != nil || remaining != 3 {
		t.Fatal("migrated search unavailable", remaining, e)
	}
	// Database-backed consumers can still read and archive the migrated exchange.
	tr, e := traffic.Open(filepath.Join(opts.Data, "traffic"), ":0")
	if e != nil {
		t.Fatal(e)
	}
	if _, resp, e := tr.Get("legacy-two"); e != nil || !strings.Contains(resp, "9007199254740993") {
		t.Fatal("Get failed", e)
	}
	n, e := tr.ExportHosts([]string{"legacy.test"}, t.TempDir())
	if e != nil || n != 2 {
		t.Fatal("archive failed", n, e)
	}
	tr.Close()
	opts.Cursor = ""
	opts.BatchSize = 100
	again := applyBatch(t, opts)
	if again.LegacyRows != 0 || again.Changes != 0 {
		t.Fatal(again)
	}
}

func TestHistoryLegacyPreviewFingerprintAndRollback(t *testing.T) {
	opts, d := emptyLegacyStore(t)
	dir, _ := seedLegacy(t, opts, d, "inline", []byte(`{"token":"legacy-value","n":9007199254740993}`), false)
	preview, e := Run(t.Context(), opts)
	if e != nil || preview.LegacyRows != 1 || preview.Changes != 1 {
		t.Fatal(preview, e)
	}
	if files, _ := filepath.Glob(filepath.Join(opts.Data, "privacy-audit", "*.json")); len(files) != 0 {
		t.Fatal("preview wrote audit")
	}
	var count int
	if e = d.QueryRow(`SELECT count(*) FROM exchange_bodies`).Scan(&count); e != nil || count != 0 {
		t.Fatal("preview wrote body", count, e)
	}
	reqPath := filepath.Join(dir, "request.http")
	original, e := os.ReadFile(reqPath)
	if e != nil {
		t.Fatal(e)
	}
	changed := bytes.Replace(original, []byte("old-cookie"), []byte("new-cookie"), 1)
	if e = os.WriteFile(reqPath, changed, 0600); e != nil {
		t.Fatal(e)
	}
	opts.Apply = preview.Fingerprint
	if r, e := Run(t.Context(), opts); e == nil || r.Applied || r.NextCursor != "" {
		t.Fatal("stale file preview applied", r, e)
	}
	if e = os.WriteFile(reqPath, original, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Exec(`CREATE TRIGGER deny_legacy BEFORE INSERT ON exchange_bodies BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if r, e := Run(t.Context(), opts); e == nil || r.Applied {
		t.Fatal("failed migration advanced", r, e)
	}
	if e = d.QueryRow(`SELECT count(*) FROM exchanges WHERE path<>''`).Scan(&count); e != nil || count != 1 {
		t.Fatal("failed migration cleared path", count, e)
	}
	if _, e = os.Stat(reqPath); e != nil {
		t.Fatal("failed transaction deleted original", e)
	}
	if _, e = d.Exec(`DROP TRIGGER deny_legacy`); e != nil {
		t.Fatal(e)
	}
	done, e := Run(t.Context(), opts)
	if e != nil || !done.Applied || done.LegacyRows != 1 {
		t.Fatal(done, e)
	}
}

func TestHistoryLegacyRejectsUnsafeOrAmbiguousSources(t *testing.T) {
	opts, d := emptyLegacyStore(t)
	body := []byte(`{"token":"legacy-secret"}`)
	dir, hash := seedLegacy(t, opts, d, "invalid", body, true)
	reqPath := filepath.Join(dir, "request.http")
	req, e := os.ReadFile(reqPath)
	if e != nil {
		t.Fatal(e)
	}
	metaPath := filepath.Join(dir, "meta.json")
	meta, e := os.ReadFile(metaPath)
	if e != nil {
		t.Fatal(e)
	}
	reject := func() {
		t.Helper()
		if r, e := Run(t.Context(), opts); e == nil || r.NextCursor != "" {
			t.Fatal("unsafe legacy accepted", r, e)
		}
	}
	os.Remove(reqPath)
	reject()
	outside := filepath.Join(t.TempDir(), "request.http")
	os.WriteFile(outside, req, 0600)
	os.Symlink(outside, reqPath)
	reject()
	os.Remove(reqPath)
	os.WriteFile(reqPath, req, 0600)
	// Even an in-root symlink is forbidden to avoid aliasing another row's files.
	os.WriteFile(filepath.Join(dir, "other.http"), req, 0600)
	os.Remove(reqPath)
	os.Symlink("other.http", reqPath)
	reject()
	os.Remove(reqPath)
	os.WriteFile(reqPath, req, 0600)
	if _, e = d.Exec(`UPDATE exchanges SET path='../escape'`); e != nil {
		t.Fatal(e)
	}
	reject()
	if _, e = d.Exec(`UPDATE exchanges SET path='_index'`); e != nil {
		t.Fatal(e)
	}
	reject()
	rel, e := filepath.Rel(filepath.Join(opts.Data, "traffic"), dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.Exec(`UPDATE exchanges SET path=?`, rel); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(opts.Data, "traffic", "alias")
	if e = os.Symlink(dir, alias); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Exec(`UPDATE exchanges SET path='alias'`); e != nil {
		t.Fatal(e)
	}
	reject()
	if _, e = d.Exec(`UPDATE exchanges SET path=?`, rel); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(metaPath, []byte(`{"id":"different"}`), 0600)
	reject()
	os.WriteFile(metaPath, meta, 0600)
	blobPath := filepath.Join(opts.Data, "traffic", "_blobs", "sha256", hash[:2], hash[2:4], hash+".bin")
	os.WriteFile(blobPath, []byte("corrupt"), 0600)
	reject()
	os.WriteFile(blobPath, body, 0600)
	if _, e = d.Exec(`UPDATE exchanges SET resp_len=resp_len+1`); e != nil {
		t.Fatal(e)
	}
	reject()
	if _, e = d.Exec(`UPDATE exchanges SET resp_len=resp_len-1`); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Exec(`INSERT INTO exchange_bodies(id) VALUES('invalid')`); e != nil {
		t.Fatal(e)
	}
	reject()
	if _, e = d.Exec(`DELETE FROM exchange_bodies WHERE id='invalid'`); e != nil {
		t.Fatal(e)
	}
	// Optional metadata may be absent; both HTTP files remain mandatory.
	os.Remove(metaPath)
	r, e := Run(t.Context(), opts)
	if e != nil || r.LegacyRows != 1 {
		t.Fatal(r, e)
	}
}

func TestHistoryLegacyFramingPreservesBytesAndLiteralPointer(t *testing.T) {
	for _, body := range [][]byte{[]byte("binary\x00\r\n\xff"), []byte("@blob sha256:" + strings.Repeat("a", 64) + " (len=9999)"), nil} {
		raw := append([]byte("HTTP 200\r\nContent-Type: application/octet-stream\r\n\r\n"), body...)
		head, got, hash, e := splitLegacy(t.TempDir(), raw, len(body))
		if e != nil || !bytes.Equal(body, got) || hash != "" || strings.Contains(head, "\r") {
			t.Fatal("raw body changed", e)
		}
	}
	if _, _, _, e := splitLegacy(t.TempDir(), []byte("HTTP 200\n"), 0); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e := splitLegacy(t.TempDir(), []byte("HTTP 200\n"), 1); e == nil {
		t.Fatal("missing nonempty body accepted")
	}
	if _, _, _, e := splitLegacy(t.TempDir(), []byte("HTTP 200\n\n…[truncated] @blob sha256:"+strings.Repeat("a", 64)), 200); e == nil {
		t.Fatal("unproven truncated variant accepted")
	}
}

func TestHistoryLegacyRetirementChecksReferencesAndFiles(t *testing.T) {
	opts, d := emptyLegacyStore(t)
	body := []byte(`{"token":"value"}`)
	dir, _ := seedLegacy(t, opts, d, "cleanup", body, false)
	rel, _ := filepath.Rel(filepath.Join(opts.Data, "traffic"), dir)
	v := traffic.ArchiveExchange{ID: "cleanup", Host: "legacy.test", Method: "GET", URL: "http://legacy.test/?token=old-query", URLTemplate: "/", Status: 200, ContentType: "application/json", RespLen: len(body)}
	source, e := loadLegacy(filepath.Join(opts.Data, "traffic"), rel, &v)
	if e != nil {
		t.Fatal(e)
	}
	if e = retireLegacy(t.Context(), d, filepath.Join(opts.Data, "traffic"), []*legacySource{source}); e != nil {
		t.Fatal(e)
	}
	req := filepath.Join(dir, "request.http")
	if _, e = os.Stat(req); e != nil {
		t.Fatal("referenced source removed", e)
	}
	if _, e = d.Exec(`UPDATE exchanges SET path='' WHERE id='cleanup'`); e != nil {
		t.Fatal(e)
	}
	resp := filepath.Join(dir, "response.http")
	original, e := os.ReadFile(resp)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(resp, []byte("changed after commit"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = retireLegacy(t.Context(), d, filepath.Join(opts.Data, "traffic"), []*legacySource{source}); e == nil {
		t.Fatal("modified original deleted")
	}
	if _, e = os.Stat(req); e != nil {
		t.Fatal("partial delete before validation", e)
	}
	if e = os.WriteFile(resp, original, 0600); e != nil {
		t.Fatal(e)
	}
	if e = retireLegacy(t.Context(), d, filepath.Join(opts.Data, "traffic"), []*legacySource{source}); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "notes.txt")); e != nil {
		t.Fatal("unknown file removed", e)
	}
}
