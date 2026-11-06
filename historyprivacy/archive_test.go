package historyprivacy

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	"github.com/klauspost/compress/zstd"
)

func archiveFile(name string, b []byte) archiveMember {
	return archiveMember{Header: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(b))}, Body: b}
}
func archiveFixture(t *testing.T) (Options, *db.DB, archiveCatalog, []archiveMember) {
	t.Helper()
	opts, pg := fixture(t)
	task, err := pg.CreateTask("privacy archive", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"token":"archive-token","number":9007199254740993}`)
	hash := bodyHash(body)
	snap := traffic.ArchiveSnapshot{Version: 1, Blobs: []string{hash}, Exchanges: []traffic.ArchiveExchange{{ID: "cold-one", TS: 17, Host: "fixture.test", Method: "GET", URL: "http://fixture.test/?token=old-query", URLTemplate: "/", Status: 200, ContentType: "application/json", ReqHead: "GET / HTTP/1.1\nAuthorization: Bearer old-header\n", RespHead: "HTTP 200\nContent-Type: application/json\n", RespBlob: hash, RespBody: []byte("old preview " + testSecret), RespLen: len(body)}}}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(fmt.Sprintf(`{"format_version":3,"task_id":%d,"data_counts":{"traffic":1},"tables":{"findings":[{"id":9007199254740993,"evidence":"untouched evidence"}]}}`, task.ID))
	members := []archiveMember{archiveFile("manifest.json", manifest), archiveFile("traffic/traffic.json", raw), archiveFile("traffic/blobs/"+hash+".bin", body), archiveFile("files/tasks/1/note.txt", []byte("untouched workspace")), archiveFile("evidence/blobs/independent.bin", body), archiveFile("database/llm_records.ndjson", []byte("{\"id\":9007199254740993}\n"))}
	path := filepath.Join(opts.Data, "archives", "tasks", "original.tar.zst")
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	packed, original, err := encodePrivacyArchive(members)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, packed, 0600); err != nil {
		t.Fatal(err)
	}
	c := archiveCatalog{TaskID: task.ID, Version: 3, Path: path, Hash: bodyHash(packed), Original: original, Compressed: int64(len(packed))}
	if err = pg.QueryRow(`INSERT INTO task_archives(task_id,state,format_version,archive_path,sha256,original_size,compressed_size) VALUES($1,'ready',3,$2,$3,$4,$5) RETURNING id`, task.ID, path, c.Hash, original, len(packed)).Scan(&c.ID); err != nil {
		t.Fatal(err)
	}
	opts.Scope, opts.ArchiveID = "archive-traffic", c.ID
	return opts, pg, c, members
}

func TestArchiveTrafficPublicationAndImport(t *testing.T) {
	opts, pg, c, members := archiveFixture(t)
	before, err := os.ReadFile(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := Run(t.Context(), opts)
	if err != nil || preview.Rows != 1 || preview.Changes != 1 || preview.ArchiveID != c.ID || preview.More || preview.Applied {
		t.Fatal(preview, err)
	}
	after, err := os.ReadFile(c.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preview changed original", err)
	}
	files, _ := os.ReadDir(filepath.Dir(c.Path))
	if len(files) != 1 {
		t.Fatal("preview wrote candidate")
	}
	opts.Apply = preview.Fingerprint
	done, err := Run(t.Context(), opts)
	if err != nil || !done.Applied || done.NextCursor != "" {
		t.Fatal(done, err)
	}
	var next archiveCatalog
	if err = pg.QueryRow(`SELECT archive_path,sha256,original_size,compressed_size FROM task_archives WHERE id=$1`, c.ID).Scan(&next.Path, &next.Hash, &next.Original, &next.Compressed); err != nil {
		t.Fatal(err)
	}
	if next.Path == c.Path || next.Hash == c.Hash {
		t.Fatal("catalog not replaced")
	}
	if _, err = os.Stat(c.Path); !os.IsNotExist(err) {
		t.Fatal("old original retained", err)
	}
	packed, err := os.ReadFile(next.Path)
	if err != nil || bodyHash(packed) != next.Hash || int64(len(packed)) != next.Compressed {
		t.Fatal("catalog checksum invalid", err)
	}
	decoded, size, err := decodePrivacyArchive(packed)
	if err != nil || size != next.Original {
		t.Fatal("rewritten package invalid", err)
	}
	restored := t.TempDir()
	for _, m := range decoded {
		if strings.HasPrefix(m.Header.Name, "traffic/blobs/") {
			t.Fatal("raw blob retained")
		}
		if !strings.HasPrefix(m.Header.Name, "traffic/") {
			matched := false
			for _, old := range members {
				if old.Header.Name == m.Header.Name {
					matched = true
					if !bytes.Equal(old.Body, m.Body) {
						t.Fatal("nontraffic data changed")
					}
				}
			}
			if !matched {
				t.Fatal("unexpected member")
			}
		}
		path := filepath.Join(restored, m.Header.Name)
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, m.Body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	tr, err := traffic.Open(filepath.Join(t.TempDir(), "traffic"), ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	n, err := tr.ImportArchive(filepath.Join(restored, "traffic"))
	if err != nil || n != 1 {
		t.Fatal("restore import failed", n, err)
	}
	req, resp, err := tr.Get("cold-one")
	if err != nil || strings.Contains(req, "old-header") || strings.Contains(req, "old-query") || strings.Contains(resp, "archive-token") || !strings.Contains(resp, "9007199254740993") {
		t.Fatal("restored traffic lost data or leaked", err)
	}
	opts.Apply = ""
	again, err := Run(t.Context(), opts)
	if err != nil || again.Changes != 0 {
		t.Fatal("not idempotent", again, err)
	}
	opts.Apply = again.Fingerprint
	if done, err = Run(t.Context(), opts); err != nil || !done.Applied {
		t.Fatal(done, err)
	}
	files, _ = os.ReadDir(filepath.Dir(c.Path))
	if len(files) != 1 {
		t.Fatal("no-op created extra package")
	}
}

func TestArchiveStalePreviewAndFailedCatalogCommitKeepOriginal(t *testing.T) {
	opts, pg, c, _ := archiveFixture(t)
	preview, err := Run(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.Apply = preview.Fingerprint
	original, _ := os.ReadFile(c.Path)
	if err = os.WriteFile(c.Path, append(original, 0), 0600); err != nil {
		t.Fatal(err)
	}
	if r, e := Run(t.Context(), opts); e == nil || r.Applied {
		t.Fatal("corruption accepted")
	}
	if err = os.WriteFile(c.Path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`UPDATE task_archives SET state='restore_queued' WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = Run(t.Context(), opts); err == nil {
		t.Fatal("active job accepted")
	}
	if _, err = pg.Exec(`UPDATE task_archives SET state='ready' WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`CREATE FUNCTION reject_privacy() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$ LANGUAGE plpgsql; CREATE TRIGGER reject_privacy BEFORE UPDATE ON task_archives FOR EACH ROW EXECUTE FUNCTION reject_privacy()`); err != nil {
		t.Fatal(err)
	}
	if r, e := Run(t.Context(), opts); e == nil || r.Applied {
		t.Fatal("failed transaction advanced")
	}
	got, err := os.ReadFile(c.Path)
	if err != nil || !bytes.Equal(original, got) {
		t.Fatal("failed commit removed original", err)
	}
	var path string
	if err = pg.QueryRow(`SELECT archive_path FROM task_archives WHERE id=$1`, c.ID).Scan(&path); err != nil || path != c.Path {
		t.Fatal("catalog changed", err)
	}
	if _, err = pg.Exec(`DROP TRIGGER reject_privacy ON task_archives`); err != nil {
		t.Fatal(err)
	}
	if r, e := Run(t.Context(), opts); e != nil || !r.Applied {
		t.Fatal("retry failed", r, e)
	}
}

func TestArchiveRejectsUnsafeTraffic(t *testing.T) {
	opts, pg, c, members := archiveFixture(t)
	for _, name := range []string{"missing-blob", "bad-hash", "length", "duplicate-id", "version", "unknown-field", "unknown-file", "manifest-id", "manifest-count", "old-http", "unlisted-blob", "oversized-body"} {
		t.Run(name, func(t *testing.T) {
			m := append([]archiveMember(nil), members...)
			var s traffic.ArchiveSnapshot
			if err := json.Unmarshal(m[1].Body, &s); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing-blob":
				m = append(m[:2], m[3:]...)
			case "bad-hash":
				m[2] = archiveFile(m[2].Header.Name, []byte("bad"))
			case "length":
				s.Exchanges[0].RespLen++
			case "duplicate-id":
				s.Exchanges = append(s.Exchanges, s.Exchanges[0])
				m[0] = archiveFile("manifest.json", bytes.ReplaceAll(m[0].Body, []byte(`"traffic":1`), []byte(`"traffic":2`)))
			case "version":
				s.Version = 2
			case "unknown-file":
				m = append(m, archiveFile("traffic/unknown.bin", []byte("secret")))
			case "manifest-id":
				m[0] = archiveFile("manifest.json", []byte(`{"format_version":3,"task_id":0}`))
			case "manifest-count":
				m[0] = archiveFile("manifest.json", bytes.ReplaceAll(m[0].Body, []byte(`"traffic":1`), []byte(`"traffic":2`)))
			case "old-http":
				s.Exchanges[0].ReqHead += "\nold body"
			case "unlisted-blob":
				s.Blobs = nil
			case "oversized-body":
				s.Exchanges[0].RespLen = maxBody + 1
			}
			raw, _ := json.Marshal(s)
			if name == "unknown-field" {
				raw = append([]byte(`{"future_secret":"value",`), raw[1:]...)
			}
			m[1] = archiveFile("traffic/traffic.json", raw)
			packed, size, err := encodePrivacyArchive(m)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(c.Path, packed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = pg.Exec(`UPDATE task_archives SET sha256=$1,original_size=$2,compressed_size=$3 WHERE id=$4`, bodyHash(packed), size, len(packed), c.ID); err != nil {
				t.Fatal(err)
			}
			if r, e := Run(t.Context(), opts); e == nil || r.Applied {
				t.Fatal("invalid archive accepted", r)
			}
		})
	}
}

func TestArchiveTarValidation(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "a/../alias", "a\\b", "duplicate", "symlink", "hardlink", "parent", "trailing", "count", "truncated", "window"} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			names := []string{name}
			kind := byte(tar.TypeReg)
			switch name {
			case "duplicate":
				names = []string{"a", "a"}
			case "parent":
				names = []string{"a/b", "a"}
			case "symlink":
				kind = tar.TypeSymlink
			case "hardlink":
				kind = tar.TypeLink
			case "count":
				names = nil
				for i := 0; i <= maxRows; i++ {
					names = append(names, fmt.Sprint(i))
				}
			}
			for _, n := range names {
				h := &tar.Header{Name: n, Typeflag: kind, Mode: 0600}
				if kind == tar.TypeSymlink || kind == tar.TypeLink {
					h.Linkname = "outside"
				}
				if e := tw.WriteHeader(h); e != nil {
					t.Fatal(e)
				}
			}
			if e := tw.Close(); e != nil {
				t.Fatal(e)
			}
			if name == "trailing" {
				buf.WriteString("hidden")
			}
			encoder, _ := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
			packed := encoder.EncodeAll(buf.Bytes(), nil)
			encoder.Close()
			if name == "truncated" {
				packed = packed[:len(packed)-2]
			}
			if name == "window" {
				packed = bytes.Repeat([]byte{0}, 128)
			}
			if _, _, e := decodePrivacyArchive(packed); e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestArchiveIDAndOptionValidation(t *testing.T) {
	for _, o := range []Options{{Scope: "archive-traffic"}, {Scope: "archive-traffic", ArchiveID: -1}, {Scope: "traffic", ArchiveID: 1}, {Scope: "archive-traffic", ArchiveID: 1, Cursor: "anything"}, {Scope: "archive-traffic", ArchiveID: 1, MigrateLegacy: true}} {
		if _, e := Run(t.Context(), o); e == nil {
			t.Fatal("unsafe option accepted")
		}
	}
	opts, pg, c, _ := archiveFixture(t)
	if _, e := pg.Exec(`UPDATE task_archives SET archive_path=$1 WHERE id=$2`, filepath.Join(t.TempDir(), "outside.tar.zst"), c.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := Run(t.Context(), opts); e == nil {
		t.Fatal("outside path accepted")
	}
	if _, e := pg.Exec(`UPDATE task_archives SET archive_path=$1 WHERE id=$2`, c.Path, c.ID); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(c.Path)
	if e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "outside.tar.zst")
	if e = os.WriteFile(outside, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(c.Path); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(outside, c.Path); e != nil {
		t.Fatal(e)
	}
	if _, e = Run(t.Context(), opts); e == nil {
		t.Fatal("symlink accepted")
	}
}

func TestArchiveFingerprintIncludesWholePackageAndEmptyVersions(t *testing.T) {
	opts, pg, c, members := archiveFixture(t)
	preview, e := Run(t.Context(), opts)
	if e != nil {
		t.Fatal(e)
	}
	members[3] = archiveFile(members[3].Header.Name, []byte("changed workspace"))
	packed, size, e := encodePrivacyArchive(members)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(c.Path, packed, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = pg.Exec(`UPDATE task_archives SET sha256=$1,original_size=$2,compressed_size=$3 WHERE id=$4`, bodyHash(packed), size, len(packed), c.ID); e != nil {
		t.Fatal(e)
	}
	opts.Apply = preview.Fingerprint
	if r, e := Run(t.Context(), opts); e == nil || r.Applied {
		t.Fatal("stale valid-package fingerprint accepted")
	}
	opts.Apply = ""
	for _, version := range []int{1, 2, 3} {
		m := []archiveMember{archiveFile("manifest.json", []byte(fmt.Sprintf(`{"format_version":%d,"task_id":%d,"data_counts":{}}`, version, c.TaskID)))}
		packed, size, e = encodePrivacyArchive(m)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(c.Path, packed, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = pg.Exec(`UPDATE task_archives SET format_version=$1,sha256=$2,original_size=$3,compressed_size=$4 WHERE id=$5`, version, bodyHash(packed), size, len(packed), c.ID); e != nil {
			t.Fatal(e)
		}
		r, e := Run(t.Context(), opts)
		if e != nil || r.Rows != 0 || r.Changes != 0 {
			t.Fatal("empty archive rejected", r, e)
		}
	}
}
