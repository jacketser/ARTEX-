package historyprivacy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/traffic"
)

const maxLegacyHead = 1 << 20

// Only the original recorder's entire-body pointer is interpreted as a blob.
// An inline body containing the same text is retained when its indexed length
// matches. Preview/truncation variants are rejected instead of guessed.
var legacyPointer = regexp.MustCompile(`^@blob sha256:([0-9a-f]{64}) \(len=([0-9]+)\)$`)

type legacyFile struct{ Name, Hash string }
type legacySource struct {
	Directory string
	Files     []legacyFile
}

// OpenRoot contains path traversal. Reject symlinks as well: otherwise two
// different lexical exchange paths could share files through an alias and
// post-commit cleanup could damage an exchange in a later batch.
func legacyRegular(root *os.Root, name string) (os.FileInfo, error) {
	if !filepath.IsLocal(name) || filepath.Clean(name) != name || name == "." || strings.HasPrefix(strings.Split(name, string(filepath.Separator))[0], "_") {
		return nil, errors.New("旧流量路径无效或指向保留目录")
	}
	parts := strings.Split(name, string(filepath.Separator))
	for i := range parts {
		st, err := root.Lstat(filepath.Join(parts[:i+1]...))
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("旧流量路径含符号链接")
		}
		if i < len(parts)-1 && !st.IsDir() {
			return nil, errors.New("旧流量父路径不是目录")
		}
		if i == len(parts)-1 {
			if !st.Mode().IsRegular() {
				return nil, errors.New("旧流量文件不是普通文件")
			}
			return st, nil
		}
	}
	return nil, errors.New("旧流量路径无效")
}

func legacyRead(root *os.Root, name string, limit int64) ([]byte, error) {
	st, err := legacyRegular(root, name)
	if err != nil {
		return nil, err
	}
	if st.Size() > limit {
		return nil, errors.New("旧流量文件超过维护上限")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("旧流量文件读取失败或超限")
	}
	return b, nil
}

func readTrafficBlob(root, hash string) ([]byte, error) {
	if !validHash(hash) {
		return nil, errors.New("流量正文哈希无效")
	}
	path := filepath.Join("_blobs", "sha256", hash[:2], hash+".bin")
	if _, err := os.Stat(filepath.Join(root, path)); os.IsNotExist(err) {
		path = filepath.Join("_blobs", "sha256", hash[:2], hash[2:4], hash+".bin")
	}
	return readBody(root, path, hash)
}

func splitLegacy(root string, raw []byte, expected int) (head string, body []byte, hash string, err error) {
	if expected < 0 || expected > maxBody {
		err = errors.New("旧流量正文长度超限")
		return
	}
	// Preserve binary bytes and CRLF inside the body; normalize only the header.
	pos, sep := bytes.Index(raw, []byte("\n\n")), 2
	if crlf := bytes.Index(raw, []byte("\r\n\r\n")); crlf >= 0 && (pos < 0 || crlf < pos) {
		pos, sep = crlf, 4
	}
	if pos < 0 {
		// Some historical zero-body exports omitted the final blank line.
		if expected != 0 || !bytes.HasSuffix(raw, []byte("\n")) {
			err = errors.New("旧流量缺少报文头分隔符")
			return
		}
		head = string(raw)
	} else {
		head = string(raw[:pos+sep/2])
		body = raw[pos+sep:]
	}
	if len(head) > maxLegacyHead {
		err = errors.New("旧流量报文头超限")
		return
	}
	head = strings.ReplaceAll(head, "\r\n", "\n")
	if len(body) == expected {
		return
	}
	match := legacyPointer.FindSubmatch(body)
	if match == nil {
		err = errors.New("旧流量正文长度不符或引用格式不支持")
		return
	}
	n, e := strconv.ParseInt(string(match[2]), 10, 64)
	if e != nil || n != int64(expected) {
		err = errors.New("旧流量引用长度不匹配")
		return
	}
	hash = string(match[1])
	body, err = readTrafficBlob(root, hash)
	if err == nil && len(body) != expected {
		err = errors.New("旧流量完整正文长度不匹配")
	}
	return
}

func loadLegacy(root, dir string, v *traffic.ArchiveExchange) (*legacySource, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// Validate the stored directory before Join can clean away a traversal.
	if !filepath.IsLocal(dir) || filepath.Clean(dir) != dir || dir == "." {
		return nil, errors.New("旧流量目录无效")
	}
	source := &legacySource{Directory: dir}
	for _, side := range []struct {
		name   string
		head   *string
		body   *[]byte
		hash   *string
		length int
	}{
		{"request.http", &v.ReqHead, &v.ReqBody, &v.ReqBlob, v.ReqLen},
		{"response.http", &v.RespHead, &v.RespBody, &v.RespBlob, v.RespLen},
	} {
		name := filepath.Join(dir, side.name)
		raw, e := legacyRead(r, name, maxBody+maxLegacyHead+4)
		if e != nil {
			return nil, errors.New("旧流量报文缺失、超限或路径无效")
		}
		source.Files = append(source.Files, legacyFile{name, bodyHash(raw)})
		*side.head, *side.body, *side.hash, err = splitLegacy(root, raw, side.length)
		if err != nil {
			return nil, err
		}
	}
	name := filepath.Join(dir, "meta.json")
	raw, err := legacyRead(r, name, maxLegacyHead)
	if os.IsNotExist(err) {
		return source, nil
	}
	if err != nil {
		return nil, errors.New("旧流量元数据不可读取")
	}
	var meta struct {
		ID, Host, Method, URL, Template string
		Status                          int
		ContentType                     string `json:"content_type"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&meta) != nil || meta.ID != v.ID || meta.Host != v.Host || meta.Method != v.Method || meta.URL != v.URL || meta.Template != v.URLTemplate || meta.Status != v.Status || meta.ContentType != v.ContentType {
		return nil, errors.New("旧流量元数据与索引不一致")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("旧流量元数据格式无效")
	}
	source.Files = append(source.Files, legacyFile{name, bodyHash(raw)})
	return source, nil
}

// Never remove a directory recursively. Only the exact fingerprinted recorder
// files are retired, after the SQLite transaction and last legacy path reference.
// An interruption after commit can leave unreferenced originals; the audit must
// then be reviewed along with the mandatory pre-maintenance backup.
func retireLegacy(ctx context.Context, d *sql.DB, root string, sources []*legacySource) error {
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	seen := map[string]bool{}
	for _, source := range sources {
		if seen[source.Directory] {
			continue
		}
		seen[source.Directory] = true
		var refs int
		if err = d.QueryRowContext(ctx, `SELECT count(*) FROM exchanges WHERE path=?`, source.Directory).Scan(&refs); err != nil {
			return err
		}
		if refs > 0 {
			continue
		}
		// Validate all files before deleting any, rather than trusting the old plan.
		for _, file := range source.Files {
			raw, e := legacyRead(r, file.Name, maxBody+maxLegacyHead+4)
			if e != nil || bodyHash(raw) != file.Hash {
				return errors.New("已提交迁移，但旧文件变化或无法清理")
			}
		}
		for _, file := range source.Files {
			if err = r.Remove(file.Name); err != nil {
				return err
			}
		}
		// Keep empty directories and any unrecognized files; they are not in the plan.
		dir, e := r.Open(source.Directory)
		if e != nil {
			return e
		}
		e = dir.Sync()
		dir.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
