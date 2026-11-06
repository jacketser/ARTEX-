package historyprivacy

import (
	"archive/tar"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/traffic"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
)

// A compressed package is the unit of publication; active-store page cursors
// cannot be used to partially rewrite one package and its catalog checksum.
func ValidateArchiveOptions(scope string, id int64, cursor string, migrate bool) error {
	if scope != "traffic" && scope != "evidence" && scope != "archive-traffic" {
		return errors.New("scope 须为 traffic、evidence 或 archive-traffic")
	}
	if scope == "archive-traffic" {
		if id <= 0 || cursor != "" || migrate {
			return errors.New("archive-traffic 须指定正整数 archive-id，且不能使用游标或旧目录迁移")
		}
	} else if id != 0 {
		return errors.New("archive-id 仅用于 archive-traffic")
	}
	if migrate && scope != "traffic" {
		return errors.New("旧格式迁移仅用于 traffic 范围")
	}
	return nil
}

type archiveMember struct {
	Header tar.Header
	Body   []byte
}
type archiveCatalog struct {
	ID, TaskID           int64
	Version              int
	Path, Hash           string
	Original, Compressed int64
}

// Decode without extracting to disk. Both compressed and expanded bytes, entry
// count, decoder window and allocations are bounded independently.
func decodePrivacyArchive(raw []byte) ([]archiveMember, int64, error) {
	if len(raw) > maxTotal {
		return nil, 0, errors.New("归档压缩大小超过 128 MiB")
	}
	decoder, err := zstd.NewReader(bytes.NewReader(raw), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxTotal), zstd.WithDecoderMaxWindow(maxTotal))
	if err != nil {
		return nil, 0, err
	}
	expanded, err := io.ReadAll(io.LimitReader(decoder, maxTotal+1))
	decoder.Close()
	if err != nil || len(expanded) > maxTotal {
		return nil, 0, errors.New("归档解压失败或展开大小超过 128 MiB")
	}
	input := bytes.NewReader(expanded)
	tr := tar.NewReader(input)
	members := []archiveMember{}
	seen := map[string]byte{}
	var original int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		name := strings.TrimSuffix(h.Name, "/")
		if len(members) >= maxRows || !filepath.IsLocal(name) || path.Clean(name) != name || name == "." || strings.Contains(name, "\\") || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir) || h.Linkname != "" {
			return nil, 0, errors.New("归档路径、类型或成员数不受支持")
		}
		if _, exists := seen[name]; exists {
			return nil, 0, errors.New("归档含重复路径")
		}
		seen[name] = h.Typeflag
		if h.Typeflag == tar.TypeDir && h.Size != 0 {
			return nil, 0, errors.New("归档目录带正文")
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, 0, err
		}
		original += int64(len(body))
		members = append(members, archiveMember{Header: *h, Body: body})
	}
	// tar EOF may precede the end of a concatenated payload. Never silently drop it.
	tail, _ := io.ReadAll(input)
	if len(bytes.Trim(tail, "\x00")) != 0 {
		return nil, 0, errors.New("归档含尾随数据")
	}
	for name := range seen {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if kind, exists := seen[parent]; exists && kind != tar.TypeDir {
				return nil, 0, errors.New("归档父路径与文件冲突")
			}
		}
	}
	return members, original, nil
}

func strictArchiveJSON(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("归档 JSON 尾随数据")
	}
	return nil
}

func redactArchiveMembers(members []archiveMember, c archiveCatalog, p *plan) ([]archiveMember, error) {
	files := map[string][]byte{}
	for _, m := range members {
		if m.Header.Typeflag == tar.TypeReg {
			files[m.Header.Name] = m.Body
		}
	}
	// Keep manifest bytes verbatim, including arbitrary-precision numbers in tables.
	var manifest struct {
		Version int              `json:"format_version"`
		TaskID  int64            `json:"task_id"`
		Counts  map[string]int64 `json:"data_counts"`
	}
	if json.Unmarshal(files["manifest.json"], &manifest) != nil || manifest.TaskID != c.TaskID || manifest.Version != c.Version || c.Version < 1 || c.Version > 3 {
		return nil, errors.New("归档清单与目录不匹配或版本不受支持")
	}
	var snapshot traffic.ArchiveSnapshot
	raw, exists := files["traffic/traffic.json"]
	if exists {
		if strictArchiveJSON(raw, &snapshot) != nil || snapshot.Version != 1 || len(snapshot.Exchanges) > maxRows {
			return nil, errors.New("归档流量格式无效或超过 10000 条")
		}
	}
	if manifest.Counts["traffic"] != int64(len(snapshot.Exchanges)) {
		return nil, errors.New("归档流量计数不匹配")
	}
	blobs := map[string][]byte{}
	for _, hash := range snapshot.Blobs {
		b, ok := files["traffic/blobs/"+hash+".bin"]
		if !validHash(hash) || !ok || len(b) > maxBody || bodyHash(b) != hash {
			return nil, errors.New("归档流量正文缺失、超限或哈希不匹配")
		}
		if _, dup := blobs[hash]; dup {
			return nil, errors.New("归档重复正文引用")
		}
		blobs[hash] = b
	}
	for name := range files {
		if strings.HasPrefix(name, "traffic/") && name != "traffic/traffic.json" {
			hash := strings.TrimSuffix(strings.TrimPrefix(name, "traffic/blobs/"), ".bin")
			if _, ok := blobs[hash]; !ok || name != "traffic/blobs/"+hash+".bin" {
				return nil, errors.New("归档含未知流量文件")
			}
		}
	}
	ids, used := map[string]bool{}, map[string]bool{}
	var safeBudget, outputBudget int64
	for i, old := range snapshot.Exchanges {
		if old.ID == "" || ids[old.ID] {
			return nil, errors.New("归档流量 ID 为空或重复")
		}
		ids[old.ID] = true
		full := old
		for _, part := range []struct {
			hash   string
			body   *[]byte
			length int
			head   string
		}{
			{old.ReqBlob, &full.ReqBody, old.ReqLen, old.ReqHead}, {old.RespBlob, &full.RespBody, old.RespLen, old.RespHead},
		} {
			if len(part.head) > maxLegacyHead || part.length < 0 || part.length > maxBody {
				return nil, errors.New("归档报文超过维护上限")
			}
			// Old exporter placed the entire .http file into a header. Reject this
			// ambiguous format, including a body hidden after a blank header line.
			normalized := strings.ReplaceAll(part.head, "\r\n", "\n")
			if split := strings.Index(normalized, "\n\n"); split >= 0 && len(strings.TrimSpace(normalized[split+2:])) > 0 {
				return nil, errors.New("归档旧报文混合格式不受支持")
			}
			if part.hash != "" {
				b, ok := blobs[part.hash]
				if !ok {
					return nil, errors.New("归档正文引用未登记")
				}
				*part.body = b
				used[part.hash] = true
			}
			if len(*part.body) != part.length {
				return nil, errors.New("归档完整正文长度不匹配")
			}
		}
		// Shared blobs may expand into many inline copies. Bound the rewritten JSON
		// budget before allocating copies (base64 + worst-case JSON string escaping).
		safeBudget += int64((len(full.ReqBody)+len(full.RespBody))*2 + (len(full.ReqHead)+len(full.RespHead)+len(full.URL)+len(full.URLTemplate)+len(full.ID)+len(full.Method)+len(full.Host)+len(full.ContentType))*6 + 1024)
		if safeBudget > maxTotal {
			return nil, errors.New("归档流量展开计划超过 128 MiB")
		}
		safe, err := traffic.HistoricalExchange(full, p.secrets)
		if err != nil {
			return nil, errors.New("归档流量报文无法脱敏")
		}
		if len(safe.ReqBody) > maxBody || len(safe.RespBody) > maxBody || len(safe.ReqHead) > maxLegacyHead || len(safe.RespHead) > maxLegacyHead {
			return nil, errors.New("脱敏后报文超过维护上限")
		}
		safe.ReqBlob, safe.RespBlob = "", ""
		encoded, err := json.Marshal(safe)
		if err != nil {
			return nil, err
		}
		outputBudget += int64(len(encoded)) + 1
		if outputBudget > maxTotal-4096 {
			return nil, errors.New("脱敏后流量计划超过 128 MiB")
		}
		snapshot.Exchanges[i] = safe
		p.report.Rows++
		if !same(old, safe) {
			p.report.Changes++
		}
	}
	if len(used) != len(blobs) {
		return nil, errors.New("归档含未关联的流量正文")
	}
	if p.report.Changes == 0 {
		return members, nil
	}
	snapshot.Blobs = nil
	safeJSON, err := json.Marshal(snapshot)
	if err != nil || len(safeJSON) > maxTotal {
		return nil, errors.New("脱敏后归档流量超过维护上限")
	}
	result := []archiveMember{}
	for _, m := range members {
		name := strings.TrimSuffix(m.Header.Name, "/")
		if strings.HasPrefix(name, "traffic/blobs/") || name == "traffic/blobs" {
			continue
		}
		if name == "traffic/traffic.json" {
			m.Body = safeJSON
			// Traffic headers are regenerated: old PAX metadata must not retain content
			// or override the new body size. All nontraffic headers remain intact.
			m.Header = tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(safeJSON)), ModTime: m.Header.ModTime}
		}
		result = append(result, m)
	}
	return result, nil
}

// Re-encode with a bounded tar buffer so compression cannot conceal expansion.
func encodePrivacyArchive(members []archiveMember) ([]byte, int64, error) {
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	var original int64
	for _, m := range members {
		if int64(plain.Len())+int64(len(m.Body))+4096 > maxTotal {
			return nil, 0, errors.New("重写归档超过 128 MiB")
		}
		if err := tw.WriteHeader(&m.Header); err != nil {
			return nil, 0, err
		}
		if _, err := tw.Write(m.Body); err != nil {
			return nil, 0, err
		}
		original += int64(len(m.Body))
		if plain.Len() > maxTotal {
			return nil, 0, errors.New("重写归档超过 128 MiB")
		}
	}
	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	if plain.Len() > maxTotal {
		return nil, 0, errors.New("重写归档超过 128 MiB")
	}
	var packed bytes.Buffer
	zw, err := zstd.NewWriter(&packed, zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true))
	if err != nil {
		return nil, 0, err
	}
	if _, err = zw.Write(plain.Bytes()); err != nil {
		zw.Close()
		return nil, 0, err
	}
	if err = zw.Close(); err != nil {
		return nil, 0, err
	}
	if packed.Len() > maxTotal {
		return nil, 0, errors.New("重写压缩归档超过 128 MiB")
	}
	return packed.Bytes(), original, nil
}

func planArchiveTraffic(ctx context.Context, pg *sql.DB, tx *sql.Tx, opts Options, p *plan) (func() error, error) {
	c := archiveCatalog{ID: opts.ArchiveID}
	var state string
	err := tx.QueryRowContext(ctx, `SELECT task_id,state,format_version,archive_path,sha256,original_size,compressed_size FROM task_archives WHERE id=$1`, c.ID).Scan(&c.TaskID, &state, &c.Version, &c.Path, &c.Hash, &c.Original, &c.Compressed)
	if err != nil || state != "ready" || !validHash(c.Hash) {
		return nil, errors.New("归档不存在、未就绪或校验值无效")
	}
	rootPath, err := filepath.Abs(filepath.Join(opts.Data, "archives", "tasks"))
	if err != nil {
		return nil, err
	}
	// Current archive writers use absolute root-level paths. Reject aliases and
	// subdirectories, including worker staging journals and symbolic links.
	if !filepath.IsAbs(c.Path) || filepath.Clean(c.Path) != c.Path || filepath.Dir(c.Path) != rootPath || !strings.HasSuffix(c.Path, ".tar.zst") {
		return nil, errors.New("归档路径不受支持")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, errors.New("归档目录不可读取")
	}
	p.cleanup = append(p.cleanup, func() { root.Close() })
	name := filepath.Base(c.Path)
	raw, err := legacyRead(root, name, maxTotal)
	if err != nil || int64(len(raw)) != c.Compressed || bodyHash(raw) != c.Hash {
		return nil, errors.New("归档包大小或哈希校验失败")
	}
	members, original, err := decodePrivacyArchive(raw)
	if err != nil {
		return nil, errors.New("归档包损坏、不受支持或超过维护上限")
	}
	if original != c.Original {
		return nil, errors.New("归档展开大小与目录不匹配")
	}
	if err = p.absorb([]any{"archive-traffic-v1", c}); err != nil {
		return nil, err
	}
	safe, err := redactArchiveMembers(members, c, p)
	if err != nil {
		return nil, err
	}
	if err = p.finish(false); err != nil {
		return nil, err
	}
	// Preview also verifies output encodability/limits. It creates no files.
	if p.report.Changes == 0 {
		return func() error { return nil }, nil
	}
	packed, newOriginal, err := encodePrivacyArchive(safe)
	if err != nil {
		return nil, err
	}
	newHash := bodyHash(packed)
	return func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Refuse file changes after planning, before publication.
		current, err := legacyRead(root, name, maxTotal)
		if err != nil || bodyHash(current) != c.Hash {
			return errors.New("原归档已变化")
		}
		candidate := fmt.Sprintf("privacy-%d-%s.tar.zst", c.ID, uuid.NewString())
		f, err := root.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		// Never remove an uncertain candidate: a commit may have succeeded even when
		// its response was lost. Such leftovers are documented for manual inspection.
		_, writeErr := f.Write(packed)
		syncErr := f.Sync()
		if err = errors.Join(writeErr, syncErr, f.Close()); err != nil {
			return err
		}
		directory, err := root.Open(".")
		if err != nil {
			return err
		}
		defer directory.Close()
		if err = directory.Sync(); err != nil {
			return err
		}
		check, err := legacyRead(root, candidate, maxTotal)
		if err != nil || bodyHash(check) != newHash {
			return errors.New("新归档校验失败")
		}
		if _, _, err = decodePrivacyArchive(check); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE task_archives SET archive_path=$1,sha256=$2,original_size=$3,compressed_size=$4 WHERE id=$5 AND state='ready' AND archive_path=$6 AND sha256=$7`, filepath.Join(rootPath, candidate), newHash, newOriginal, len(packed), c.ID, c.Path, c.Hash)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return errors.New("归档目录已变化")
		}
		if err = tx.Commit(); err != nil {
			return errors.New("归档提交状态未知，保留新旧包并重新预览")
		}
		var refs int
		if err = pg.QueryRowContext(ctx, `SELECT count(*) FROM task_archives WHERE archive_path=$1`, c.Path).Scan(&refs); err != nil {
			return err
		}
		if refs > 0 {
			return nil
		}
		current, err = legacyRead(root, name, maxTotal)
		if err != nil || bodyHash(current) != c.Hash {
			return errors.New("目录已提交，旧包已变化或回收未完成")
		}
		if err = root.Remove(name); err != nil {
			return err
		}
		return directory.Sync()
	}, nil
}
