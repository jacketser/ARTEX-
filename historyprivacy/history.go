// Package historyprivacy implements bounded offline redaction with a preview
// fingerprint. It deliberately never opens the normal migrating/seeded stores.
package historyprivacy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

const maxRows = 10000
const DefaultBatchSize = 1000

var errBatchFull = errors.New("batch full")

// continuation contains only numeric row keys or snapshot digests, never content.
// Snapshot IDs can change during redaction: keyset traversal may visit a newly
// sanitized snapshot again, but never skips an untouched original or uses OFFSET.
type continuation struct {
	Version int    `json:"v"`
	Scope   string `json:"scope"`
	Store   string `json:"store"`
	Phase   int    `json:"phase"`
	After   string `json:"after"`
}

func numericAfter(after string) int64 {
	n, _ := strconv.ParseInt(after, 10, 64)
	return n
}

func (p *plan) finish(more bool) error {
	p.report.More = more
	if more {
		b, err := json.Marshal(p.position)
		if err != nil {
			return err
		}
		p.next = base64.RawURLEncoding.EncodeToString(b)
	}
	b, err := json.Marshal([]any{"boundary", p.position, more})
	if err != nil {
		return err
	}
	fmt.Fprintf(p.hash, "%d:", len(b))
	_, err = p.hash.Write(b)
	return err
}

// ValidateBatch rejects malformed cursors before opening either store.
func ValidateBatch(scope string, size int, cursor string) error {
	if size < 0 || size > maxRows {
		return errors.New("batch-size 须为 1–10000（省略时为 1000）")
	}
	if cursor == "" {
		return nil
	}
	var c continuation
	if len(cursor) > 2048 {
		return errors.New("续跑游标过长")
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || json.Unmarshal(b, &c) != nil || c.Version != 2 || c.Scope != scope || !validHash(c.Store) || c.Phase < 0 || c.Phase > len(evidenceTextTables) {
		return errors.New("续跑游标无效或范围不匹配")
	}
	if scope == "traffic" && c.Phase != 0 {
		return errors.New("续跑游标无效")
	}
	if c.After != "" {
		if scope == "evidence" && c.Phase == 0 {
			if !validHash(c.After) {
				return errors.New("续跑快照游标无效")
			}
		} else {
			n, e := strconv.ParseInt(c.After, 10, 64)
			if e != nil || n <= 0 {
				return errors.New("续跑记录游标无效")
			}
		}
	}
	return nil
}

const maxBody = 16 << 20
const maxTotal = 128 << 20

// Reserved separately from schema/evidence/company locks and retest bootstrap
// (7337741010), which must remain usable while the application is running.
const maintenanceKey = 7337741099

type Report struct {
	Scope       string   `json:"scope"`
	Rows        int      `json:"rows"`
	Changes     int      `json:"changes"`
	Fingerprint string   `json:"fingerprint"`
	Applied     bool     `json:"applied"`
	BatchSize   int      `json:"batch_size"`
	Cursor      string   `json:"cursor,omitempty"`
	More        bool     `json:"more"`
	NextCursor  string   `json:"next_cursor,omitempty"`
	Limitations []string `json:"limitations"`
}

// RuntimeGuard is held for the whole normal server lifetime. Maintenance takes
// the exclusive form, so it cannot race this version of the application.
func RuntimeGuard(ctx context.Context, dsn string) (func(), error) {
	return guard(ctx, dsn, true)
}
func guard(ctx context.Context, dsn string, shared bool) (func(), error) {
	d, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, errors.New("维护锁连接失败")
	}
	c, err := d.Conn(ctx)
	if err != nil {
		d.Close()
		return nil, errors.New("维护锁连接失败")
	}
	query := "SELECT pg_try_advisory_lock($1)"
	unlock := "SELECT pg_advisory_unlock($1)"
	if shared {
		query = "SELECT pg_try_advisory_lock_shared($1)"
		unlock = "SELECT pg_advisory_unlock_shared($1)"
	}
	var ok bool
	if err = c.QueryRowContext(ctx, query, maintenanceKey).Scan(&ok); err != nil || !ok {
		c.Close()
		d.Close()
		return nil, errors.New("应用或维护命令正在运行，请先停机再重试")
	}
	return func() {
		end, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c.ExecContext(end, unlock, maintenanceKey)
		c.Close()
		d.Close()
	}, nil
}

type Options struct {
	DSN, Data, Scope, Apply string
	Secrets                 []string
	BatchSize               int
	Cursor                  string
}
type plan struct {
	report           Report
	hash             io.Writer
	used             int64
	secrets          []string
	cleanup          []func()
	obsoleteEvidence map[string]bool
	position         continuation
	next             string
}

func (p *plan) absorb(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if p.used+int64(len(b)) > maxTotal-4096 {
		if p.report.Rows > 0 {
			return errBatchFull
		}
		return errors.New("单条历史记录超过 128 MiB 维护上限")
	}
	p.used += int64(len(b))
	fmt.Fprintf(p.hash, "%d:", len(b))
	p.hash.Write(b)
	return nil
}

// Run takes an exclusive maintenance lease even for preview so both stores are
// stable. Preview opens SQLite read-only and PostgreSQL in a read-only snapshot.
// An apply request recomputes the entire plan before its first persistent write.
func Run(ctx context.Context, opts Options) (Report, error) {
	r := Report{Scope: opts.Scope, Limitations: []string{
		"仅覆盖选择的活动流量或证据存储；备份、冷归档、导出文件、日志、会话和资产元数据不处理",
		"识别已知凭据、私钥及结构化敏感字段，不保证识别自由文本中的未知密码或任意编码",
		"旧文件和数据库历史页不保证物理擦除；需另行管理备份与存储保留策略",
	}}
	if opts.Scope != "traffic" && opts.Scope != "evidence" {
		return r, errors.New("scope 须为 traffic 或 evidence")
	}
	if err := ValidateBatch(opts.Scope, opts.BatchSize, opts.Cursor); err != nil {
		return r, err
	}
	if opts.BatchSize == 0 {
		opts.BatchSize = DefaultBatchSize
	}
	r.BatchSize, r.Cursor = opts.BatchSize, opts.Cursor
	if opts.Apply != "" {
		if b, e := hex.DecodeString(opts.Apply); e != nil || len(b) != 32 {
			return r, errors.New("apply 须为预览指纹")
		}
	}
	release, err := guard(ctx, opts.DSN, false)
	if err != nil {
		return r, err
	}
	defer release()
	pg, err := sql.Open("pgx", opts.DSN)
	if err != nil {
		return r, errors.New("数据库连接失败")
	}
	defer pg.Close()
	tx, err := pg.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: opts.Apply == ""})
	if err != nil {
		return r, errors.New("无法建立维护快照")
	}
	defer tx.Rollback()
	keys, err := loadSecrets(ctx, tx, opts.Secrets)
	if err != nil {
		return r, errors.New("凭据来源不可用，未执行清理")
	}
	h := sha256.New()
	binding, _ := json.Marshal([]any{"history-redaction-v2", opts.DSN, filepath.Clean(opts.Data), keys})
	store := bodyHash(binding)
	position := continuation{Version: 2, Scope: opts.Scope, Store: store}
	if opts.Cursor != "" {
		b, _ := base64.RawURLEncoding.DecodeString(opts.Cursor)
		_ = json.Unmarshal(b, &position)
		if position.Store != store {
			return r, errors.New("数据源、凭据或脱敏规则已变化，请从头预览")
		}
	}
	p := &plan{report: r, hash: h, secrets: keys, position: position}
	defer func() {
		for i := len(p.cleanup) - 1; i >= 0; i-- {
			p.cleanup[i]()
		}
	}()
	if err = p.absorb([]any{"history-redaction-v2", opts.Scope, store, keys, opts.BatchSize, opts.Cursor}); err != nil {
		return r, err
	}
	var apply func() error
	if opts.Scope == "traffic" {
		apply, err = planTraffic(ctx, opts, p)
	} else {
		apply, err = planEvidence(ctx, tx, opts, p)
	}
	if err != nil {
		return r, err
	}
	p.report.Fingerprint = hex.EncodeToString(h.Sum(nil))
	if opts.Apply == "" {
		return p.report, nil
	}
	if opts.Apply != p.report.Fingerprint {
		return p.report, errors.New("数据或脱敏规则已变化，请重新预览")
	}
	if p.report.Changes > 0 {
		if err = apply(); err != nil {
			return p.report, errors.New("清理未完成，请检查审计状态并重新预览；不要删除备份")
		}
	}
	if opts.Scope == "evidence" {
		if err = tx.Commit(); err != nil {
			return p.report, errors.New("证据提交状态未知，请重新预览")
		}
		for hash := range p.obsoleteEvidence {
			var refs int
			if err = pg.QueryRowContext(ctx, `SELECT count(*) FROM traffic_evidence_snapshots WHERE req_hash=$1 OR resp_hash=$1`, hash).Scan(&refs); err != nil {
				return p.report, errors.New("证据已提交，旧正文回收未完成")
			}
			if refs > 0 {
				continue
			}
			root, e := os.OpenRoot(filepath.Join(opts.Data, "evidence"))
			if e != nil {
				return p.report, errors.New("证据已提交，旧正文回收未完成")
			}
			e = root.Remove(filepath.Join("blobs", hash[:2], hash+".bin"))
			root.Close()
			if e != nil && !os.IsNotExist(e) {
				return p.report, errors.New("证据已提交，旧正文回收未完成")
			}
		}
	}
	p.report.Applied = true
	p.report.NextCursor = p.next
	return p.report, nil
}

func loadSecrets(ctx context.Context, tx *sql.Tx, extra []string) ([]string, error) {
	keys := append([]string{}, extra...)
	rows, err := tx.QueryContext(ctx, `SELECT api_key FROM llm_profiles WHERE api_key IS NOT NULL UNION ALL SELECT value FROM settings WHERE key IN ('auth.password_hash','brave_search_api_key','tavily_search_api_key','global_proxy')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err = rows.Scan(&v); err != nil {
			return nil, err
		}
		keys = append(keys, v)
		if u, e := url.Parse(v); e == nil && u.User != nil {
			pw, _ := u.User.Password()
			keys = append(keys, pw)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, key := range keys {
		if len(key) >= 8 {
			set[key] = true
		}
	}
	keys = nil
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func readBody(root, relative string, expected string) ([]byte, error) {
	if !filepath.IsLocal(relative) {
		return nil, errors.New("历史正文路径无效")
	}
	// OpenRoot confines symlinks as well as lexical .. traversal to this store.
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("历史正文目录不可用")
	}
	defer r.Close()
	f, err := r.Open(relative)
	if err != nil {
		return nil, errors.New("历史正文缺失")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBody+1))
	if err != nil || len(b) > maxBody {
		return nil, errors.New("历史正文读取失败或超过 16 MiB")
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != expected {
		return nil, errors.New("历史正文哈希不匹配")
	}
	return b, nil
}
func validHash(h string) bool {
	b, e := hex.DecodeString(h)
	return e == nil && len(b) == 32 && strings.ToLower(h) == h
}
func bodyHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func same(a, b any) bool       { return reflect.DeepEqual(a, b) }

func writeBody(root, hash string, b []byte) error {
	if !validHash(hash) || bodyHash(b) != hash {
		return errors.New("脱敏正文校验失败")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	dir := filepath.Join("blobs", hash[:2])
	if err = r.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, hash+".bin")
	f, err := r.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		_, err = readBody(root, path, hash)
		return err
	}
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			r.Remove(path)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	d, err := r.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	err = d.Sync()
	ok = err == nil
	return err
}

// Reports are append-only, contain counts/digests only and never raw values.
func Audit(data string, r Report, status string) error {
	dir := filepath.Join(data, "privacy-audit")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, time.Now().UTC().Format("20060102T150405.000000000")+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = json.NewEncoder(f).Encode(struct {
		Report
		Status string `json:"status"`
	}{r, status}); err != nil {
		return err
	}
	return f.Sync()
}
