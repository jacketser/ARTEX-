package historyprivacy

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Autumn-27/artex/traffic"
)

type trafficChange struct {
	old, safe traffic.ArchiveExchange
	rowid     int64
	legacy    *legacySource
}

func planTraffic(ctx context.Context, opts Options, p *plan) (func() error, error) {
	root := filepath.Join(opts.Data, "traffic")
	index := filepath.Join(root, "_index", "index.sqlite")
	if _, err := os.Stat(index); err != nil {
		return nil, errors.New("流量索引不存在或不可读取")
	}
	mode := "ro"
	if opts.Apply != "" {
		mode = "rw"
	}
	u := url.URL{Scheme: "file", Path: index}
	q := u.Query()
	q.Set("mode", mode)
	q.Set("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	d, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, errors.New("无法打开历史流量索引")
	}
	p.cleanup = append(p.cleanup, func() { d.Close() })
	d.SetMaxOpenConns(1)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.New("无法读取历史流量快照")
	}
	p.cleanup = append(p.cleanup, func() { tx.Rollback() })
	after := int64(0)
	if p.position.After != "" {
		after, _ = strconv.ParseInt(p.position.After, 10, 64)
	}
	// Inspect only the selected page. Missing bodies must fail, not disappear in a JOIN.
	var invalid int
	if err = tx.QueryRowContext(ctx, `WITH batch AS (SELECT rowid,id,path FROM exchanges WHERE rowid>? ORDER BY rowid LIMIT ?)
 SELECT count(*) FROM batch e LEFT JOIN exchange_bodies b ON b.id=e.id WHERE (e.path<>'' AND (?=0 OR b.id IS NOT NULL)) OR (e.path='' AND b.id IS NULL) OR length(b.req_body)>? OR length(b.resp_body)>? OR length(b.req_head)>1048576 OR length(b.resp_head)>1048576`, after, opts.BatchSize, opts.MigrateLegacy, maxBody, maxBody).Scan(&invalid); err != nil || invalid > 0 {
		return nil, errors.New("本批存在未启用迁移的旧格式、双份正文冲突、缺失正文或超限字段，未清理")
	}
	rows, err := tx.QueryContext(ctx, `SELECT e.rowid,e.id,e.ts,e.host,e.method,e.url_template,e.url,e.status,e.content_type,e.req_len,e.resp_len,coalesce(b.req_head,''),b.req_body,coalesce(b.req_blob,''),coalesce(b.resp_head,''),b.resp_body,coalesce(b.resp_blob,''),e.path FROM exchanges e LEFT JOIN exchange_bodies b ON b.id=e.id WHERE e.rowid>? ORDER BY e.rowid LIMIT ?`, after, opts.BatchSize)
	if err != nil {
		return nil, errors.New("无法读取历史流量正文")
	}
	all := []trafficChange{}
	more := false
	for rows.Next() {
		if p.report.Rows >= opts.BatchSize {
			more = true
			break
		}
		var c trafficChange
		v := &c.old
		var legacyDir string
		if err = rows.Scan(&c.rowid, &v.ID, &v.TS, &v.Host, &v.Method, &v.URLTemplate, &v.URL, &v.Status, &v.ContentType, &v.ReqLen, &v.RespLen, &v.ReqHead, &v.ReqBody, &v.ReqBlob, &v.RespHead, &v.RespBody, &v.RespBlob, &legacyDir); err != nil {
			break
		}
		// Include both stored previews and complete bodies atomically in the budget.
		stored := *v
		if legacyDir != "" {
			c.legacy, err = loadLegacy(root, legacyDir, v)
			if err != nil {
				break
			}
		}
		for _, b := range []struct {
			hash string
			body *[]byte
		}{{v.ReqBlob, &v.ReqBody}, {v.RespBlob, &v.RespBody}} {
			if b.hash == "" {
				continue
			}
			// loadLegacy already resolved and validated its complete bodies.
			if c.legacy != nil {
				continue
			}
			*b.body, err = readTrafficBlob(root, b.hash)
			if err != nil {
				break
			}
		}
		if err != nil {
			break
		}
		if len(v.ReqBody) != v.ReqLen || len(v.RespBody) != v.RespLen {
			err = errors.New("历史流量正文长度不匹配")
			break
		}
		if err = p.absorb([]any{c.rowid, stored, v, c.legacy}); err != nil {
			if errors.Is(err, errBatchFull) {
				more = true
				err = nil
			}
			break
		}
		c.safe, err = traffic.HistoricalExchange(*v, p.secrets)
		if err != nil {
			break
		}
		if c.legacy != nil || !same(c.old, c.safe) {
			p.report.Changes++
		}
		if c.legacy != nil {
			p.report.LegacyRows++
		}
		all = append(all, c)
		p.report.Rows++
		p.position.After = strconv.FormatInt(c.rowid, 10)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, errors.New("历史流量不完整、无效或超过维护上限，未清理")
	}
	if !more {
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exchanges WHERE rowid>?)`, p.position.After).Scan(&more); err != nil {
			return nil, errors.New("无法读取下一批流量边界")
		}
	}
	if err = p.finish(more); err != nil {
		return nil, err
	}
	return func() error {
		if _, err = tx.ExecContext(ctx, `PRAGMA secure_delete=ON`); err != nil {
			return err
		}
		var fts int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name='ex_fts'`).Scan(&fts); err != nil {
			return err
		}
		oldBlobs := map[string]bool{}
		oldSources := []*legacySource{}
		for _, c := range all {
			v := c.safe
			if c.legacy != nil || !same(c.old, c.safe) {
				if _, err = tx.ExecContext(ctx, `UPDATE exchanges SET host=?,url_template=?,url=?,content_type=?,req_len=?,resp_len=?,path='' WHERE id=?`, v.Host, v.URLTemplate, v.URL, v.ContentType, v.ReqLen, v.RespLen, v.ID); err != nil {
					return err
				}
				// The bounded maintenance batch stores complete sanitized bodies inline.
				if c.legacy != nil {
					_, err = tx.ExecContext(ctx, `INSERT INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body) VALUES(?,?,?,?,?)`, v.ID, v.ReqHead, v.ReqBody, v.RespHead, v.RespBody)
					oldSources = append(oldSources, c.legacy)
				} else {
					_, err = tx.ExecContext(ctx, `UPDATE exchange_bodies SET req_head=?,req_body=?,req_blob=NULL,resp_head=?,resp_body=?,resp_blob=NULL WHERE id=?`, v.ReqHead, v.ReqBody, v.RespHead, v.RespBody, v.ID)
				}
				if err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, `DELETE FROM blob_refs WHERE exchange_id=?`, v.ID); err != nil {
					return err
				}
				for _, h := range []string{c.old.ReqBlob, c.old.RespBlob} {
					if h != "" {
						oldBlobs[h] = true
					}
				}
			}
			if fts > 0 {
				if _, err = tx.ExecContext(ctx, `DELETE FROM ex_fts WHERE rowid=?`, c.rowid); err != nil {
					return err
				}
				text := traffic.HistoricalIndex(v)
				if _, err = tx.ExecContext(ctx, `INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, c.rowid, text); err != nil {
					return err
				}
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		if len(oldSources) > 0 {
			if err = retireLegacy(ctx, d, root, oldSources); err != nil {
				return err
			}
		}
		// Legacy pointer references are not in blob_refs. Keep candidates while any
		// legacy rows remain; regular store GC can reclaim deferred orphans later.
		var legacyRemaining int
		if err = d.QueryRowContext(ctx, `SELECT count(*) FROM exchanges WHERE path<>''`).Scan(&legacyRemaining); err != nil {
			return err
		}
		if legacyRemaining > 0 {
			return nil
		}
		// Remove only affected blobs with no live body or reference-table use.
		for h := range oldBlobs {
			var refs int
			if err = d.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM blob_refs WHERE hash=?)+(SELECT count(*) FROM exchange_bodies WHERE req_blob=? OR resp_blob=?)`, h, h, h).Scan(&refs); err != nil {
				return err
			}
			if refs > 0 {
				continue
			}
			r, e := os.OpenRoot(root)
			if e != nil {
				return e
			}
			for _, path := range []string{filepath.Join("_blobs", "sha256", h[:2], h+".bin"), filepath.Join("_blobs", "sha256", h[:2], h[2:4], h+".bin")} {
				e = r.Remove(path)
				if e != nil && !os.IsNotExist(e) {
					r.Close()
					return e
				}
			}
			r.Close()
		}
		return nil
	}, nil
}
