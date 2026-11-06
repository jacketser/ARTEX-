package historyprivacy

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"

	"github.com/Autumn-27/artex/traffic"
)

type trafficChange struct {
	old, safe traffic.ArchiveExchange
	rowid     int64
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
	var count, legacy, oversize int
	if err = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(CASE WHEN path<>'' THEN 1 ELSE 0 END),0) FROM exchanges`).Scan(&count, &legacy); err != nil {
		return nil, errors.New("历史流量结构不可用")
	}
	if count > maxRows {
		return nil, errors.New("历史流量超过 10000 条维护上限")
	}
	if legacy > 0 {
		return nil, errors.New("存在旧目录格式流量，请先迁移；本次未清理")
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM exchange_bodies WHERE length(req_body)>? OR length(resp_body)>? OR length(req_head)>1048576 OR length(resp_head)>1048576`, maxBody, maxBody).Scan(&oversize); err != nil || oversize > 0 {
		return nil, errors.New("历史流量字段超过维护上限或无法读取")
	}
	rows, err := tx.QueryContext(ctx, `SELECT e.rowid,e.id,e.ts,e.host,e.method,e.url_template,e.url,e.status,e.content_type,e.req_len,e.resp_len,b.req_head,b.req_body,coalesce(b.req_blob,''),b.resp_head,b.resp_body,coalesce(b.resp_blob,'') FROM exchanges e JOIN exchange_bodies b ON b.id=e.id ORDER BY e.id`)
	if err != nil {
		return nil, errors.New("无法读取历史流量正文")
	}
	all := []trafficChange{}
	for rows.Next() {
		var c trafficChange
		v := &c.old
		if err = rows.Scan(&c.rowid, &v.ID, &v.TS, &v.Host, &v.Method, &v.URLTemplate, &v.URL, &v.Status, &v.ContentType, &v.ReqLen, &v.RespLen, &v.ReqHead, &v.ReqBody, &v.ReqBlob, &v.RespHead, &v.RespBody, &v.RespBlob); err != nil {
			break
		}
		// Include previews as well as complete bodies in the preview fingerprint.
		if err = p.absorb(v); err != nil {
			break
		}
		for _, b := range []struct {
			hash string
			body *[]byte
		}{{v.ReqBlob, &v.ReqBody}, {v.RespBlob, &v.RespBody}} {
			if b.hash == "" {
				continue
			}
			if !validHash(b.hash) {
				err = errors.New("流量正文哈希无效")
				break
			}
			path := filepath.Join("_blobs", "sha256", b.hash[:2], b.hash+".bin")
			if _, e := os.Stat(filepath.Join(root, path)); os.IsNotExist(e) {
				path = filepath.Join("_blobs", "sha256", b.hash[:2], b.hash[2:4], b.hash+".bin")
			}
			*b.body, err = readBody(root, path, b.hash)
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
		if err = p.absorb(v); err != nil {
			break
		}
		c.safe, err = traffic.HistoricalExchange(*v, p.secrets)
		if err != nil {
			break
		}
		if !same(c.old, c.safe) {
			p.report.Changes++
		}
		all = append(all, c)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, errors.New("历史流量不完整、无效或超过维护上限，未清理")
	}
	if len(all) != count {
		return nil, errors.New("存在缺失正文的历史流量，未清理")
	}
	p.report.Rows = count
	return func() error {
		if _, err = tx.ExecContext(ctx, `PRAGMA secure_delete=ON`); err != nil {
			return err
		}
		var fts int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name='ex_fts'`).Scan(&fts); err != nil {
			return err
		}
		if fts > 0 {
			if _, err = tx.ExecContext(ctx, `INSERT INTO ex_fts(ex_fts) VALUES('delete-all')`); err != nil {
				return err
			}
		}
		oldBlobs := map[string]bool{}
		for _, c := range all {
			v := c.safe
			if !same(c.old, c.safe) {
				if _, err = tx.ExecContext(ctx, `UPDATE exchanges SET host=?,url_template=?,url=?,content_type=?,req_len=?,resp_len=? WHERE id=?`, v.Host, v.URLTemplate, v.URL, v.ContentType, v.ReqLen, v.RespLen, v.ID); err != nil {
					return err
				}
				// The bounded maintenance batch stores complete sanitized bodies inline.
				if _, err = tx.ExecContext(ctx, `UPDATE exchange_bodies SET req_head=?,req_body=?,req_blob=NULL,resp_head=?,resp_body=?,resp_blob=NULL WHERE id=?`, v.ReqHead, v.ReqBody, v.RespHead, v.RespBody, v.ID); err != nil {
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
				text := traffic.HistoricalIndex(v)
				if _, err = tx.ExecContext(ctx, `INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, c.rowid, text); err != nil {
					return err
				}
			}
		}
		if err = tx.Commit(); err != nil {
			return err
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
