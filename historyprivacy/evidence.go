package historyprivacy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

type snapshotChange struct {
	old, safe db.TrafficEvidenceSnapshot
	req, resp []byte
}
type textSpec struct {
	table, key, owner string
	fields            []string
	jsonFields        map[string]bool
}
type textChange struct {
	spec      textSpec
	id, owner int64
	values    map[string]string
}

var evidenceTextTables = []textSpec{
	{"findings", "id", "id", []string{"name", "summary", "evidence", "report"}, nil},
	{"finding_retests", "id", "finding_id", []string{"notes", "snapshot", "summary", "evidence", "error"}, map[string]bool{"snapshot": true}},
	{"finding_reviews", "finding_id", "finding_id", []string{"sources", "reproduction", "counter_evidence", "limitations"}, nil},
	{"finding_review_history", "id", "finding_id", []string{"result"}, map[string]bool{"result": true}},
	{"finding_traffic_bindings", "id", "finding_id", []string{"note"}, nil},
}

func planEvidence(ctx context.Context, tx *sql.Tx, opts Options, p *plan) (func() error, error) {
	root := filepath.Join(opts.Data, "evidence")
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM traffic_evidence_snapshots`).Scan(&count); err != nil {
		return nil, errors.New("证据结构不可用")
	}
	if count > maxRows {
		return nil, errors.New("证据快照超过维护上限")
	}
	var oversize int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM traffic_evidence_snapshots s WHERE octet_length(to_jsonb(s)::text)>$1`, maxBody).Scan(&oversize); err != nil || oversize > 0 {
		return nil, errors.New("证据元数据超过维护上限或无法读取")
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len,created_at FROM traffic_evidence_snapshots ORDER BY id`)
	if err != nil {
		return nil, errors.New("无法读取证据快照")
	}
	changes := []snapshotChange{}
	for rows.Next() {
		var v db.TrafficEvidenceSnapshot
		if err = rows.Scan(&v.ID, &v.SourceTrafficID, &v.CapturedAt, &v.URL, &v.Method, &v.Status, &v.ContentType, &v.ReqHead, &v.RespHead, &v.ReqHash, &v.RespHash, &v.ReqLen, &v.RespLen, &v.CreatedAt); err != nil {
			break
		}
		if !validHash(v.ReqHash) || !validHash(v.RespHash) || db.TrafficSnapshotID(v) != v.ID {
			err = errors.New("证据快照指纹无效")
			break
		}
		var req, resp []byte
		req, err = readBody(root, filepath.Join("blobs", v.ReqHash[:2], v.ReqHash+".bin"), v.ReqHash)
		if err != nil {
			break
		}
		resp, err = readBody(root, filepath.Join("blobs", v.RespHash[:2], v.RespHash+".bin"), v.RespHash)
		if err != nil {
			break
		}
		if int64(len(req)) != v.ReqLen || int64(len(resp)) != v.RespLen {
			err = errors.New("证据正文长度无效")
			break
		}
		if err = p.absorb([]any{v, req, resp}); err != nil {
			break
		}
		var out traffic.ArchiveExchange
		out, err = traffic.HistoricalExchange(traffic.ArchiveExchange{URL: v.URL, Method: v.Method, ContentType: v.ContentType, ReqHead: v.ReqHead, RespHead: v.RespHead, ReqBody: req, RespBody: resp}, p.secrets)
		if err != nil {
			break
		}
		safe := v
		safe.URL = out.URL
		safe.ContentType = out.ContentType
		safe.ReqHead = out.ReqHead
		safe.RespHead = out.RespHead
		safe.ReqHash = bodyHash(out.ReqBody)
		safe.RespHash = bodyHash(out.RespBody)
		safe.ReqLen = int64(len(out.ReqBody))
		safe.RespLen = int64(len(out.RespBody))
		safe.ID = db.TrafficSnapshotID(safe)
		if safe.ID != v.ID {
			changes = append(changes, snapshotChange{v, safe, out.ReqBody, out.RespBody})
			p.report.Changes++
		}
		p.report.Rows++
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, errors.New("证据快照或正文无效、缺失或超过维护上限，未清理")
	}
	texts := []textChange{}
	for _, spec := range evidenceTextTables {
		var n, oversize int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM "+spec.table).Scan(&n); err != nil {
			return nil, errors.New("历史证据文本表不可用")
		}
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM "+spec.table+" t WHERE octet_length(to_jsonb(t)::text)>$1", maxBody).Scan(&oversize); err != nil || oversize > 0 {
			return nil, errors.New("历史证据文本超过维护上限或无法读取")
		}
		if p.report.Rows+n > maxRows {
			return nil, errors.New("历史证据超过 10000 条维护上限")
		}
		cols := []string{spec.key, spec.owner}
		for _, f := range spec.fields {
			cols = append(cols, f+"::text")
		}
		rows, err = tx.QueryContext(ctx, "SELECT "+strings.Join(cols, ",")+" FROM "+spec.table+" ORDER BY "+spec.key)
		if err != nil {
			return nil, errors.New("历史证据文本读取失败")
		}
		for rows.Next() {
			c := textChange{spec: spec, values: map[string]string{}}
			values := make([]string, len(spec.fields))
			args := []any{&c.id, &c.owner}
			for i := range values {
				args = append(args, &values[i])
			}
			if err = rows.Scan(args...); err != nil {
				break
			}
			if err = p.absorb([]any{spec.table, c.id, c.owner, values}); err != nil {
				break
			}
			for i, f := range spec.fields {
				safe := traffic.HistoricalText(values[i], p.secrets)
				if safe != values[i] {
					c.values[f] = safe
				}
			}
			if len(c.values) > 0 {
				texts = append(texts, c)
				p.report.Changes++
			}
			p.report.Rows++
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return nil, errors.New("历史证据文本无效或超过维护上限")
		}
	}
	return func() error {
		affected := map[int64]bool{}
		p.obsoleteEvidence = map[string]bool{}
		for _, c := range changes {
			p.obsoleteEvidence[c.old.ReqHash] = true
			p.obsoleteEvidence[c.old.RespHash] = true
			v := c.safe
			if err = writeBody(root, v.ReqHash, c.req); err != nil {
				return err
			}
			if err = writeBody(root, v.RespHash, c.resp); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO traffic_evidence_snapshots(id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO NOTHING`, v.ID, v.SourceTrafficID, v.CapturedAt, v.URL, v.Method, v.Status, v.ContentType, v.ReqHead, v.RespHead, v.ReqHash, v.RespHash, v.ReqLen, v.RespLen, v.CreatedAt); err != nil {
				return err
			}
			rows, err = tx.QueryContext(ctx, `SELECT finding_id FROM finding_traffic_bindings WHERE snapshot_id=$1`, c.old.ID)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id int64
				if err = rows.Scan(&id); err != nil {
					break
				}
				affected[id] = true
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
			if err != nil {
				return err
			}
			// A duplicate binding collision aborts the transaction rather than
			// silently losing its role/note. It needs an explicit evidence decision.
			if _, err = tx.ExecContext(ctx, `UPDATE finding_traffic_bindings SET snapshot_id=$1 WHERE snapshot_id=$2`, v.ID, c.old.ID); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM traffic_evidence_snapshots WHERE id=$1`, c.old.ID); err != nil {
				return err
			}
		}
		for _, c := range texts {
			sets := []string{}
			args := []any{c.id}
			for _, f := range c.spec.fields {
				v, ok := c.values[f]
				if !ok {
					continue
				}
				args = append(args, v)
				expr := fmt.Sprintf("%s=$%d", f, len(args))
				if c.spec.jsonFields[f] {
					expr += "::jsonb"
				}
				sets = append(sets, expr)
			}
			if _, err = tx.ExecContext(ctx, "UPDATE "+c.spec.table+" SET "+strings.Join(sets, ",")+" WHERE "+c.spec.key+"=$1", args...); err != nil {
				return err
			}
			affected[c.owner] = true
		}
		for id := range affected {
			// Keep the old review fingerprint and report version: both now show
			// stale. Do not assert that redacted evidence supports the old verdict.
			if _, err = tx.ExecContext(ctx, `UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, id); err != nil {
				return err
			}
		}
		return nil
	}, nil
}
