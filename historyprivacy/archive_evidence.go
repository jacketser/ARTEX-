package historyprivacy

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

type archiveRow map[string]json.RawMessage

func rowInt(row archiveRow, key string, optional bool) (int64, error) {
	raw, ok := row[key]
	if !ok && optional {
		return 0, nil
	}
	var n int64
	if !ok || string(raw) == "null" || json.Unmarshal(raw, &n) != nil {
		return 0, errors.New("归档证据整数无效")
	}
	return n, nil
}
func rowString(row archiveRow, key string, optional bool) (string, error) {
	raw, ok := row[key]
	if !ok && optional {
		return "", nil
	}
	var s string
	if !ok || string(raw) == "null" || json.Unmarshal(raw, &s) != nil {
		return "", errors.New("归档证据文本无效")
	}
	return s, nil
}
func setArchiveField(row archiveRow, key string, v any) { row[key], _ = json.Marshal(v) }
func checkArchiveFields(row archiveRow, allowed string) error {
	fields := map[string]bool{}
	for _, key := range strings.Fields(allowed) {
		fields[key] = true
	}
	for key := range row {
		if !fields[key] {
			return errors.New("归档证据包含未知字段")
		}
	}
	return nil
}

func redactArchiveEvidence(members []archiveMember, c archiveCatalog, p *plan) ([]archiveMember, error) {
	files := map[string][]byte{}
	for _, m := range members {
		if m.Header.Typeflag == tar.TypeReg {
			files[m.Header.Name] = m.Body
		}
	}
	var manifest archiveRow
	if json.Unmarshal(files["manifest.json"], &manifest) != nil || manifest == nil {
		return nil, errors.New("归档清单无效")
	}
	version, e := rowInt(manifest, "format_version", false)
	if e != nil || version != int64(c.Version) || version < 1 || version > 4 {
		return nil, errors.New("归档版本不匹配")
	}
	taskID, e := rowInt(manifest, "task_id", false)
	if e != nil || taskID != c.TaskID {
		return nil, errors.New("归档任务不匹配")
	}
	var tables map[string]json.RawMessage
	var counts map[string]int64
	var streamed map[string]string
	if json.Unmarshal(manifest["tables"], &tables) != nil || tables == nil || json.Unmarshal(manifest["data_counts"], &counts) != nil {
		return nil, errors.New("归档表清单无效")
	}
	if raw, ok := manifest["streamed_tables"]; ok && json.Unmarshal(raw, &streamed) != nil {
		return nil, errors.New("归档流式表清单无效")
	}
	var snapshot db.TaskArchiveSnapshot
	if e = json.Unmarshal(files["manifest.json"], &snapshot); e != nil {
		return nil, errors.New("归档证据清单无效")
	}
	if e = db.ValidateArchiveFindingHistory(&snapshot); e != nil {
		return nil, errors.New("归档复测或审阅格式、计数或归属无效")
	}
	tableNames := []string{"findings", "traffic_evidence_snapshots", "finding_traffic_bindings"}
	if c.Version >= 4 {
		tableNames = append(tableNames, "finding_retests", "finding_reviews", "finding_review_history")
	}
	rows := map[string][]archiveRow{}
	for _, name := range tableNames {
		if _, ok := streamed[name]; ok {
			return nil, errors.New("归档证据不支持流式扩展格式")
		}
		var rawRows []json.RawMessage
		if raw, ok := tables[name]; ok && json.Unmarshal(raw, &rawRows) != nil {
			return nil, errors.New("归档证据表无效")
		}
		if counts[name] != int64(len(rawRows)) || p.report.Rows+len(rawRows) > maxRows {
			return nil, errors.New("归档证据计数不匹配或超过 10000 条")
		}
		for _, raw := range rawRows {
			var row archiveRow
			if len(raw) > maxBody || json.Unmarshal(raw, &row) != nil || row == nil {
				return nil, errors.New("归档证据行无效或超过 16 MiB")
			}
			rows[name] = append(rows[name], row)
		}
		p.report.Rows += len(rawRows)
	}
	if c.Version < 3 && (len(rows["traffic_evidence_snapshots"])+len(rows["finding_traffic_bindings"]) > 0) {
		return nil, errors.New("旧归档版本不支持独立流量证据")
	}
	findings := map[int64]archiveRow{}
	changedFindings := map[int64]bool{}
	for _, row := range rows["findings"] {
		if e = checkArchiveFields(row, "id task_id node_id vulnclass name severity summary evidence worker asset_ids status report created_at evidence_version report_evidence_version"); e != nil {
			return nil, e
		}
		id, e := rowInt(row, "id", false)
		if e != nil || id <= 0 || findings[id] != nil {
			return nil, errors.New("归档漏洞 ID 无效或重复")
		}
		owner, e := rowInt(row, "task_id", false)
		if e != nil || owner != c.TaskID {
			return nil, errors.New("归档漏洞不属于本任务")
		}
		ev, e := rowInt(row, "evidence_version", true)
		if e != nil || ev < 0 {
			return nil, errors.New("归档证据版本无效")
		}
		rv, e := rowInt(row, "report_evidence_version", true)
		if e != nil || rv < 0 || rv > ev {
			return nil, errors.New("归档报告版本无效")
		}
		findings[id] = row
		for _, field := range []string{"name", "summary", "evidence", "report"} {
			text, e := rowString(row, field, true)
			if e != nil {
				return nil, e
			}
			safe := traffic.HistoricalText(text, p.secrets)
			if safe != text {
				setArchiveField(row, field, safe)
				changedFindings[id] = true
			}
		}
	}
	oldToNew := map[string]string{}
	newIDs := map[string]bool{}
	oldBodies, newBodies := map[string][]byte{}, map[string][]byte{}
	var budget int64
	for _, row := range rows["traffic_evidence_snapshots"] {
		if e = checkArchiveFields(row, "id source_traffic_id captured_at url method status content_type req_head resp_head req_hash resp_hash req_len resp_len unreferenced_at created_at"); e != nil {
			return nil, e
		}
		raw, _ := json.Marshal(row)
		var old db.TrafficEvidenceSnapshot
		if json.Unmarshal(raw, &old) != nil || !validHash(old.ID) || db.TrafficSnapshotID(old) != old.ID || !validHash(old.ReqHash) || !validHash(old.RespHash) || oldToNew[old.ID] != "" {
			return nil, errors.New("归档证据快照指纹无效或重复")
		}
		load := func(hash string, length int64) ([]byte, error) {
			b, ok := files[evidenceArchivePath(hash)]
			if !ok || length < 0 || length > maxBody || int64(len(b)) != length || bodyHash(b) != hash {
				return nil, errors.New("归档证据正文缺失、超限或校验不匹配")
			}
			oldBodies[hash] = b
			return b, nil
		}
		req, e := load(old.ReqHash, old.ReqLen)
		if e != nil {
			return nil, e
		}
		resp, e := load(old.RespHash, old.RespLen)
		if e != nil {
			return nil, e
		}
		if len(old.ReqHead) > maxLegacyHead || len(old.RespHead) > maxLegacyHead {
			return nil, errors.New("归档证据头超过 1 MiB")
		}
		budget += int64(len(req) + len(resp) + len(raw))
		if budget > maxTotal {
			return nil, errors.New("归档证据处理预算超过 128 MiB")
		}
		out, e := traffic.HistoricalExchange(traffic.ArchiveExchange{URL: old.URL, Method: old.Method, ContentType: old.ContentType, ReqHead: old.ReqHead, RespHead: old.RespHead, ReqBody: req, RespBody: resp}, p.secrets)
		if e != nil || len(out.ReqBody) > maxBody || len(out.RespBody) > maxBody || len(out.ReqHead) > maxLegacyHead || len(out.RespHead) > maxLegacyHead {
			return nil, errors.New("归档证据无法脱敏或输出超限")
		}
		safe := old
		safe.URL, safe.ContentType = out.URL, out.ContentType
		safe.ReqHead, safe.RespHead = out.ReqHead, out.RespHead
		safe.ReqHash, safe.RespHash = bodyHash(out.ReqBody), bodyHash(out.RespBody)
		safe.ReqLen, safe.RespLen = int64(len(out.ReqBody)), int64(len(out.RespBody))
		safe.ID = db.TrafficSnapshotID(safe)
		if newIDs[safe.ID] {
			return nil, errors.New("脱敏导致证据快照合并冲突，须先核查绑定")
		}
		newIDs[safe.ID] = true
		oldToNew[old.ID] = safe.ID
		newBodies[safe.ReqHash], newBodies[safe.RespHash] = out.ReqBody, out.RespBody
		if safe.ID != old.ID {
			// Patch only changed fields; retain creation/unreferenced timestamps and
			// untouched JSON values without float64 conversion.
			for key, value := range map[string]any{"id": safe.ID, "url": safe.URL, "content_type": safe.ContentType, "req_head": safe.ReqHead, "resp_head": safe.RespHead, "req_hash": safe.ReqHash, "resp_hash": safe.RespHash, "req_len": safe.ReqLen, "resp_len": safe.RespLen} {
				setArchiveField(row, key, value)
			}
			p.report.Changes++
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "evidence/") {
			hash := strings.TrimSuffix(strings.TrimPrefix(name, "evidence/blobs/"), ".bin")
			parts := strings.Split(hash, "/")
			if len(parts) != 2 || !validHash(parts[1]) || name != evidenceArchivePath(parts[1]) {
				return nil, errors.New("归档含未知证据文件")
			}
			if _, ok := oldBodies[parts[1]]; !ok {
				return nil, errors.New("归档含未关联的证据正文")
			}
		}
	}
	bindings, refs, unique := map[int64]bool{}, map[string]bool{}, map[string]bool{}
	for _, row := range rows["finding_traffic_bindings"] {
		if e = checkArchiveFields(row, "id finding_id snapshot_id role note position created_at"); e != nil {
			return nil, e
		}
		id, e := rowInt(row, "id", false)
		if e != nil || id <= 0 || bindings[id] {
			return nil, errors.New("归档证据绑定 ID 无效或重复")
		}
		bindings[id] = true
		fid, e := rowInt(row, "finding_id", false)
		if e != nil || findings[fid] == nil {
			return nil, errors.New("归档证据绑定指向外部漏洞")
		}
		oldID, e := rowString(row, "snapshot_id", false)
		if e != nil || oldToNew[oldID] == "" {
			return nil, errors.New("归档证据绑定缺失快照")
		}
		role, e := rowString(row, "role", false)
		if e != nil || !db.ValidTrafficRole(role) {
			return nil, errors.New("归档证据角色无效")
		}
		position, e := rowInt(row, "position", false)
		if e != nil || position < 0 {
			return nil, errors.New("归档证据位置无效")
		}
		key := fmt.Sprint(fid) + ":" + oldToNew[oldID]
		if unique[key] {
			return nil, errors.New("归档证据绑定冲突")
		}
		unique[key] = true
		refs[oldID] = true
		note, e := rowString(row, "note", false)
		if e != nil {
			return nil, e
		}
		safeNote := traffic.HistoricalText(note, p.secrets)
		if oldToNew[oldID] != oldID || safeNote != note {
			setArchiveField(row, "snapshot_id", oldToNew[oldID])
			setArchiveField(row, "note", safeNote)
			changedFindings[fid] = true
			p.report.Changes++
		}
	}
	if len(refs) != len(oldToNew) {
		return nil, errors.New("归档含未绑定的证据快照")
	}
	for _, spec := range evidenceTextTables[1:4] {
		allowed := map[string]string{
			"finding_retests":        "id finding_id conversation_id status verdict notes snapshot summary evidence error created_at started_at finished_at",
			"finding_reviews":        "finding_id fingerprint verdict sources reproduction counter_evidence limitations updated_at",
			"finding_review_history": "id finding_id kind fingerprint result created_at",
		}
		for _, row := range rows[spec.table] {
			if e = checkArchiveFields(row, allowed[spec.table]); e != nil {
				return nil, e
			}
			fid, e := rowInt(row, "finding_id", false)
			if e != nil || findings[fid] == nil {
				return nil, errors.New("归档历史关联漏洞无效")
			}
			changed := false
			for _, field := range spec.fields {
				if spec.jsonFields[field] {
					raw, ok := row[field]
					if !ok || !json.Valid(raw) {
						return nil, errors.New("归档历史 JSON 无效")
					}
					safe := traffic.HistoricalText(string(raw), p.secrets)
					if !json.Valid([]byte(safe)) {
						return nil, errors.New("脱敏后历史 JSON 无效")
					}
					// Formatting alone must not make a repeat operation stale.
					var before, after bytes.Buffer
					json.Compact(&before, raw)
					json.Compact(&after, []byte(safe))
					if !bytes.Equal(before.Bytes(), after.Bytes()) {
						row[field] = json.RawMessage(safe)
						changed = true
					}
				} else {
					text, e := rowString(row, field, false)
					if e != nil {
						return nil, e
					}
					safe := traffic.HistoricalText(text, p.secrets)
					if safe != text {
						setArchiveField(row, field, safe)
						changed = true
					}
				}
			}
			if changed {
				changedFindings[fid] = true
				p.report.Changes++
			}
		}
	}
	for fid := range changedFindings {
		row := findings[fid]
		ev, _ := rowInt(row, "evidence_version", true)
		if ev == math.MaxInt64 {
			return nil, errors.New("归档证据版本已达到上限")
		}
		setArchiveField(row, "evidence_version", ev+1)
		// Legacy manifests can lack this field. The restore normalizer defaults it
		// to zero. Preserve the old report version so sanitization makes it stale.
		p.report.Changes++
	}
	if p.report.Changes == 0 {
		return members, nil
	}
	for _, name := range tableNames {
		if len(rows[name]) > 0 {
			for _, row := range rows[name] {
				encoded, err := json.Marshal(row)
				if err != nil || len(encoded) > maxBody {
					return nil, errors.New("脱敏后证据行超过 16 MiB")
				}
			}
			tables[name], e = json.Marshal(rows[name])
			if e != nil {
				return nil, e
			}
		}
	}
	manifest["tables"], e = json.Marshal(tables)
	if e != nil {
		return nil, e
	}
	safeManifest, e := json.Marshal(manifest)
	if e != nil || len(safeManifest) > maxTotal {
		return nil, errors.New("重写清单超过 128 MiB")
	}
	result := []archiveMember{}
	for _, m := range members {
		name := strings.TrimSuffix(m.Header.Name, "/")
		if name == "evidence" || strings.HasPrefix(name, "evidence/") {
			continue
		}
		if name == "manifest.json" {
			m.Body = safeManifest
			m.Header = tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(safeManifest)), ModTime: m.Header.ModTime}
		}
		result = append(result, m)
	}
	// Stable ordering makes output and verification reproducible.
	hashes := make([]string, 0, len(newBodies))
	for hash := range newBodies {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)
	for _, hash := range hashes {
		b := newBodies[hash]
		result = append(result, archiveMember{Header: tar.Header{Name: evidenceArchivePath(hash), Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(b))}, Body: b})
	}
	return result, nil
}

func evidenceArchivePath(hash string) string {
	return "evidence/blobs/" + hash[:2] + "/" + hash + ".bin"
}
