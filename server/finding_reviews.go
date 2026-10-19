package server

import (
	"errors"
	"github.com/Autumn-27/artex/db"
	"net/http"
	"strings"
)

func (s *Server) findingReview(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "无效的漏洞编号")
		return
	}
	if r.Method == http.MethodPut {
		var review db.FindingReview
		r.Body = http.MaxBytesReader(w, r.Body, 70000)
		if decode(r, &review) != nil {
			writeErr(w, 400, "复核内容格式错误或过长")
			return
		}
		if err := review.Validate(); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if err := s.m.PG().SaveFindingReview(r.Context(), id, review); err != nil {
			switch {
			case errors.Is(err, db.ErrFindingNotFound):
				writeErr(w, 404, "漏洞不存在")
			case errors.Is(err, db.ErrReviewStale):
				writeErr(w, 409, err.Error())
			default:
				writeErr(w, 500, "保存复核失败")
			}
			return
		}
	}
	f, err := s.m.PG().GetFinding(id)
	if err != nil {
		writeErr(w, 500, "读取漏洞失败")
		return
	}
	if f == nil {
		writeErr(w, 404, "漏洞不存在")
		return
	}
	review, err := s.m.PG().GetFindingReview(id)
	if err != nil {
		writeErr(w, 500, "读取复核失败")
		return
	}
	fingerprint := db.FindingFingerprint(f)
	warnings := []string{}
	if strings.TrimSpace(f.Evidence) == "" {
		warnings = append(warnings, "缺少文字证据；请补充原始记录及其来源。")
	}
	if f.TrafficCount == 0 {
		warnings = append(warnings, "未关联 HTTP 流量；非 HTTP 发现可使用日志、命令输出或其他可核实记录。")
	}
	if review == nil {
		warnings = append(warnings, "尚未完成人工反证复核；已有状态不代表证据已充分。")
	}
	stale := review != nil && review.Fingerprint != fingerprint
	if stale {
		warnings = append(warnings, "证据或结论内容已变化，之前的复核需要重新确认。")
	}
	writeJSON(w, 200, map[string]any{"fingerprint": fingerprint, "review": review, "stale": stale, "warnings": warnings})
}
