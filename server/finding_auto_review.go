package server

import (
	"errors"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"net/http"
	"strconv"
)

func (s *Server) findingAutoReview(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingTrafficAccess(w, r, r.Method == http.MethodPost)
	if !ok {
		return
	}
	f, retests, err := s.m.pg.FindingAutoReviewContext(r.Context(), id)
	if errors.Is(err, db.ErrFindingNotFound) {
		writeErr(w, 404, "漏洞不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, "读取审阅上下文失败")
		return
	}
	review := evidence.ReviewFinding(f, retests)
	review.ApplyComparisons(s.evidenceStore().CompareTraffic(f.TrafficBindings))
	fingerprint := db.FindingFingerprint(f)
	if r.Method == http.MethodPost {
		if err := s.m.pg.SaveAutomaticReview(r.Context(), id, fingerprint, review); err != nil {
			if errors.Is(err, db.ErrReviewStale) {
				writeErr(w, 409, err.Error())
			} else {
				writeErr(w, 500, "保存审阅历史失败")
			}
			return
		}
	}
	writeJSON(w, 200, map[string]any{"fingerprint": fingerprint, "review": review})
}

func (s *Server) findingReviewHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingTrafficAccess(w, r, false)
	if !ok {
		return
	}
	before, err := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	if r.URL.Query().Get("before") != "" && (err != nil || before < 0) {
		writeErr(w, 400, "无效历史游标")
		return
	}
	rows, err := s.m.pg.FindingReviewHistory(r.Context(), id, before)
	if err != nil {
		writeErr(w, 500, "读取审阅历史失败")
		return
	}
	writeJSON(w, 200, rows)
}
