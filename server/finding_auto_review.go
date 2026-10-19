package server

import (
	"errors"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"net/http"
)

func (s *Server) findingAutoReview(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingTrafficAccess(w, r, false)
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
	writeJSON(w, 200, map[string]any{"fingerprint": db.FindingFingerprint(f), "review": evidence.ReviewFinding(f, retests)})
}
