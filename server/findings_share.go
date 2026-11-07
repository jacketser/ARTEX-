package server

import (
	"context"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
)

// Load secrets once per export, without caching across profile/password changes.
// Build the entire download before setting attachment headers or writing bytes.
func (s *Server) sharedFindingsExport(w http.ResponseWriter, r *http.Request, fs []*db.DBFinding, format string, now time.Time) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	secrets, err := s.m.trafficSecrets(ctx)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "无法读取脱敏凭据，未生成导出文件，请稍后重试")
		return
	}
	var body []byte
	var contentType, extension string
	if format == "md-single" {
		body = []byte(report.SharedFindingsMarkdown(fs, now, secrets))
		contentType, extension = "text/markdown; charset=utf-8", ".md"
	} else {
		body = report.SharedFindingsCSV(fs, secrets)
		contentType, extension = "text/csv; charset=utf-8", ".csv"
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Artex-Export", "sanitized-copy; not-original-evidence")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="findings-sanitized-`+now.Format("20060102-150405")+extension+`"`)
	_, _ = w.Write(body)
}
