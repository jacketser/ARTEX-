package server

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/honeydetect"
)

func (s *Server) scanAssetHoneypot(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	if dec.Decode(&req) != nil || dec.Decode(new(any)) != io.EOF || len(req.IDs) == 0 || len(req.IDs) > 200 {
		writeErr(w, 400, "请提交 1–200 个明确的资产编号")
		return
	}
	seen := map[int64]bool{}
	ids := []int64{}
	for _, id := range req.IDs {
		if id <= 0 {
			writeErr(w, 400, "无效资产编号")
			return
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	assets, err := as.GetByIDs(ids)
	if err != nil {
		writeErr(w, 500, "无法读取所选资产，请刷新后重试")
		return
	}
	if len(assets) != len(ids) {
		writeErr(w, 404, "部分资产已不存在，请刷新后重试")
		return
	}
	results := make([]map[string]any, 0, len(assets))
	for _, a := range assets {
		result := honeydetect.Detect(honeyInput(a))
		if err := as.SetHoneypot(a.ID, result); err != nil {
			writeErr(w, 500, "无法保存识别结果，请重试")
			return
		}
		results = append(results, map[string]any{"id": a.ID, "result": result})
	}
	writeJSON(w, 200, map[string]any{"count": len(results), "results": results})
}

func honeyInput(a *db.Asset) honeydetect.Input {
	get := func(key string) string {
		if v, ok := a.Extra[key].(string); ok {
			return v
		}
		return ""
	}
	return honeydetect.Input{Service: a.ServiceName, Title: a.PageTitle, Technologies: a.Technologies, Banner: get("banner"), ServerHeader: get("server_header"), PoweredBy: get("powered_by"), ResponseSummary: get("response_summary")}
}
