package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

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
		result, err := as.AssessHoneypot(r.Context(), a.ID, nil)
		if err != nil {
			writeErr(w, 500, "无法保存识别结果，请重试")
			return
		}
		results = append(results, map[string]any{"id": a.ID, "result": result})
	}
	writeJSON(w, 200, map[string]any{"count": len(results), "results": results})
}

func honeyInput(a *db.Asset) honeydetect.Input { return db.HoneypotInput(a) }
func (sc *Scheduler) refreshHoneypots() {
	ctx, cancel := context.WithTimeout(sc.s.ctx, 2*time.Second)
	defer cancel()
	if err := sc.pg.Assets().RefreshHoneypots(ctx); err != nil && sc.s.ctx.Err() == nil {
		log.Printf("[honeypot] metadata reassessment failed: %v", err)
	}
}
func (s *Server) reviewHoneypot(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "无效资产编号")
		return
	}
	var req map[string]string
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if decode(r, &req) != nil || (req["verdict"] != "confirmed" && req["verdict"] != "excluded" && req["verdict"] != "unreviewed") || len(req["note"]) > 4000 || (req["verdict"] != "unreviewed" && strings.TrimSpace(req["note"]) == "") {
		writeErr(w, 400, "请选择确认、排除或撤销，并填写不超过 4000 字节的依据")
		return
	}
	_, err := s.assetStore().AssessHoneypot(r.Context(), id, req)
	if errors.Is(err, db.ErrHoneypotStale) {
		writeErr(w, 409, err.Error())
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "资产不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, "保存人工复核失败")
		return
	}
	items, err := s.assetStore().GetByIDs([]int64{id})
	if err != nil || len(items) != 1 {
		writeErr(w, 500, "读取资产失败")
		return
	}
	writeJSON(w, 200, items[0])
}
