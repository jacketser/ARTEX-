package server

import (
	"encoding/json"
	"github.com/Autumn-27/artex/honeydetect"
	"github.com/Autumn-27/artex/scenarioprompt"
	"io"
	"net/http"
)

func decodeEnhancement(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		writeErr(w, 400, "配置格式不正确或包含未知字段")
		return false
	}
	return true
}
func (s *Server) honeyRulesSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var c honeydetect.RuleSet
		if !decodeEnhancement(w, r, &c) {
			return
		}
		if err := c.Validate(); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if err := s.m.pg.SaveHoneypotRules(r.Context(), c); err != nil {
			writeErr(w, 500, "保存规则失败")
			return
		}
	}
	c, err := s.m.pg.HoneypotRules()
	if err != nil {
		writeErr(w, 503, "蜜罐规则不可用")
		return
	}
	writeJSON(w, 200, c)
}
func (s *Server) scenarioSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var c scenarioprompt.Config
		if !decodeEnhancement(w, r, &c) {
			return
		}
		if err := c.Validate(); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if err := s.m.pg.SaveScenarioConfig(c); err != nil {
			writeErr(w, 500, "保存场景配置失败")
			return
		}
	}
	c, err := s.assetStore().ScenarioConfig()
	if err != nil {
		writeErr(w, 503, "场景配置不可用")
		return
	}
	writeJSON(w, 200, c)
}
func (s *Server) scenarioPreview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Summary string   `json:"summary"`
		Tags    []string `json:"chain_tags"`
	}
	if !decodeEnhancement(w, r, &in) {
		return
	}
	if len(in.Summary) > 16000 || scenarioprompt.ValidateTags(in.Tags) != nil {
		writeErr(w, 400, "意图或场景标签无效")
		return
	}
	c, err := s.assetStore().ScenarioConfig()
	if err != nil {
		writeErr(w, 503, "场景配置不可用")
		return
	}
	b, _ := json.Marshal(in)
	writeJSON(w, 200, scenarioprompt.Select(b, c))
}
