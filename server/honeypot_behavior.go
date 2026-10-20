package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/honeydetect"
	"net/http"
	"strconv"
	"time"
)

const behaviorKey = "honeypot_behavior"

func (s *Server) behaviorConfig() (honeydetect.BehaviorConfig, error) {
	c := honeydetect.DefaultBehaviorConfig()
	v, ok, e := s.m.pg.GetSetting(behaviorKey)
	if e != nil {
		return c, e
	}
	if ok {
		if e = json.Unmarshal([]byte(v), &c); e != nil {
			return c, e
		}
	}
	return c, c.Validate()
}
func (s *Server) behaviorSettings(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if r.Method == http.MethodPut {
		var c honeydetect.BehaviorConfig
		if !decodeEnhancement(w, r, &c) {
			return
		}
		if e := c.Validate(); e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		// Synchronize authorization edits with run reservation, not the network call.
		tx, e := s.m.pg.BeginTx(r.Context(), nil)
		if e != nil {
			writeErr(w, 503, "配置保存失败")
			return
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(r.Context(), "SELECT pg_advisory_xact_lock(722683)"); e == nil {
			b, _ := json.Marshal(c)
			_, e = tx.ExecContext(r.Context(), `INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, behaviorKey, string(b))
		}
		if e != nil || tx.Commit() != nil {
			writeErr(w, 503, "配置保存失败")
			return
		}
	}
	c, e := s.behaviorConfig()
	if e != nil {
		writeErr(w, 503, "行为探测配置不可用")
		return
	}
	writeJSON(w, 200, c)
}
func behaviorFingerprint(a *db.Asset) string {
	b, _ := json.Marshal([]any{a.Type, a.URL, a.Port, honeydetect.Fingerprint(db.HoneypotInput(a))})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type behaviorRecord struct {
	ID         int64           `json:"id"`
	Origin     string          `json:"origin"`
	Status     string          `json:"status"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at"`
	Result     json.RawMessage `json:"result"`
	Stale      bool            `json:"stale"`
}

func (s *Server) honeypotBehavior(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "资产编号无效")
		return
	}
	assets, e := s.assetStore().GetByIDs([]int64{id})
	if e != nil {
		writeErr(w, 503, "资产不可用")
		return
	}
	if len(assets) != 1 {
		writeErr(w, 404, "资产不存在")
		return
	}
	a := assets[0]
	rules, e := s.m.pg.HoneypotRules()
	if e != nil {
		writeErr(w, 503, "规则不可用")
		return
	}
	fingerprint := behaviorFingerprint(a)
	if r.Method == http.MethodGet {
		before := int64(0)
		if v := r.URL.Query().Get("before"); v != "" {
			before, e = strconv.ParseInt(v, 10, 64)
			if e != nil || before <= 0 {
				writeErr(w, 400, "游标无效")
				return
			}
		}
		rows, e := s.m.pg.QueryContext(r.Context(), `SELECT id,origin,status,created_at,finished_at,result,source_fingerprint,rule_revision FROM asset_honeypot_probes WHERE asset_id=$1 AND ($2::bigint=0 OR id<$2) ORDER BY id DESC LIMIT 10`, id, before)
		if e != nil {
			writeErr(w, 503, "读取探测历史失败")
			return
		}
		defer rows.Close()
		records := []behaviorRecord{}
		for rows.Next() {
			var rec behaviorRecord
			var source, revision string
			if e = rows.Scan(&rec.ID, &rec.Origin, &rec.Status, &rec.CreatedAt, &rec.FinishedAt, &rec.Result, &source, &revision); e != nil {
				writeErr(w, 503, "读取探测历史失败")
				return
			}
			rec.Stale = source != fingerprint || revision != rules.Revision()
			if rec.Status == "running" && time.Since(rec.CreatedAt) > time.Minute {
				rec.Status = "interrupted"
			}
			records = append(records, rec)
		}
		if rows.Err() != nil {
			writeErr(w, 503, "读取探测历史失败")
			return
		}
		writeJSON(w, 200, records)
		return
	}
	var in struct {
		Confirm bool   `json:"confirm"`
		Origin  string `json:"origin"`
	}
	if !decodeEnhancement(w, r, &in) {
		return
	}
	origin, e := honeydetect.Origin(a.URL)
	if !in.Confirm {
		writeErr(w, 400, "请明确确认已授权的探测范围")
		return
	}
	if a.Type != "service" || e != nil {
		writeErr(w, 400, "仅支持已保存的 HTTP/HTTPS 服务资产")
		return
	}
	if in.Origin != origin {
		writeErr(w, 409, "服务来源已变化，请刷新后确认")
		return
	}
	// DNS pinning cannot be guaranteed through an arbitrary upstream proxy.
	if s.m.GlobalProxy() != "" {
		writeErr(w, 409, "行为探测暂不支持全局上游代理；不会绕过已配置代理直连")
		return
	}
	if s.m.traffic == nil {
		writeErr(w, 503, "代理安全检查器不可用")
		return
	}
	runID, e := s.reserveBehavior(r.Context(), id, origin, fingerprint, rules.Revision())
	if e != nil {
		var status *behaviorError
		if errors.As(e, &status) {
			if status.code == 429 {
				w.Header().Set("Retry-After", "300")
			}
			writeErr(w, status.code, status.Error())
		} else {
			writeErr(w, 503, "无法建立探测审计记录")
		}
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	result, probeErr := honeydetect.Probe(ctx, origin, rules, func(c context.Context, method, raw string) error {
		var value string
		if err := s.m.pg.QueryRowContext(c, "SELECT value FROM settings WHERE key=$1", behaviorKey).Scan(&value); err != nil {
			return err
		}
		var policy honeydetect.BehaviorConfig
		if json.Unmarshal([]byte(value), &policy) != nil || policy.Validate() != nil || !policy.Allows(origin) || s.m.GlobalProxy() != "" {
			return errors.New("probe authorization changed")
		}
		return s.m.traffic.AdmitDiagnosticRequest(c, method, raw)
	})
	status := "complete"
	if probeErr != nil {
		status = "blocked"
		result.Signals = append(result.Signals, probeErr.Error())
	}
	if ctx.Err() != nil {
		status = "interrupted"
	}
	b, _ := json.Marshal(result)
	saveCtx, saveCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer saveCancel()
	_, e = s.m.pg.ExecContext(saveCtx, `UPDATE asset_honeypot_probes SET status=$2,result=$3::jsonb,finished_at=now() WHERE id=$1`, runID, status, string(b))
	if e != nil {
		writeErr(w, 503, "请求已结束，但结果保存失败；请查看历史，勿立即重复探测")
		return
	}
	writeJSON(w, 200, map[string]any{"id": runID, "status": status, "result": result})
}

type behaviorError struct {
	code    int
	message string
}

func (e *behaviorError) Error() string { return e.message }
func (s *Server) reserveBehavior(ctx context.Context, id int64, origin, fingerprint, revision string) (int64, error) {
	tx, e := s.m.pg.BeginTx(ctx, nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(722683)"); e != nil {
		return 0, e
	}
	c := honeydetect.DefaultBehaviorConfig()
	var raw string
	e = tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=$1", behaviorKey).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return 0, &behaviorError{403, "请先在系统设置中启用行为探测并配置明确授权来源"}
	}
	if e != nil {
		return 0, e
	}
	if json.Unmarshal([]byte(raw), &c) != nil || c.Validate() != nil {
		return 0, &behaviorError{503, "行为探测配置不可用"}
	}
	if !c.Allows(origin) {
		return 0, &behaviorError{403, "该服务来源不在已启用的行为探测授权列表中"}
	}
	var recent, active int
	e = tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE (asset_id=$1 OR origin=$2) AND created_at>now()-interval '5 minutes'),count(*) FILTER (WHERE status='running' AND created_at>now()-interval '1 minute') FROM asset_honeypot_probes WHERE created_at>now()-interval '5 minutes'`, id, origin).Scan(&recent, &active)
	if e != nil {
		return 0, e
	}
	if recent > 0 || active >= 2 {
		return 0, &behaviorError{429, "同一服务需间隔 5 分钟，全局同时最多 2 次探测"}
	}
	var run int64
	e = tx.QueryRowContext(ctx, `INSERT INTO asset_honeypot_probes(asset_id,origin,source_fingerprint,rule_revision) VALUES($1,$2,$3,$4) RETURNING id`, id, origin, fingerprint, revision).Scan(&run)
	if e != nil {
		return 0, e
	}
	return run, tx.Commit()
}
