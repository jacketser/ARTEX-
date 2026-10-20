package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"log"
	"net/http"
	"strconv"
	"time"
)

const (
	autoRecoveryAfter    = 120 * time.Second
	autoRecoveryCooldown = 5 * time.Minute
	autoRecoveryMax      = 3
)

type recoveryObservation struct {
	Paused, Queued, Terminal, Deleting, Settling, Ready bool
	Calls, Operations                                   int64
	Tools, Approvals, Pending                           int
	Last, Now, Deadline                                 int64
	After                                               int64
}

func canAutoRecover(o recoveryObservation) bool {
	if o.After == 0 {
		o.After = int64(autoRecoveryAfter / time.Second)
	}
	return !o.Paused && !o.Queued && !o.Terminal && !o.Deleting && !o.Settling && o.Ready &&
		o.Calls == 0 && o.Operations == 0 && o.Tools == 0 && o.Approvals == 0 && o.Pending > 0 &&
		o.Last > 0 && o.Now-o.Last >= o.After && (o.Deadline == 0 || o.Now < o.Deadline)
}

func nextRecoveryState(old db.TaskRecoveryState, progress, now int64, cooldowns ...int64) (db.TaskRecoveryState, bool) {
	cooldown := int64(autoRecoveryCooldown / time.Second)
	if len(cooldowns) > 0 {
		cooldown = cooldowns[0]
	}
	next := old
	// Only worker completion or human input resets the consecutive retry budget;
	// planner heartbeats and watchdog log entries do not count as progress.
	if progress > next.ProgressID {
		next.Attempts = 0
		next.ProgressID = progress
	}
	if next.Attempts >= autoRecoveryMax || (next.LastAttempt > 0 && now-next.LastAttempt < cooldown) {
		return next, false
	}
	next.Attempts++
	next.LastAttempt = now
	return next, true
}

func (sc *Scheduler) recoverStalledTasks() {
	if sc.s.ctx == nil || sc.s.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(sc.s.ctx, 2*time.Second)
	err := sc.pg.UpdateRecoveryOutcomes(ctx, time.Now().Unix())
	cancel()
	if err != nil {
		log.Printf("[recovery] observe failed: %v", err)
		return
	}
	// Fail closed on unavailable/corrupt settings; unset means enabled.
	value, ok, err := sc.pg.GetSetting(settingAutoRecovery)
	if err != nil || (ok && value != "true" && value != "1") {
		return
	}
	for _, task := range sc.s.m.List() {
		sc.s.recoverStalledTask(task, time.Now().Unix())
	}
}

func (s *Server) recoverStalledTask(t *Task, now int64) bool {
	// Use the same lifecycle locks as pause, admission and terminal transitions.
	s.concMu.Lock()
	defer s.concMu.Unlock()
	s.m.taskStateMu.Lock()
	defer s.m.taskStateMu.Unlock()
	current, ok := s.m.Task(t.ID)
	if !ok || current != t {
		return false
	}
	cfg, err := s.recoveryConfig()
	if err != nil {
		return false
	}
	life := t.lifecycleSnapshot()
	if life.Paused || life.Queued || isTerminalStatus(life.Status) || s.engine.IsDeleting(t.ID) || s.engine.IsPaused(t.ID) || s.engine.isSettling(t.ID) {
		return false
	}
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	snap, err := s.m.pg.TaskRecoverySnapshot(ctx, t.ID)
	if err != nil {
		return false
	}
	last := max(snap.LastActivity, s.engine.LastActivity(t.ID))
	tools, _ := s.engine.toolProgress(t.ID)
	o := recoveryObservation{After: int64(cfg.AfterSeconds), Ready: s.engine.ReadyFor(t), Calls: s.engine.ActiveLLMCalls(t.ID), Operations: s.engine.inflightCount(t.ID), Tools: tools, Approvals: snap.Approvals, Pending: snap.Pending, Last: last, Now: now, Deadline: life.DeadlineAt}
	if !canAutoRecover(o) {
		return false
	}
	next, due := nextRecoveryState(snap.TaskRecoveryState, snap.LatestProgress, now, int64(cfg.CooldownSeconds))
	if !due {
		return false
	}
	reserved, err := s.m.pg.ReserveTaskRecovery(ctx, t.ID, snap.TaskRecoveryState, next, int64(cfg.ObserveSeconds))
	if err != nil {
		log.Printf("[recovery] task %s state write failed: %v", t.ID, err)
		return false
	}
	if !reserved {
		return false
	}
	// Run is idempotent. Never Resume (which clears pause), reset running intents,
	// cancel a live worker, or bypass approval/concurrency boundaries.
	s.engine.Run(s.ctx, t)
	t.Notify()
	meta, _ := json.Marshal(map[string]any{"auto_recovery": true, "attempt": next.Attempts})
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text", Summary: fmt.Sprintf("停滞自动恢复：已唤醒调度循环（%d/%d）；未重置意图或重放工具", next.Attempts, autoRecoveryMax), Metadata: meta})
	return true
}

func (s *Server) taskRecoveryStatus(ctx context.Context, t *Task) map[string]any {
	state, err := s.m.pg.GetTaskRecoveryState(ctx, t.ID)
	message := "尚未触发自动唤醒"
	if err != nil {
		message = "暂时无法读取恢复状态"
	} else if state.Attempts >= autoRecoveryMax {
		message = "已达连续自动唤醒上限，请检查记录并人工处理"
	} else if state.Attempts > 0 {
		message = "已自动唤醒；冷却结束前不会再次尝试"
	}
	cfg, configErr := s.recoveryConfig()
	history, historyErr := s.m.pg.RecoveryHistory(ctx, t.ID, 0)
	if len(history) > 0 {
		switch history[0].Status {
		case "observing":
			message = "已唤醒，正在观察实际进展"
		case "recovered":
			message = "已观察到 Worker 完成或任务完成"
		case "no_progress":
			message = "观察期内未出现有效进展"
		case "interrupted":
			message = "任务状态改变，恢复观察已结束"
		}
	}
	alert := false
	alerts, alertsErr := s.m.pg.RecoveryAlerts(ctx)
	for _, a := range alerts {
		if a.TaskID == t.ID {
			alert = true
			break
		}
	}
	if alert {
		message = "连续唤醒未取得进展，请人工检查"
	}
	enabled := s.m.AutoRecoveryEnabled()
	if !enabled {
		message = "自动恢复已关闭"
	}
	available := err == nil && historyErr == nil && configErr == nil && alertsErr == nil
	if !available {
		message = "暂时无法读取完整恢复状态"
	}
	return map[string]any{"history": history, "needs_attention": alert, "config": cfg, "enabled": enabled, "attempts": state.Attempts, "max_attempts": autoRecoveryMax, "last_attempt": state.LastAttempt, "available": available, "message": message}
}

type recoveryConfig struct {
	AfterSeconds    int `json:"after_seconds"`
	CooldownSeconds int `json:"cooldown_seconds"`
	ObserveSeconds  int `json:"observe_seconds"`
}

func (c recoveryConfig) valid() bool {
	return c.AfterSeconds >= 30 && c.AfterSeconds <= 3600 && c.ObserveSeconds >= 30 && c.ObserveSeconds <= 3600 && c.CooldownSeconds >= c.ObserveSeconds && c.CooldownSeconds <= 86400
}
func (s *Server) recoveryConfig() (recoveryConfig, error) {
	cfg := recoveryConfig{120, 300, 300}
	v, ok, err := s.m.pg.GetSetting("auto_recovery_config")
	if err != nil {
		return cfg, err
	}
	if ok {
		if err = json.Unmarshal([]byte(v), &cfg); err != nil {
			return cfg, err
		}
		if !cfg.valid() {
			return cfg, fmt.Errorf("invalid recovery config")
		}
	}
	return cfg, nil
}
func (s *Server) recoverySettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var cfg recoveryConfig
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if decode(r, &cfg) != nil || !cfg.valid() {
			writeErr(w, 400, "停滞和观察期需为 30–3600 秒；冷却需不小于观察期且不超过 86400 秒")
			return
		}
		raw, _ := json.Marshal(cfg)
		if err := s.m.pg.SetSetting("auto_recovery_config", string(raw)); err != nil {
			writeErr(w, 500, "保存失败")
			return
		}
	}
	cfg, err := s.recoveryConfig()
	if err != nil {
		writeErr(w, 503, "恢复配置不可用")
		return
	}
	writeJSON(w, 200, cfg)
}
func (s *Server) recoveryHistory(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.PathValue("id"))
	if t == nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	before, err := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	if r.URL.Query().Get("before") != "" && (err != nil || before < 0) {
		writeErr(w, 400, "无效历史游标")
		return
	}
	history, err := s.m.pg.RecoveryHistory(r.Context(), t.ID, before)
	if err != nil {
		writeErr(w, 500, "读取历史失败")
		return
	}
	writeJSON(w, 200, history)
}
func (s *Server) recoveryAlerts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.m.pg.RecoveryAlerts(r.Context())
	if err != nil {
		writeErr(w, 500, "读取恢复提醒失败")
		return
	}
	writeJSON(w, 200, rows)
}
