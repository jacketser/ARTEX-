package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"log"
	"math"
	"net/http"
	"strconv"
	"time"
)

type freezeConfig struct {
	Enabled   bool  `json:"enabled"`
	Threshold int64 `json:"threshold_seconds"`
	MaxShift  int64 `json:"max_compensation_seconds"`
}

func (c freezeConfig) valid() bool {
	return c.Threshold >= 30 && c.Threshold <= 3600 && c.MaxShift >= c.Threshold && c.MaxShift <= 604800
}
func (m *Manager) freezeConfig() (freezeConfig, error) {
	c := freezeConfig{true, 60, 86400}
	v, ok, err := m.pg.GetSetting("freeze_compensation")
	if err != nil {
		return c, err
	}
	if ok {
		if err = json.Unmarshal([]byte(v), &c); err != nil {
			return c, err
		}
	}
	if !c.valid() {
		return c, fmt.Errorf("冻结补偿配置无效")
	}
	return c, nil
}

// wall elapsed catches NTP/VM wall jumps; monotonic elapsed distinguishes clock
// corrections from a process scheduling gap. A long gap is a suspicion, not proof of VM sleep.
func clockShift(previous, now time.Time, c freezeConfig) (int64, string) {
	return clockShiftElapsed(now.UnixNano()-previous.UnixNano(), now.Sub(previous).Nanoseconds(), c)
}

func clockShiftElapsed(wall, mono int64, c freezeConfig) (int64, string) {
	threshold := float64(c.Threshold) * float64(time.Second)
	skew := float64(wall - mono)
	var shift int64
	reason := ""
	if math.Abs(skew) >= threshold {
		shift = int64(skew / float64(time.Second))
		reason = "wall_clock_jump"
	} else if wall-int64(5*time.Second) >= int64(threshold) {
		shift = (wall - int64(5*time.Second)) / int64(time.Second)
		reason = "scheduler_gap"
	}
	if shift == 0 {
		return 0, ""
	}
	if !c.Enabled {
		return 0, reason + "_disabled"
	}
	if math.Abs(float64(shift)) > float64(c.MaxShift) {
		return 0, reason + "_exceeds_limit"
	}
	return shift, reason
}

// Called by the scheduler and immediately before task deadline checks.
func (e *Engine) checkClock() bool {
	e.clockMu.Lock()
	defer e.clockMu.Unlock()
	now := time.Now()
	if e.clockLast.IsZero() {
		e.clockLast = now
		return true
	}
	if now.Sub(e.clockLast) >= 0 && now.Sub(e.clockLast) < 2*time.Second && now.UnixNano()-e.clockLast.UnixNano() >= 0 && now.UnixNano()-e.clockLast.UnixNano() < int64(2*time.Second) {
		return true
	}
	cfg, err := e.m.freezeConfig()
	if err != nil {
		log.Printf("[clock] config unavailable: %v", err)
		return false
	}
	previous := e.clockLast
	shift, reason := clockShift(previous, now, cfg)
	if reason == "" {
		e.clockLast = now
		return true
	}
	e.m.taskStateMu.Lock()
	defer e.m.taskStateMu.Unlock()
	ids := []string{}
	for _, t := range e.m.List() {
		v := t.lifecycleSnapshot()
		if v.Status == "running" && !v.Paused && !v.Queued && !e.IsDeleting(t.ID) && !e.isSettling(t.ID) {
			ids = append(ids, t.ID)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	deadlines, err := e.m.pg.CompensateClock(ctx, fmt.Sprintf("%d:%d", e.clockInstance, previous.UnixNano()), previous.Unix(), now.Unix(), shift, reason, ids)
	if err != nil {
		log.Printf("[clock] compensation failed, will retry: %v", err)
		return false
	}
	e.clockLast = now
	for id, dl := range deadlines {
		e.deadline.Store(id, dl)
		if t, ok := e.m.Task(id); ok {
			t.updateLifecycle(func(v *taskLifecycleState) { v.DeadlineAt = dl })
			e.emitActivity(t, db.Activity{Worker: "system", Kind: "text", Summary: fmt.Sprintf("服务器时钟异常补偿：截止时间调整 %+d 秒（%s）", shift, reason)})
			t.Notify()
		}
	}
	log.Printf("[clock] %s shift=%d affected=%d", reason, shift, len(deadlines))
	return true
}
func (s *Server) freezeSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var c freezeConfig
		if !decodeEnhancement(w, r, &c) {
			return
		}
		if !c.valid() {
			writeErr(w, 400, "阈值 30–3600 秒；单次补偿上限需不小于阈值且最多 7 天")
			return
		}
		b, _ := json.Marshal(c)
		if err := s.m.pg.SetSetting("freeze_compensation", string(b)); err != nil {
			writeErr(w, 500, "保存失败")
			return
		}
	}
	c, err := s.m.freezeConfig()
	if err != nil {
		writeErr(w, 503, "冻结补偿配置不可用")
		return
	}
	writeJSON(w, 200, c)
}
func (s *Server) clockHistory(w http.ResponseWriter, r *http.Request) {
	before, err := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	if r.URL.Query().Get("before") != "" && (err != nil || before < 0) {
		writeErr(w, 400, "无效游标")
		return
	}
	rows, err := s.m.pg.ClockHistory(r.Context(), before)
	if err != nil {
		writeErr(w, 500, "读取补偿记录失败")
		return
	}
	writeJSON(w, 200, rows)
}
