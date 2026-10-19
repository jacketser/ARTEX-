package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"log"
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
}

func canAutoRecover(o recoveryObservation) bool {
	return !o.Paused && !o.Queued && !o.Terminal && !o.Deleting && !o.Settling && o.Ready &&
		o.Calls == 0 && o.Operations == 0 && o.Tools == 0 && o.Approvals == 0 && o.Pending > 0 &&
		o.Last > 0 && o.Now-o.Last >= int64(autoRecoveryAfter/time.Second) && (o.Deadline == 0 || o.Now < o.Deadline)
}

func nextRecoveryState(old db.TaskRecoveryState, progress, now int64) (db.TaskRecoveryState, bool) {
	next := old
	// Only worker completion or human input resets the consecutive retry budget;
	// planner heartbeats and watchdog log entries do not count as progress.
	if progress > next.ProgressID {
		next.Attempts = 0
		next.ProgressID = progress
	}
	if next.Attempts >= autoRecoveryMax || (next.LastAttempt > 0 && now-next.LastAttempt < int64(autoRecoveryCooldown/time.Second)) {
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
	o := recoveryObservation{Ready: s.engine.ReadyFor(t), Calls: s.engine.ActiveLLMCalls(t.ID), Operations: s.engine.inflightCount(t.ID), Tools: tools, Approvals: snap.Approvals, Pending: snap.Pending, Last: last, Now: now, Deadline: life.DeadlineAt}
	if !canAutoRecover(o) {
		return false
	}
	next, due := nextRecoveryState(snap.TaskRecoveryState, snap.LatestProgress, now)
	if !due {
		return false
	}
	reserved, err := s.m.pg.ReserveTaskRecovery(ctx, t.ID, snap.TaskRecoveryState, next)
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
		message = "已自动唤醒；5 分钟内不会再次尝试"
	}
	enabled := s.m.AutoRecoveryEnabled()
	if !enabled {
		message = "自动恢复已关闭"
	}
	return map[string]any{"enabled": enabled, "attempts": state.Attempts, "max_attempts": autoRecoveryMax, "last_attempt": state.LastAttempt, "available": err == nil, "message": message}
}
