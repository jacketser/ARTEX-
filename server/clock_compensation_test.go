package server

import (
	"fmt"
	"github.com/Autumn-27/artex/db"
	"sync"
	"testing"
	"time"
)

func TestClockShift(t *testing.T) {
	cfg := freezeConfig{true, 60, 86400}
	for _, tt := range []struct {
		wall, mono, want int64
		reason           string
	}{
		{5, 5, 0, ""}, {64, 64, 0, ""}, {125, 125, 120, "scheduler_gap"},
		{125, 5, 120, "wall_clock_jump"}, {-115, 5, -120, "wall_clock_jump"},
		{90005, 5, 0, "wall_clock_jump_exceeds_limit"},
	} {
		n, r := clockShiftElapsed(tt.wall*int64(time.Second), tt.mono*int64(time.Second), cfg)
		if n != tt.want || r != tt.reason {
			t.Fatal(tt, n, r)
		}
	}
	cfg.Enabled = false
	if n, r := clockShiftElapsed(125*int64(time.Second), 5*int64(time.Second), cfg); n != 0 || r != "wall_clock_jump_disabled" {
		t.Fatal(n, r)
	}
}
func TestClockPersistenceExclusionsAndRecovery(t *testing.T) {
	s, rec, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	f, _ := pg.GetFinding(rec.FindingID)
	id := fmt.Sprint(*f.TaskID)
	prev := time.Now().Unix()
	dl := prev + 60
	sql := `UPDATE tasks SET status='running',paused=false,queued=false,created_at=to_timestamp($2-100),first_run_at=to_timestamp($2-100),deadline_at=to_timestamp($3) WHERE id=$1`
	if _, err := pg.Exec(sql, id, prev, dl); err != nil {
		t.Fatal(err)
	}
	if ok, err := pg.ReserveTaskRecovery(t.Context(), id, db.TaskRecoveryState{}, db.TaskRecoveryState{Attempts: 1, LastAttempt: prev - 10}, 100); err != nil || !ok {
		t.Fatal(ok, err)
	}
	key := fmt.Sprintf("test-clock-%s-%d", id, time.Now().UnixNano())
	t.Cleanup(func() { pg.Exec(`DELETE FROM clock_compensations WHERE event_key LIKE $1`, key+"%") })
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			got, err := pg.CompensateClock(t.Context(), key, prev, prev+125, 120, "scheduler_gap", []string{id})
			if err != nil || got[id] != dl+120 {
				t.Errorf("compensate %v %v", got, err)
			}
		})
	}
	wg.Wait()
	history, err := pg.RecoveryHistory(t.Context(), id, 0)
	if err != nil || history[0].ObserveUntil != prev+210 {
		t.Fatal(history, err)
	}
	state, err := pg.GetTaskRecoveryState(t.Context(), id)
	if err != nil || state.LastAttempt != prev+110 {
		t.Fatal(state, err)
	}
	// Durable deadline survives a new DB read and a backwards wall correction.
	var persisted int64
	pg.QueryRow(`SELECT EXTRACT(EPOCH FROM deadline_at)::bigint FROM tasks WHERE id=$1`, id).Scan(&persisted)
	if persisted != dl+120 {
		t.Fatal(persisted)
	}
	got, err := pg.CompensateClock(t.Context(), key+"back", prev+125, prev+5, -120, "wall_clock_jump", []string{id})
	if err != nil || got[id] != dl {
		t.Fatal(got, err)
	}
	for i, condition := range []string{"paused=true", "queued=true", "status='done'", "deadline_at=to_timestamp(1)", "deleted_at=now()"} {
		pg.Exec(sql, id, prev, dl)
		pg.Exec(`UPDATE tasks SET deleted_at=NULL WHERE id=$1`, id)
		if _, err := pg.Exec(`UPDATE tasks SET `+condition+` WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		got, err := pg.CompensateClock(t.Context(), fmt.Sprintf("%sx%d", key, i), prev, prev+125, 120, "scheduler_gap", []string{id})
		if err != nil || len(got) != 0 {
			t.Fatal(condition, got, err)
		}
	}
	pg.Exec(sql, id, prev, dl)
	pg.Exec(`UPDATE tasks SET deleted_at=NULL,deadline_at=NULL,first_run_at=NULL WHERE id=$1`, id)
	// Tasks without a deadline still get their recovery observation extended.
	pg.Exec(`UPDATE task_recovery_history SET observe_until=$2 WHERE task_id=$1`, id, prev+90)
	_, err = pg.CompensateClock(t.Context(), key+"no-deadline", prev, prev+125, 120, "scheduler_gap", []string{id})
	if err != nil {
		t.Fatal(err)
	}
	history, err = pg.RecoveryHistory(t.Context(), id, 0)
	if err != nil || history[0].ObserveUntil != prev+210 {
		t.Fatal(history, err)
	}
}
func TestEngineClockCompensatesOnceBeforeTimeout(t *testing.T) {
	s, rec, _ := trafficEvidenceServer(t)
	f, _ := s.m.pg.GetFinding(rec.FindingID)
	id := fmt.Sprint(*f.TaskID)
	task, _ := s.m.Task(id)
	now := time.Now()
	old := now.Add(-125 * time.Second)
	dl := old.Unix() + 60
	if _, err := s.m.pg.Exec(`UPDATE tasks SET status='running',first_run_at=to_timestamp($2-10),deadline_at=to_timestamp($3) WHERE id=$1`, id, old.Unix(), dl); err != nil {
		t.Fatal(err)
	}
	task.updateLifecycle(func(v *taskLifecycleState) {
		v.Status = "running"
		v.DeadlineAt = dl
		v.Paused = false
		v.Queued = false
	})
	s.engine.clockLast = old
	t.Cleanup(func() {
		s.m.pg.Exec(`DELETE FROM clock_compensations WHERE event_key LIKE $1`, fmt.Sprint(s.engine.clockInstance)+":%")
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got := s.engine.taskDeadline(task); got != dl+120 {
				t.Errorf("deadline=%d want %d", got, dl+120)
			}
		})
	}
	wg.Wait()
	if task.lifecycleSnapshot().DeadlineAt <= time.Now().Unix() {
		t.Fatal("task would expire after freeze")
	}
	// A DB failure must prevent settlement, retaining the last sample for retry.
	s.engine.clockLast = time.Now().Add(-125 * time.Second)
	s.m.pg.SetSetting("freeze_compensation", "invalid")
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM settings WHERE key='freeze_compensation'`) })
	if got := s.engine.taskDeadline(task); got != 0 {
		t.Fatal("unresolved clock allowed deadline settlement", got)
	}
}
