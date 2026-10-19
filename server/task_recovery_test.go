package server

import (
	"context"
	"github.com/Autumn-27/artex/db"
	"testing"
	"time"
)

func TestRecoveryGates(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*recoveryObservation)
		want bool
	}{
		{"stalled", func(o *recoveryObservation) {}, true},
		{"paused", func(o *recoveryObservation) { o.Paused = true }, false},
		{"queued", func(o *recoveryObservation) { o.Queued = true }, false},
		{"terminal", func(o *recoveryObservation) { o.Terminal = true }, false},
		{"deleting", func(o *recoveryObservation) { o.Deleting = true }, false},
		{"settling", func(o *recoveryObservation) { o.Settling = true }, false},
		{"not ready", func(o *recoveryObservation) { o.Ready = false }, false},
		{"model", func(o *recoveryObservation) { o.Calls = 1 }, false},
		{"live operation", func(o *recoveryObservation) { o.Operations = 1 }, false},
		{"tool", func(o *recoveryObservation) { o.Tools = 1 }, false},
		{"approval", func(o *recoveryObservation) { o.Approvals = 1 }, false},
		{"no intent", func(o *recoveryObservation) { o.Pending = 0 }, false},
		{"recent", func(o *recoveryObservation) { o.Last = 299 }, false},
		{"unknown", func(o *recoveryObservation) { o.Last = 0 }, false},
		{"deadline", func(o *recoveryObservation) { o.Deadline = 300 }, false},
		{"clock backwards", func(o *recoveryObservation) { o.Last = 400 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := recoveryObservation{Ready: true, Pending: 1, Last: 100, Now: 300}
			tc.edit(&o)
			if canAutoRecover(o) != tc.want {
				t.Fatal(o)
			}
		})
	}
}
func TestRecoveryCooldownAndBudget(t *testing.T) {
	state := db.TaskRecoveryState{}
	for i := 1; i <= 3; i++ {
		next, due := nextRecoveryState(state, 10, int64(i)*300)
		if !due || next.Attempts != i {
			t.Fatal(next, due)
		}
		state = next
	}
	if _, due := nextRecoveryState(state, 10, 1200); due {
		t.Fatal("exceeded budget")
	}
	next, due := nextRecoveryState(state, 11, 1200)
	if !due || next.Attempts != 1 {
		t.Fatal("real progress did not reset")
	}
	if _, due = nextRecoveryState(next, 11, 1201); due {
		t.Fatal("cooldown ignored")
	}
}
func TestRecoveryPersistsAndNeverResetsRunningIntents(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	task, err := m.CreateTask("recovery fixture", "offline", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.DeleteTask(task.ID, DeleteTaskOptions{})
	s := newAdmissionTestServer(m, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.ctx = ctx
	s.engine.started.Store(task.ID, true) // no model or tool execution in this fixture
	id, err := task.Store.AddNode(db.KindIntent, map[string]any{"summary": "already running"}, 0, "running", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix() + 3600
	for i := 0; i < 3; i++ {
		if !s.recoverStalledTask(task, now+int64(i)*300) {
			t.Fatalf("attempt %d was not admitted", i)
		}
	}
	state, err := m.pg.GetTaskRecoveryState(ctx, task.ID)
	if err != nil || state.Attempts != 3 {
		t.Fatal(state, err)
	}
	restarted := newAdmissionTestServer(m, nil)
	restarted.ctx = ctx
	restarted.engine.started.Store(task.ID, true)
	if restarted.recoverStalledTask(task, now+1200) {
		t.Fatal("restart reset budget")
	}
	nodes, err := task.Store.ListByKind(db.KindIntent, 100)
	if err != nil || len(nodes) != 1 || nodes[0].ID != id || nodes[0].State != "running" {
		t.Fatal("running intent changed", nodes, err)
	}
	// Human input permits a fresh bounded recovery sequence.
	if _, err = task.Store.AppendActivity(db.Activity{Worker: "user", Kind: "user", Summary: "inspect again"}); err != nil {
		t.Fatal(err)
	}
	if !restarted.recoverStalledTask(task, now+1500) {
		t.Fatal("human input did not allow fresh attempt")
	}
	if _, err = m.pg.Exec(`DELETE FROM task_recovery_state WHERE task_id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	s.engine.BeginLLMCall(task.ID)
	if s.recoverStalledTask(task, now+1800) {
		t.Fatal("woke live model")
	}
	s.engine.EndLLMCall(task.ID)
	s.engine.beginTaskOperation(task.ID)
	if s.recoverStalledTask(task, now+1800) {
		t.Fatal("woke live operation")
	}
	s.engine.decInflight(task.ID)
	if err = m.SetTaskPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	if s.recoverStalledTask(task, now+1800) {
		t.Fatal("woke paused task")
	}
}
