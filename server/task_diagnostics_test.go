package server

import (
	"github.com/Autumn-27/artex/db"
	"testing"
)

func TestTaskDiagnosticWaits(t *testing.T) {
	for _, tc := range []struct {
		code             string
		paused           bool
		calls            int64
		approvals, tools int
		available        bool
	}{
		{"paused", true, 1, 1, 1, true}, {"approval", false, 1, 1, 1, true}, {"tool", false, 1, 0, 1, true}, {"model_or_agent", false, 1, 0, 0, true}, {"stalled", false, 0, 0, 0, true}, {"unknown", false, 0, 0, 0, false},
	} {
		d := diagnoseTask(true, tc.paused, tc.calls, 1, 10, 300, tc.approvals, tc.tools, 250, tc.available)
		if d.Code != tc.code {
			t.Fatalf("%+v: %+v", tc, d)
		}
	}
}
func TestToolProgressTerminalCleanup(t *testing.T) {
	e := &Engine{}
	e.observeProgress("a", db.Activity{Kind: "tool_use", Worker: "one", ToolUseID: "x"})
	e.observeProgress("a", db.Activity{Kind: "tool_use", Worker: "two", ToolUseID: "x"})
	e.observeProgress("a", db.Activity{Kind: "tool_result", Worker: "one", ToolUseID: "x"})
	if n, _ := e.toolProgress("a"); n != 1 {
		t.Fatal(n)
	}
	e.observeProgress("a", db.Activity{Kind: "result", Worker: "two"})
	if n, _ := e.toolProgress("a"); n != 0 {
		t.Fatal(n)
	}
	if n, _ := e.toolProgress("b"); n != 0 {
		t.Fatal(n)
	}
}
