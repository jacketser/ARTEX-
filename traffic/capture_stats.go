package traffic

import (
	"sync/atomic"
	"time"
)

// CaptureStage reports cumulative wall time, not CPU time. Concurrent phases
// overlap; callers must use deltas and must not sum them as elapsed runtime.
type CaptureStage struct {
	Calls       uint64 `json:"calls"`
	Nanoseconds uint64 `json:"nanoseconds"`
}
type captureStage struct{ calls, nanos atomic.Uint64 }

func (s *captureStage) observe(start time.Time) {
	s.nanos.Add(uint64(time.Since(start)))
	s.calls.Add(1)
}
func (s *captureStage) snapshot() CaptureStage { return CaptureStage{s.calls.Load(), s.nanos.Load()} }

type captureMetrics struct {
	admit, redact, wait, prepare, sql, commit captureStage
	written, failed                           atomic.Uint64
}

// CaptureStats contains counters only: never URLs, headers, bodies or credentials.
func (t *Traffic) CaptureStats() map[string]any {
	m := &t.captureMetrics
	return map[string]any{"stages": map[string]CaptureStage{"admit": m.admit.snapshot(), "redact": m.redact.snapshot(), "wait": m.wait.snapshot(), "prepare": m.prepare.snapshot(), "sql": m.sql.snapshot(), "commit": m.commit.snapshot()}, "written": m.written.Load(), "failed": m.failed.Load()}
}
