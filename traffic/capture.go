package traffic

import (
	"context"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

type captureContextKey struct{}

// SetCaptureEnabled controls persistence only. Proxy routing, credential checks
// and budgets remain active. Once disabling returns, no record writes continue.
func (t *Traffic) SetCaptureEnabled(enabled bool) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	state := t.captureState.Load()
	if (state&1 == 0) == enabled {
		return
	}
	next := (state &^ 1) + 2
	if !enabled {
		next |= 1
	}
	t.captureState.Store(next)
}

func (t *Traffic) CaptureEnabled() bool { return t.captureState.Load()&1 == 0 }

func (t *Traffic) markCapture(f *mproxy.Flow) {
	if raw := f.Request.Raw(); raw != nil {
		*raw = *raw.WithContext(context.WithValue(raw.Context(), captureContextKey{}, t.captureState.Load()))
	}
}

func (t *Traffic) captureAllowed(f *mproxy.Flow) bool {
	state := t.captureState.Load()
	if state&1 != 0 {
		return false
	}
	if f.Request != nil {
		if raw := f.Request.Raw(); raw != nil {
			if started, ok := raw.Context().Value(captureContextKey{}).(uint64); ok {
				return started == state
			}
		}
	}
	return true // synthetic/imported flows without a live request context
}

// Avoid buffering response bodies that cannot be saved. Request checks already
// ran in Requestheaders; this does not bypass credential or quota enforcement.
func (s *sink) Responseheaders(f *mproxy.Flow) {
	if !s.t.captureAllowed(f) {
		f.Stream = true
	}
}
