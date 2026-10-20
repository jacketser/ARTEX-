package traffic

import (
	"context"
	"errors"
	"net/url"
	"time"
)

// AdmitDiagnosticRequest reuses mandatory guard budgets for the bounded manual
// probe transport (DNS pinned, strict TLS). The probe stores summaries, not traffic.
func (t *Traffic) AdmitDiagnosticRequest(ctx context.Context, method, raw string) error {
	if t.security.unavailable.Load() {
		t.security.block("policy_unavailable")
		return errors.New("policy unavailable")
	}
	u, e := url.Parse(raw)
	if e != nil {
		return e
	}
	keys, e := t.secrets(ctx)
	if e != nil {
		t.security.block("secret_source_unavailable")
		return e
	}
	if containsSecret([]byte(raw), keys) {
		t.security.block("platform_credential")
		return errors.New("credential blocked")
	}
	if why, _ := t.security.admitTask("", canonicalAuthority(u), method, u.RequestURI(), time.Now()); why != "" {
		t.security.block(why)
		return errors.New("request budget exceeded")
	}
	t.security.allowed.Add(1)
	return nil
}
