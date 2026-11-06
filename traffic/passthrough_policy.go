package traffic

import (
	"context"
	"crypto/sha256"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type passthroughContextKey struct{}

const failedAuthorityTTL = 5 * time.Minute

func (t *Traffic) markUninspectable(authority string, now time.Time) {
	g := &t.security
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failedAuthorities == nil {
		g.failedAuthorities = map[string]time.Time{}
	}
	for key, until := range g.failedAuthorities {
		if !now.Before(until) {
			delete(g.failedAuthorities, key)
		}
	}
	if _, exists := g.failedAuthorities[authority]; !exists && len(g.failedAuthorities) >= 4096 {
		return // no fallback permission is granted when the bounded registry is full
	}
	g.failedAuthorities[authority] = now.Add(failedAuthorityTTL)
	sum := sha256.Sum256([]byte(authority))
	log.Printf("[security] HTTPS inspection failure authority_hash=%x; subsequent CONNECT follows configured policy", sum[:6])
}

func (t *Traffic) uninspectable(authority string, now time.Time) bool {
	g := &t.security
	g.mu.Lock()
	defer g.mu.Unlock()
	until, found := g.failedAuthorities[authority]
	if found && !now.Before(until) {
		delete(g.failedAuthorities, authority)
		return false
	}
	return found
}

// The dependency's auth hook rejects BEFORE opening an upstream connection and
// emits HTTP 407. Do not write a second status/body here; expose the precise
// policy category in headers and aggregate stats instead of claiming bad login.
func (t *Traffic) denyConnect(w http.ResponseWriter, reason string, retry int) (bool, error) {
	t.security.block(reason)
	w.Header().Set("X-Artex-Security", reason)
	w.Header().Set("Cache-Control", "no-store")
	if retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
	}
	return false, errors.New("ARTEX CONNECT policy: " + reason)
}

func (t *Traffic) admitConnect(w http.ResponseWriter, r *http.Request, task string) (bool, error) {
	if t.security.unavailable.Load() {
		return t.denyConnect(w, "policy_unavailable", 0)
	}
	u := &url.URL{Scheme: "https", Host: r.Host}
	authority := canonicalAuthority(u)
	if !t.uninspectable(authority, time.Now()) {
		return true, nil
	}
	if t.SecurityConfig().PassthroughMode != "allow" {
		return t.denyConnect(w, "passthrough_blocked", 0)
	}
	keys, err := t.secrets(r.Context())
	if err != nil {
		return t.denyConnect(w, "secret_source_unavailable", 0)
	}
	if containsSecret([]byte(r.Host+"\n"+headerLines(r.Header)), keys) {
		return t.denyConnect(w, "platform_credential", 0)
	}
	if why, retry := t.security.admitTask(task, authority, "CONNECT", "", time.Now()); why != "" {
		return t.denyConnect(w, why, retry)
	}
	// Recheck the mode after potentially blocking DB reads. Existing tunnels are
	// not terminated on policy updates; all decisions here apply to new CONNECTs.
	g := &t.security
	g.mu.Lock()
	if g.policyLocked().PassthroughMode != "allow" || g.unavailable.Load() {
		g.mu.Unlock()
		return t.denyConnect(w, "passthrough_blocked", 0)
	}
	g.passthroughAllowed++
	g.mu.Unlock()
	*r = *r.WithContext(context.WithValue(r.Context(), passthroughContextKey{}, true))
	return true, nil
}
