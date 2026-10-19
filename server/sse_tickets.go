package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const sseTicketTTL = 45 * time.Second
const maxSSETickets = 2048

type sseTicket struct {
	route, token string
	expires      time.Time
}
type sseTicketStore struct {
	mu      sync.Mutex
	tickets map[string]sseTicket
}

func sseRoute(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" || u.RawPath != "" {
		return "", false
	}
	valid := u.Path == "/api/logs/stream" || u.Path == "/api/update/stream" || u.Path == "/api/exploration/activity/stream"
	if strings.HasPrefix(u.Path, "/api/side-questions/") && strings.HasSuffix(u.Path, "/events") {
		id := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/api/side-questions/"), "/events")
		valid = id != "" && !strings.Contains(id, "/")
	}
	if !valid {
		return "", false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || q.Has("token") || q.Has("ticket") {
		return "", false
	}
	u.RawQuery = q.Encode()
	return u.String(), true
}
func (s *sseTicketStore) issue(route, token string, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tickets == nil {
		s.tickets = map[string]sseTicket{}
	}
	for key, t := range s.tickets {
		if !now.Before(t.expires) {
			delete(s.tickets, key)
		}
	}
	if len(s.tickets) >= maxSSETickets {
		return "", fmt.Errorf("too many pending tickets")
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	key := base64.RawURLEncoding.EncodeToString(secret[:])
	s.tickets[key] = sseTicket{route: route, token: token, expires: now.Add(sseTicketTTL)}
	return key, nil
}
func (s *sseTicketStore) consume(key, route string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[key]
	delete(s.tickets, key)
	return t.token, ok && t.route == route && now.Before(t.expires)
}
func (s *Server) issueSSETicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if decode(r, &req) != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	route, ok := sseRoute(req.Path)
	if !ok {
		writeErr(w, 400, "仅支持指定的实时事件接口")
		return
	}
	ticket, err := s.sseTickets.issue(route, extractToken(r), time.Now())
	if err != nil {
		writeErr(w, 503, "暂时无法签发票据")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"ticket": ticket, "expires_in": int(sseTicketTTL.Seconds())})
}

// Long-lived connections also lose access when their login expires or is revoked.
func (s *Server) serveAuthenticatedStream(h http.Handler, w http.ResponseWriter, r *http.Request, token string) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				ok, err := s.validSession(token)
				if err != nil || !ok {
					cancel()
					return
				}
			}
		}
	}()
	h.ServeHTTP(w, r.WithContext(ctx))
}
