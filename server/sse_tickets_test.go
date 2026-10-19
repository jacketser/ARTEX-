package server

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestSSETicketBoundaries(t *testing.T) {
	var store sseTicketStore
	now := time.Now()
	route := "/api/logs/stream?since=1"
	key, err := store.issue(route, "session", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.consume(key, "/api/update/stream", now); ok {
		t.Fatal("cross-route ticket accepted")
	}
	if _, ok := store.consume(key, route, now); ok {
		t.Fatal("ticket replay accepted")
	}
	key, _ = store.issue(route, "session", now)
	if _, ok := store.consume(key, route, now.Add(sseTicketTTL)); ok {
		t.Fatal("expired ticket accepted")
	}
	key, _ = store.issue(route, "session", now)
	if token, ok := store.consume(key, route, now); !ok || token != "session" {
		t.Fatal("valid ticket rejected")
	}
	if _, ok := store.consume(key, route, now); ok {
		t.Fatal("consumed ticket accepted")
	}
	for _, path := range []string{"/api/settings", "https://example.com/api/logs/stream", "//example.com/api/logs/stream", "/api/logs/stream?token=secret", "/api/logs/stream?ticket=x", "/api/side-questions/a/b/events"} {
		if _, ok := sseRoute(path); ok {
			t.Fatalf("invalid route accepted: %s", path)
		}
	}
	if extractToken(httptest.NewRequest("GET", "/api/logs/stream?token=secret", nil)) != "" {
		t.Fatal("JWT URL accepted")
	}
}
func TestSSETicketCapacity(t *testing.T) {
	var store sseTicketStore
	now := time.Now()
	for i := 0; i < maxSSETickets; i++ {
		if _, err := store.issue("route", "token", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.issue("route", "token", now); err == nil {
		t.Fatal("unbounded ticket store")
	}
	if _, err := store.issue("route", "token", now.Add(sseTicketTTL)); err != nil {
		t.Fatal("expired tickets not reclaimed")
	}
}
