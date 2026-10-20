package server

import (
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/honeydetect"
	"github.com/Autumn-27/artex/notify"
	"github.com/Autumn-27/artex/scenarioprompt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnhancementSettingsAndTLSInvalidation(t *testing.T) {
	s, _, req := trafficEvidenceServer(t)
	pg := s.m.pg
	for _, key := range []string{db.HoneyRulesKey, db.ScenarioKey, "freeze_compensation"} {
		old, ok, err := pg.GetSetting(key)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if ok {
				pg.SetSetting(key, old)
			} else {
				pg.Exec(`DELETE FROM settings WHERE key=$1`, key)
			}
		})
	}
	paths := []string{"/api/settings/honeypot-rules", "/api/settings/scenario-prompts", "/api/settings/freeze-compensation"}
	for _, path := range paths {
		w := req("GET", path, "")
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body)
		}
		saved := w.Body.String()
		if w = req("PUT", path, saved); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		for _, bad := range []string{`{}`, saved + ` {}`, `{"unknown":true}`} {
			if w = req("PUT", path, bad); w.Code != 400 {
				t.Fatal("invalid configuration accepted", path, w.Code, w.Body)
			}
		}
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Fatal("unauthenticated", path, w.Code)
		}
	}
	var id int64
	if err := pg.QueryRow(`INSERT INTO assets(type,extra) VALUES('service','{"tls_subject":"CN=Cowrie fixture"}') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM assets WHERE id=$1`, id) })
	first, err := s.assetStore().AssessHoneypot(t.Context(), id, nil)
	if err != nil || !first.Matched {
		t.Fatal(first, err)
	}
	if _, err := s.assetStore().AssessHoneypot(t.Context(), id, map[string]string{"fingerprint": first.Fingerprint, "verdict": "excluded", "note": "fixture review"}); err != nil {
		t.Fatal(err)
	}
	rules := honeydetect.DefaultRules()
	rules.Rules[0].Source = "updated test reference"
	b, _ := json.Marshal(rules)
	if w := req("PUT", paths[0], string(b)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var stale bool
	if err := pg.QueryRow(`SELECT (extra->>'honeypot_stale')::boolean FROM assets WHERE id=$1`, id).Scan(&stale); err != nil || !stale {
		t.Fatal(stale, err)
	}
	next, err := s.assetStore().AssessHoneypot(t.Context(), id, nil)
	if err != nil || next.Fingerprint == first.Fingerprint {
		t.Fatal(next, err)
	}
	// Restoring old rules must not silently reactivate a superseded manual review.
	b, _ = json.Marshal(honeydetect.DefaultRules())
	if w := req("PUT", paths[0], string(b)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	restored, err := s.assetStore().AssessHoneypot(t.Context(), id, nil)
	if err != nil || restored.Fingerprint != first.Fingerprint {
		t.Fatal(restored, err)
	}
	var reviewStale bool
	if err := pg.QueryRow(`SELECT (extra->'honeypot_review'->>'stale')::boolean FROM assets WHERE id=$1`, id).Scan(&reviewStale); err != nil || !reviewStale {
		t.Fatal("old review reactivated", reviewStale, err)
	}
	if _, err := s.assetStore().AssessHoneypot(t.Context(), id, map[string]string{"fingerprint": restored.Fingerprint, "verdict": "excluded", "note": "fresh review"}); err != nil {
		t.Fatal(err)
	}
	// Saving unchanged rules is a no-op for current conclusions.
	if w := req("PUT", paths[0], string(b)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if err := pg.QueryRow(`SELECT (extra->'honeypot_review'->>'stale')::boolean FROM assets WHERE id=$1`, id).Scan(&reviewStale); err != nil || reviewStale {
		t.Fatal(reviewStale, err)
	}
	cfg := scenarioprompt.Default()
	cfg.MaxCategories = 1
	cfg.Profiles[0].Prompt = "custom evidence guidance"
	b, _ = json.Marshal(cfg)
	if w := req("PUT", paths[1], string(b)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w := req("POST", paths[1]+"/preview", `{"summary":"API","chain_tags":["web"]}`)
	var preview scenarioprompt.Selection
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &preview) != nil || len(preview.Tags) != 1 || preview.Tags[0] != "web" {
		t.Fatal(w.Code, w.Body)
	}
	for _, body := range []string{`{"chain_tags":["bad"]}`, `{"chain_tags":["web","web"]}`} {
		if w := req("POST", paths[1]+"/preview", body); w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if w := req("GET", "/api/clock-compensations?before=-1", ""); w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestRecoveryNoticeDedupOptInAndAcknowledgement(t *testing.T) {
	s, rec, req := trafficEvidenceServer(t)
	pg := s.m.pg
	f, _ := pg.GetFinding(rec.FindingID)
	id := fmt.Sprint(*f.TaskID)
	old := db.TaskRecoveryState{}
	now := time.Now().Unix()
	for attempt := 1; attempt <= 3; attempt++ {
		next := db.TaskRecoveryState{Attempts: attempt, LastAttempt: now + int64(attempt)*30}
		if ok, err := pg.ReserveTaskRecovery(t.Context(), id, old, next, 30); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if err := pg.UpdateRecoveryOutcomes(t.Context(), next.LastAttempt+30); err != nil {
			t.Fatal(err)
		}
		old = next
	}
	history, err := pg.RecoveryHistory(t.Context(), id, 0)
	if err != nil {
		t.Fatal(err)
	}
	hid := history[0].ID
	t.Cleanup(func() {
		pg.Exec(`DELETE FROM notification_events WHERE kind=$1 AND snapshot->>'task_id'=$2`, notify.EventRecoveryExhausted, id)
	})
	// Persisted deduplication: repeat scheduler passes produce one event.
	for range 3 {
		if err := pg.QueueRecoveryNotifications(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var event int64
	var count int
	if err := pg.QueryRow(`SELECT count(*),max(id) FROM notification_events WHERE kind=$1 AND snapshot->>'task_id'=$2`, notify.EventRecoveryExhausted, id).Scan(&count, &event); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	channels := []db.NotificationChannel{
		{Name: "default", Kind: "webhook", Mode: "realtime", Config: json.RawMessage(`{"url":"http://127.0.0.1:1"}`), Filter: json.RawMessage(`{}`)},
		{Name: "opt-in", Kind: "webhook", Mode: "realtime", Config: json.RawMessage(`{"url":"http://127.0.0.1:1"}`), Filter: json.RawMessage(`{"on_recovery_failure":true}`)},
		{Name: "digest", Kind: "webhook", Mode: "digest", Config: json.RawMessage(`{"url":"http://127.0.0.1:1"}`), Filter: json.RawMessage(`{"on_recovery_failure":true}`)},
	}
	for i := range channels {
		cid, err := pg.SaveNotificationChannel(t.Context(), &channels[i])
		if err != nil {
			t.Fatal(err)
		}
		channels[i].ID = cid
		t.Cleanup(func() { pg.DeleteNotificationChannel(t.Context(), cid) })
	}
	if _, _, err := pg.FanOutPendingEvents(t.Context(), 1000); err != nil {
		t.Fatal(err)
	}
	var cid int64
	if err := pg.QueryRow(`SELECT count(*),max(channel_id) FROM notification_deliveries WHERE event_id=$1`, event).Scan(&count, &cid); err != nil || count != 1 || cid != channels[1].ID {
		t.Fatal(count, cid, err)
	}
	if w := req("POST", "/api/tasks/"+id+"/recovery-ack", fmt.Sprintf(`{"history_id":%d,"note":"已检查，等待补充配置"}`, hid)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	alerts, err := pg.RecoveryAlerts(t.Context())
	if err != nil || len(alerts) != 0 {
		t.Fatal(alerts, err)
	}
	history, err = pg.RecoveryHistory(t.Context(), id, 0)
	if err != nil || history[0].AcknowledgedNote != "已检查，等待补充配置" || history[0].Status != "no_progress" {
		t.Fatal(history, err)
	}
	state, _ := pg.GetTaskRecoveryState(t.Context(), id)
	if state.Attempts != 3 {
		t.Fatal("ack reset recovery budget")
	}
}
