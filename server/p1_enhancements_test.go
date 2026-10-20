package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
)

func TestP1RecoveryObservationAndAlerts(t *testing.T) {
	s, recorded, request := trafficEvidenceServer(t)
	f, err := s.m.pg.GetFinding(recorded.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	taskID := fmt.Sprint(*f.TaskID)
	task, _ := s.m.Task(taskID)
	now := time.Now().Unix()
	old := db.TaskRecoveryState{}
	for attempt := 1; attempt <= 3; attempt++ {
		next := db.TaskRecoveryState{Attempts: attempt, LastAttempt: now + int64(attempt)*30}
		reserved, err := s.m.pg.ReserveTaskRecovery(t.Context(), taskID, old, next, 30)
		if err != nil || !reserved {
			t.Fatal(reserved, err)
		}
		if err = s.m.pg.UpdateRecoveryOutcomes(t.Context(), next.LastAttempt+30); err != nil {
			t.Fatal(err)
		}
		old = next
	}
	history, err := s.m.pg.RecoveryHistory(t.Context(), taskID, 0)
	if err != nil || len(history) != 3 || history[0].Status != "no_progress" {
		t.Fatal(history, err)
	}
	alerts, err := s.m.pg.RecoveryAlerts(t.Context())
	if err != nil || len(alerts) != 1 || alerts[0].TaskID != taskID {
		t.Fatal(alerts, err)
	}
	// A message clears attention but must not relabel a failed observation as success.
	if _, err = task.Store.AppendActivity(db.Activity{Worker: "user", Kind: "user", Summary: "manual follow-up"}); err != nil {
		t.Fatal(err)
	}
	alerts, err = s.m.pg.RecoveryAlerts(t.Context())
	if err != nil || len(alerts) != 0 {
		t.Fatal(alerts, err)
	}
	next := db.TaskRecoveryState{Attempts: 1, LastAttempt: now + 1000}
	reserved, err := s.m.pg.ReserveTaskRecovery(t.Context(), taskID, old, next, 30)
	if err != nil || !reserved {
		t.Fatal(reserved, err)
	}
	if _, err = task.Store.AppendActivity(db.Activity{Worker: "work#1", Kind: "result", Summary: "completed fixture"}); err != nil {
		t.Fatal(err)
	}
	if err = s.m.pg.UpdateRecoveryOutcomes(t.Context(), now+1001); err != nil {
		t.Fatal(err)
	}
	history, err = s.m.pg.RecoveryHistory(t.Context(), taskID, 0)
	if err != nil || history[0].Status != "recovered" {
		t.Fatal(history, err)
	}
	if w := request("GET", "/api/tasks/"+taskID+"/recovery-history", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := request("GET", "/api/recovery-alerts", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	// Pagination does not repeat the newest row.
	older, err := s.m.pg.RecoveryHistory(t.Context(), taskID, history[0].ID)
	if err != nil || len(older) != 3 {
		t.Fatal(older, err)
	}
}

func TestP1RecoveryDoesNotCountErrorsOrLateResults(t *testing.T) {
	s, recorded, _ := trafficEvidenceServer(t)
	f, err := s.m.pg.GetFinding(recorded.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	taskID := fmt.Sprint(*f.TaskID)
	task, _ := s.m.Task(taskID)
	now := time.Now().Unix()
	old := db.TaskRecoveryState{}
	next := db.TaskRecoveryState{Attempts: 1, LastAttempt: now}
	if ok, err := s.m.pg.ReserveTaskRecovery(t.Context(), taskID, old, next, 30); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, err := task.Store.AppendActivity(db.Activity{Worker: "work#1", Kind: "result", IsError: true, Summary: "failed fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.UpdateRecoveryOutcomes(t.Context(), now+1); err != nil {
		t.Fatal(err)
	}
	history, err := s.m.pg.RecoveryHistory(t.Context(), taskID, 0)
	if err != nil || history[0].Status != "observing" {
		t.Fatal(history, err)
	}
	// A successful result arriving after the deadline must not rewrite the observation as success.
	if _, err := s.m.pg.Exec(`UPDATE task_recovery_history SET observe_until=$2 WHERE task_id=$1`, taskID, now-1); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AppendActivity(db.Activity{Worker: "work#2", Kind: "result", Summary: "late fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.UpdateRecoveryOutcomes(t.Context(), now+2); err != nil {
		t.Fatal(err)
	}
	history, err = s.m.pg.RecoveryHistory(t.Context(), taskID, 0)
	if err != nil || history[0].Status != "no_progress" {
		t.Fatal(history, err)
	}
	old = next
	next = db.TaskRecoveryState{Attempts: 2, LastAttempt: now + 60}
	if ok, err := s.m.pg.ReserveTaskRecovery(t.Context(), taskID, old, next, 30); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, err := s.m.pg.Exec(`UPDATE tasks SET paused=true WHERE id=$1`, taskID); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.UpdateRecoveryOutcomes(t.Context(), now+61); err != nil {
		t.Fatal(err)
	}
	history, err = s.m.pg.RecoveryHistory(t.Context(), taskID, 0)
	if err != nil || history[0].Status != "interrupted" {
		t.Fatal(history, err)
	}
}

func TestP1RecoveryConfigValidation(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM settings WHERE key='auto_recovery_config'`) })
	for _, body := range []string{`{"after_seconds":0,"cooldown_seconds":300,"observe_seconds":30}`, `{"after_seconds":120,"cooldown_seconds":30,"observe_seconds":60}`, `{"after_seconds":120,"cooldown_seconds":90000,"observe_seconds":30}`} {
		if w := request("PUT", "/api/settings/auto-recovery", body); w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if w := request("PUT", "/api/settings/auto-recovery", `{"after_seconds":45,"cooldown_seconds":90,"observe_seconds":60}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	cfg, err := s.recoveryConfig()
	if err != nil || cfg.AfterSeconds != 45 || cfg.CooldownSeconds != 90 {
		t.Fatal(cfg, err)
	}
	if !canAutoRecover(recoveryObservation{Ready: true, Pending: 1, Last: 1, Now: 50, After: 45}) {
		t.Fatal("configured threshold ignored")
	}
	if _, due := nextRecoveryState(db.TaskRecoveryState{LastAttempt: 100}, 0, 150, 90); due {
		t.Fatal("configured cooldown ignored")
	}
}

func TestP1HoneypotStalenessReviewAndFilter(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	var id int64
	if err := s.m.pg.QueryRow(`INSERT INTO assets(type,service_name,page_title,extra) VALUES('service','Cowrie','Cowrie console','{"owner_note":"preserved"}') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM assets WHERE id=$1`, id) })
	store := s.assetStore()
	if err := store.RefreshHoneypots(t.Context()); err != nil {
		t.Fatal(err)
	}
	items, err := store.GetByIDs([]int64{id})
	if err != nil || len(items) != 1 {
		t.Fatal(err)
	}
	fingerprint := items[0].Honeypot["fingerprint"].(string)
	body, _ := json.Marshal(map[string]string{"fingerprint": fingerprint, "verdict": "excluded", "note": "product documentation only"})
	path := fmt.Sprintf("/api/assets/%d/honeypot-review", id)
	if w := request("PUT", path, string(body)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	count, err := store.CountDSL("honeypot==excluded", "service", 0)
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if _, err = s.m.pg.Exec(`UPDATE assets SET page_title='ordinary console',service_name='http' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	items, err = store.GetByIDs([]int64{id})
	if err != nil || items[0].Honeypot["stale"] != true || items[0].HoneypotReview["stale"] != true {
		t.Fatal(items, err)
	}
	if w := request("PUT", path, string(body)); w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
	if err = store.RefreshHoneypots(t.Context()); err != nil {
		t.Fatal(err)
	}
	items, err = store.GetByIDs([]int64{id})
	if err != nil || items[0].Honeypot["matched"] != false || items[0].Honeypot["stale"] != false || items[0].HoneypotReview["stale"] != true || items[0].Extra["owner_note"] != "preserved" {
		t.Fatal(items, err)
	}
	count, err = store.CountDSL("honeypot==excluded", "service", 0)
	if err != nil || count != 0 {
		t.Fatal(count, err)
	}
	var pending int
	if err = s.m.pg.QueryRow(`SELECT count(*) FROM asset_honeypot_pending WHERE asset_id=$1`, id).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("assessment requeued itself", pending, err)
	}
}

func TestP1ReviewHistoryAndComparison(t *testing.T) {
	s, f, request := trafficEvidenceServer(t)
	seedServerEvidenceFlow(t, s, "p1-baseline", []byte("first response"))
	seedServerEvidenceFlow(t, s, "p1-proof", []byte("first DIFFERENT response"))
	base := fmt.Sprintf("/api/exploration/findings/%d", f.FindingID)
	if w := request("POST", base+"/traffic", `{"traffic_refs":[{"traffic_id":"p1-baseline","role":"baseline"},{"traffic_id":"p1-proof","role":"proof"}]}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w := request("GET", base+"/auto-review", "")
	var out struct {
		Fingerprint string              `json:"fingerprint"`
		Review      evidence.AutoReview `json:"review"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Review.Comparisons) != 1 {
		t.Fatal(w.Code, w.Body)
	}
	comparison := out.Review.Comparisons[0]
	if comparison.Bodies[1].Status != "different" || comparison.Bodies[1].FirstDifference == nil || *comparison.Bodies[1].FirstDifference != 6 {
		t.Fatal(comparison)
	}
	if strings.Contains(w.Body.String(), "DIFFERENT response") {
		t.Fatal("comparison leaked body")
	}
	rows, err := s.m.pg.FindingReviewHistory(t.Context(), f.FindingID, 0)
	if err != nil || len(rows) != 0 {
		t.Fatal("read created history", err)
	}
	if w = request("POST", base+"/auto-review", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	body, _ := json.Marshal(db.FindingReview{Fingerprint: out.Fingerprint, Verdict: "inconclusive", Limitations: "offline only"})
	if w = request("PUT", base+"/review", string(body)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	rows, err = s.m.pg.FindingReviewHistory(t.Context(), f.FindingID, 0)
	if err != nil || len(rows) != 2 || rows[0].Kind != "manual" || rows[1].Kind != "automatic" {
		t.Fatal(rows, err)
	}
	if w = request("GET", base+"/review-history", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	child, err := s.m.CreateTaskWithOptions("inherited P1 fixture", "fixture", db.TaskCreateOptions{SourceTaskIDs: []int64{*finding.TaskID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.DeleteTask(child.ID, DeleteTaskOptions{}) })
	if w = request("POST", base+"/auto-review?context_task="+child.ID, ""); w.Code != 403 {
		t.Fatal("inherited findings must not append reviews", w.Code, w.Body)
	}
	if w = request("GET", base+"/auto-review?context_task="+child.ID, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	// Later source changes cannot make a new saved automatic review claim the old fingerprint is current.
	if _, err = s.m.pg.Exec(`UPDATE findings SET severity='high' WHERE id=$1`, f.FindingID); err != nil {
		t.Fatal(err)
	}
	if err = s.m.pg.SaveAutomaticReview(t.Context(), f.FindingID, out.Fingerprint, out.Review); err != db.ErrReviewStale {
		t.Fatal(err)
	}
}
