package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/honeydetect"
)

func TestFindingAutoReviewAPI(t *testing.T) {
	s, recorded, request := trafficEvidenceServer(t)
	id := recorded.FindingID
	base := fmt.Sprintf("/api/exploration/findings/%d/auto-review", id)
	if _, err := s.m.pg.Exec(`UPDATE findings SET evidence='offline observed evidence',vulnclass='XSS' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		t.Fatal(err)
	}
	check := func(method, want string) {
		t.Helper()
		w := request(method, base, "")
		var got struct {
			Fingerprint string              `json:"fingerprint"`
			Review      evidence.AutoReview `json:"review"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Review.Verdict != want || got.Fingerprint != db.FindingFingerprint(f) {
			t.Fatalf("review: %d %s", w.Code, w.Body)
		}
	}
	check("GET", "inconclusive")
	review := db.FindingReview{Fingerprint: db.FindingFingerprint(f), Verdict: "supported", Sources: "offline log", Reproduction: "observed baseline", CounterEvidence: "alternative explanations recorded"}
	if err := s.m.pg.SaveFindingReview(t.Context(), id, review); err != nil {
		t.Fatal(err)
	}
	check("POST", "supported")
	r, c, _, err := s.m.pg.CreateFindingRetest(t.Context(), id, "offline fixture only")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, c.ID) })
	check("GET", "inconclusive")
	if _, err := s.m.pg.Exec(`UPDATE finding_retests SET status='completed',verdict='fixed',summary='fixed fixture',evidence='offline result',snapshot=snapshot || '{"assets":[{"secret":"must-not-leak"}]}'::jsonb WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	check("GET", "inconclusive")
	current, retests, err := s.m.pg.FindingAutoReviewContext(t.Context(), id)
	if err != nil || len(retests) != 1 || strings.Contains(string(retests[0].Snapshot), "must-not-leak") || !evidence.RetestMatchesFinding(current, retests[0]) {
		t.Fatalf("snapshot not reduced/consistent: %v", err)
	}
	after, err := s.m.pg.GetFinding(id)
	if err != nil || after.Status != f.Status {
		t.Fatal("automatic review modified triage state", err)
	}
	if w := request("GET", "/api/exploration/findings/invalid/auto-review", ""); w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
	if w := request("GET", "/api/exploration/findings/9223372036854775807/auto-review", ""); w.Code != 404 {
		t.Fatal(w.Code, w.Body)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", base, nil))
	if w.Code != 401 {
		t.Fatal("unauthenticated auto-review accepted", w.Code)
	}
}

func TestHoneypotScanAPIAndPersistence(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	var id int64
	err := s.m.pg.QueryRow(`INSERT INTO assets(type,service_name,page_title,extra) VALUES('service','Cowrie SSH','Cowrie console','{"banner":"Cowrie service","owner_note":"preserve me"}') RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM assets WHERE id=$1`, id) })
	path := "/api/assets/honeypot-scan"
	w := request("POST", path, fmt.Sprintf(`{"ids":[%d,%d]}`, id, id))
	var got struct {
		Count   int `json:"count"`
		Results []struct {
			ID     int64              `json:"id"`
			Result honeydetect.Result `json:"result"`
		} `json:"results"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Count != 1 || len(got.Results) != 1 || got.Results[0].ID != id || !got.Results[0].Result.Matched {
		t.Fatal(w.Code, w.Body)
	}
	assets, err := s.assetStore().GetByIDs([]int64{id})
	if err != nil || len(assets) != 1 || assets[0].Extra["owner_note"] != "preserve me" || assets[0].Honeypot["fingerprint"] != got.Results[0].Result.Fingerprint {
		t.Fatal("assessment not persisted or unrelated metadata changed", err)
	}
	tooMany, _ := json.Marshal(map[string]any{"ids": make([]int64, 201)})
	for _, body := range []string{`{}`, `{"ids":[]}`, `{"ids":[0]}`, `{"ids":[-1]}`, `{"ids":["1"]}`, `{"ids":[1]} {}`, string(tooMany)} {
		if w := request("POST", path, body); w.Code != 400 {
			t.Fatalf("invalid body accepted: %s: %d", body, w.Code)
		}
	}
	if w := request("POST", path, `{"ids":[9223372036854775807]}`); w.Code != 404 {
		t.Fatal(w.Code, w.Body)
	}
	if err := s.assetStore().SetHoneypot(9223372036854775807, got.Results[0].Result); err == nil {
		t.Fatal("missing asset update reported success")
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(fmt.Sprintf(`{"ids":[%d]}`, id))))
	if w.Code != 401 {
		t.Fatal("unauthenticated assessment accepted", w.Code)
	}
}

func TestAutoRecoverySettingAPI(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	old, present, err := s.m.pg.GetSetting(settingAutoRecovery)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			s.m.pg.SetSetting(settingAutoRecovery, old)
		} else {
			s.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingAutoRecovery)
		}
	})
	for _, enabled := range []bool{false, true} {
		w := request("PUT", "/api/settings", fmt.Sprintf(`{"auto_recovery_enabled":%t}`, enabled))
		if w.Code != 200 || s.m.AutoRecoveryEnabled() != enabled {
			t.Fatal(w.Code, w.Body)
		}
		var settings map[string]any
		w = request("GET", "/api/settings", "")
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &settings) != nil || settings["auto_recovery_enabled"] != enabled {
			t.Fatal(w.Code, w.Body)
		}
	}
}
