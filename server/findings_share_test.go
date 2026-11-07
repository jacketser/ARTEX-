package server

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestFindingsShareExportAPI(t *testing.T) {
	s, finding, req := trafficEvidenceServer(t)
	key := "synthetic-export-credential,\"12345"
	previous, exists, err := s.m.pg.GetSetting(settingBraveKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if exists {
			_ = s.m.pg.SetSetting(settingBraveKey, previous)
		} else {
			_, _ = s.m.pg.Exec("DELETE FROM settings WHERE key=$1", settingBraveKey)
		}
	})
	if err := s.m.pg.SetSetting(settingBraveKey, key); err != nil {
		t.Fatal(err)
	}
	f, err := s.m.pg.GetFinding(finding.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(key))
	if _, err := s.m.pg.Exec("UPDATE findings SET name=$2,summary=$3,evidence=$2,report=$2 WHERE id=$1", f.ID, "ordinary "+key, encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec("UPDATE tasks SET description=$2 WHERE id=$1", *f.TaskID, key); err != nil {
		t.Fatal(err)
	}
	f, err = s.m.pg.GetFinding(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	review := db.FindingReview{Verdict: "supported", Fingerprint: db.FindingFingerprint(f), Sources: key, Reproduction: key, CounterEvidence: key, Limitations: key}
	if err := s.m.pg.SaveFindingReview(t.Context(), f.ID, review); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := s.m.pg.QueryRow("SELECT row_to_json(f)::text FROM findings f WHERE id=$1", f.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"md-single", "csv"} {
		for _, scope := range []string{"selected", "filtered", "all"} {
			path := fmt.Sprintf("/api/exploration/findings/export?format=%s&scope=%s&ids=%d&task_id=%d", format, scope, f.ID, *f.TaskID)
			w := req("GET", path, "")
			if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "findings-sanitized-") || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Artex-Export") == "" {
				t.Fatalf("download metadata: %d %v", w.Code, w.Header())
			}
			body := w.Body.String()
			if format == "csv" {
				rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(body, "\xef\xbb\xbf"))).ReadAll()
				if err != nil || len(rows) < 2 || len(rows[0]) != 13 {
					t.Fatal("CSV structure", scope, err)
				}
				found := false
				var cells []string
				for _, row := range rows[1:] {
					cells = append(cells, row...)
					if row[0] == fmt.Sprint(f.ID) {
						found = true
						if row[11] != "false" {
							t.Fatal("source review became stale", scope)
						}
					}
				}
				if !found {
					t.Fatal("selected finding missing", scope)
				}
				body = strings.Join(cells, "\n")
			}
			if strings.Contains(body, key) || strings.Contains(body, encoded) || !strings.Contains(body, "ordinary") || !strings.Contains(body, "脱敏分享副本") || (scope != "all" && strings.Contains(body, "复核已过期")) {
				t.Fatal("unsafe or incomplete share export", format, scope)
			}
		}
	}
	var after string
	if err := s.m.pg.QueryRow("SELECT row_to_json(f)::text FROM findings f WHERE id=$1", f.ID).Scan(&after); err != nil || after != before {
		t.Fatal("stored finding changed", err)
	}
	savedReview, err := s.m.pg.GetFindingReview(f.ID)
	if err != nil || savedReview.Fingerprint != review.Fingerprint || savedReview.Sources != key {
		t.Fatal("stored review changed", err)
	}
	// JSON deliberately stays outside this implementation's coverage.
	w := req("GET", fmt.Sprintf("/api/exploration/findings/export?format=json&scope=selected&ids=%d", f.ID), "")
	if w.Code != 200 || w.Header().Get("X-Artex-Export") != "" || !strings.Contains(w.Body.String(), encoded) {
		t.Fatal("JSON behavior or coverage label changed")
	}
	// A settings update must affect the very next export, with no secret cache.
	newKey := "synthetic-new-export-key-67890"
	if err := s.m.pg.SetSetting(settingBraveKey, newKey); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec("UPDATE findings SET name=$2 WHERE id=$1", f.ID, newKey); err != nil {
		t.Fatal(err)
	}
	w = req("GET", fmt.Sprintf("/api/exploration/findings/export?format=md-single&scope=selected&ids=%d", f.ID), "")
	if w.Code != 200 || strings.Contains(w.Body.String(), newKey) {
		t.Fatal("updated credential was not redacted")
	}

	// Break only the secret-source query in the disposable DB. Ordinary finding
	// loading still works, so this exercises the real endpoint's fail-closed path.
	if _, err := s.m.pg.Exec("ALTER TABLE llm_profiles RENAME TO share_test_profiles_unavailable"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := s.m.pg.Exec("ALTER TABLE share_test_profiles_unavailable RENAME TO llm_profiles"); err != nil {
			t.Error(err)
		}
	}()
	for _, format := range []string{"md-single", "csv"} {
		w := req("GET", fmt.Sprintf("/api/exploration/findings/export?format=%s&scope=selected&ids=%d", format, f.ID), "")
		if w.Code != 503 || w.Header().Get("Content-Disposition") != "" || strings.Contains(w.Body.String(), newKey) || strings.Contains(w.Body.String(), "share_test_profiles_unavailable") || !strings.Contains(w.Body.String(), "未生成导出文件") {
			t.Fatal("credential-source failure did not fail closed", w.Code)
		}
	}
}
