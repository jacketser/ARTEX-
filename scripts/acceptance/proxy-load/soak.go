package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

type corpusItem struct {
	ID, Marker        string
	ContentType       string `json:"content_type"`
	Request, Response []byte `json:"-"`
}

var corpusOnce sync.Once
var corpus []corpusItem

func loadCorpus() []corpusItem {
	corpusOnce.Do(func() {
		b, e := os.ReadFile("/load/corpus.json")
		must(e)
		var manifest struct {
			Items []struct {
				ID, Marker, Request, Response string
				ContentType                   string `json:"content_type"`
			}
		}
		must(json.Unmarshal(b, &manifest))
		for _, item := range manifest.Items {
			corpus = append(corpus, corpusItem{ID: item.ID, Marker: item.Marker, ContentType: item.ContentType,
				Request: []byte(item.Request), Response: []byte(item.Response)})
		}
		if len(corpus) != 8 {
			panic("expected eight corpus pairs")
		}
	})
	return corpus
}
func corpusByID(id string) (corpusItem, bool) {
	for _, c := range loadCorpus() {
		if c.ID == id {
			return c, true
		}
	}
	return corpusItem{}, false
}
func boundedEnv(key string, fallback, maximum int) int {
	if value := os.Getenv(key); value != "" {
		n, e := strconv.Atoi(value)
		if e != nil || n < 1 || n > maximum {
			panic("invalid " + key)
		}
		return n
	}
	return fallback
}
func (d *driver) runSoak() {
	windows := boundedEnv("ARTEX_SOAK_WINDOWS", 20, 120)
	seconds := boundedEnv("ARTEX_SOAK_SECONDS", 60, 300)
	rate := boundedEnv("ARTEX_SOAK_RPS", 8, 30)
	items := loadCorpus()
	// Exercise all corpus pairs before the timed windows, including short smoke runs.
	for i, item := range items {
		d.runCase(scenario{Name: fmt.Sprintf("corpus-smoke-%d", i), Corpus: item.ID, Scheme: "https", Proxy: true, Capture: true, Upstream: true, Concurrency: 2, Requests: 4})
	}
	for i := 0; i < windows; i++ {
		item := items[i%len(items)]
		scheme := "https"
		if i%4 < 2 {
			scheme = "http"
		}
		d.runCase(scenario{Name: fmt.Sprintf("soak-%03d-%s", i, scheme), Corpus: item.ID, Scheme: scheme, Proxy: true, Capture: true, Upstream: true, Concurrency: 4, Requests: rate*seconds + 8, Seconds: seconds, Rate: rate})
		writeArtifact("soak-progress.json", map[string]any{"completed_windows": i + 1, "requested_windows": windows, "window_seconds": seconds, "rate_rps": rate, "refreshes": d.refreshCount})
	}
	d.verifyCorpusSearch()
	if windows*seconds > 15*60 && d.refreshCount < 1 {
		panic("long run did not refresh authentication")
	}
}
func writeArtifact(name string, value any) {
	b, e := json.MarshalIndent(value, "", "  ")
	must(e)
	must(os.WriteFile("/load/"+name, b, 0600))
}
func (d *driver) verifyCorpusSearch() {
	expected := map[string]int{}
	for _, r := range d.results {
		if r.Scenario.Corpus != "" {
			expected[r.Scenario.Corpus] += r.Requests
		}
	}
	for _, item := range loadCorpus() {
		var response struct{ Total int }
		d.api("GET", "/api/traffic?size=1&body="+url.QueryEscape(item.Marker), nil, &response)
		if response.Total != expected[item.ID] {
			panic(fmt.Sprintf("corpus fulltext mismatch %s: %d != %d", item.ID, response.Total, expected[item.ID]))
		}
	}
}
func verifyRestart() {
	d := &driver{apiClient: &http.Client{Timeout: 30 * time.Second}}
	var auth struct{ Token string }
	d.api("POST", "/api/auth/login", map[string]string{"username": "ARTEX", "password": "synthetic-proxy-load-password"}, &auth)
	d.token, d.refreshed = auth.Token, time.Now()
	b, e := os.ReadFile("/load/results.json")
	must(e)
	must(json.Unmarshal(b, &d.results))
	var offline struct{ Rows int }
	b, e = os.ReadFile("/load/offline-integrity.json")
	must(e)
	must(json.Unmarshal(b, &offline))
	if d.count() != offline.Rows {
		panic("restart lost rows")
	}
	d.verifyCorpusSearch()
	var health map[string]any
	d.api("GET", "/api/health", nil, &health)
	writeArtifact("restart-check.json", map[string]any{"rows": offline.Rows, "fulltext_verified": true, "health": health})
	fmt.Printf("Restart preserved %d rows and all corpus fulltext matches\n", offline.Rows)
}
