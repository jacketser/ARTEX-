package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

// Use the application's SQLite version: system SQLite may not support
// contentless_delete. The fixed path is a stopped, isolated fixture snapshot.
func verifyStore() {
	db, e := sql.Open("sqlite", "file:/load/index-snapshot/index.sqlite?mode=ro")
	must(e)
	defer db.Close()
	var integrity string
	must(db.QueryRow("PRAGMA integrity_check").Scan(&integrity))
	if integrity != "ok" {
		panic("SQLite integrity failure")
	}
	checks, e := db.Query("PRAGMA foreign_key_check")
	must(e)
	if checks.Next() {
		panic("foreign key failure")
	}
	must(checks.Err())
	checks.Close()
	b, e := os.ReadFile("/load/results.json")
	must(e)
	var results []result
	must(json.Unmarshal(b, &results))
	expected := map[string]int{}
	for _, r := range results {
		if r.Scenario.Corpus != "" {
			expected[r.Scenario.Corpus] += r.Requests
		}
	}
	seen := map[string]int{}
	rows, e := db.Query(`SELECT e.req_len,e.resp_len,b.req_head,b.req_body,b.req_blob,b.resp_body,b.resp_blob
FROM exchanges e LEFT JOIN exchange_bodies b ON b.id=e.id`)
	must(e)
	count, corpusCount := 0, 0
	for rows.Next() {
		var reqLen, respLen int
		var head string
		var req, resp []byte
		var reqBlob, respBlob sql.NullString
		must(rows.Scan(&reqLen, &respLen, &head, &req, &reqBlob, &resp, &respBlob))
		count++
		headers := map[string]string{}
		for _, line := range strings.Split(head, "\n")[1:] {
			if k, v, ok := strings.Cut(line, ": "); ok {
				headers[k] = v
			}
		}
		id := headers["X-Load-Corpus"]
		if id == "" {
			if !strings.HasPrefix(headers["X-Load-Case"], "guard-") {
				panic("unexpected extra record")
			}
			continue
		}
		item, ok := corpusByID(id)
		if !ok || reqBlob.Valid || respBlob.Valid || reqLen != len(req) || respLen != len(resp) ||
			digest(req) != digest(item.Request) || digest(resp) != digest(item.Response) {
			panic("stored corpus body differs")
		}
		if headers["Authorization"] != "[REDACTED]" {
			panic("stored target credential not redacted")
		}
		seen[id]++
		corpusCount++
	}
	must(rows.Err())
	rows.Close()
	for _, item := range loadCorpus() {
		if seen[item.ID] != expected[item.ID] {
			panic("stored corpus counts differ")
		}
		var n int
		must(db.QueryRow(`SELECT count(*) FROM ex_fts WHERE ex_fts MATCH ?`, `"`+item.Marker+`"`).Scan(&n))
		if n != expected[item.ID] {
			panic("fulltext count mismatch")
		}
	}
	var guard struct{ Ordinary int }
	b, e = os.ReadFile("/load/guard.json")
	must(e)
	must(json.Unmarshal(b, &guard))
	if count != corpusCount+guard.Ordinary {
		panic("unexpected total count")
	}
	for _, table := range []string{"exchange_bodies", "ex_fts"} {
		var n int
		must(db.QueryRow("SELECT count(*) FROM " + table).Scan(&n))
		if n != count {
			panic("body/index count mismatch")
		}
	}
	writeArtifact("offline-integrity.json", map[string]any{"rows": count, "corpus_rows": corpusCount, "corpus_counts": seen,
		"sqlite_integrity": "ok", "all_corpus_body_hashes_verified": true, "fulltext_counts_verified": true, "target_authorization_redacted": true})
	fmt.Printf("Offline integrity: %d rows; every corpus request/response hash and fulltext count verified\n", count)
}
