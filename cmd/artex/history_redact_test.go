package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHistoryRedactRejectsUnsafeArgumentsBeforeDatabase(t *testing.T) {
	for _, args := range [][]string{{"-scope", "synthetic-secret"}, {"-apply", "synthetic-secret"}, {"extra-positional"}, {"-batch-size", "0"}, {"-batch-size", "10001"}, {"-cursor", "synthetic-secret"}, {"-scope", "evidence", "-migrate-legacy"}, {"-scope", "archive-traffic"}, {"-scope", "archive-evidence"}, {"-scope", "archive-evidence", "-archive-id", "1", "-migrate-legacy"}, {"-archive-id", "1"}, {"-scope", "archive-traffic", "-archive-id", "1", "-cursor", "synthetic-secret"}, {"-scope", "archive-traffic", "-archive-id", "1", "-migrate-legacy"}} {
		var out bytes.Buffer
		if got := runHistoryRedact(args, &out); got != 2 || strings.Contains(out.String(), "synthetic-secret") {
			t.Fatal(got, out.String())
		}
	}
	t.Setenv("ARTEX_PG_DSN", "postgres://unused:unused@127.0.0.1:1/unused?sslmode=disable")
	var out bytes.Buffer
	if got := runHistoryRedact([]string{"-apply", strings.Repeat("a", 64)}, &out); got != 2 || !strings.Contains(out.String(), "backup") {
		t.Fatal(got, out.String())
	}
}
