package traffic

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func captureWait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("capture condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestCaptureBatchAtomicFailureAndRecovery(t *testing.T) {
	tr, _ := openTraffic(t)
	jobs := []*captureJob{}
	body := append([]byte("searchable fixture "), bytes.Repeat([]byte("x"), maxInlineBody)...)
	for _, path := range []string{"/good", "/reject"} {
		jobs = append(jobs, &captureJob{flow: newFlow("fixture.test", "POST", path, nil, body), epoch: tr.captureState.Load(), queued: time.Now()})
	}
	if _, e := tr.db.Exec(`CREATE TRIGGER reject_capture BEFORE INSERT ON exchanges WHEN NEW.url LIKE '%/reject' BEGIN SELECT RAISE(ABORT,'fixture failure'); END`); e != nil {
		t.Fatal(e)
	}
	tr.writeCaptureBatch(jobs)
	for _, table := range []string{"exchanges", "exchange_bodies", "blob_refs", "ex_fts"} {
		var n int
		if e := tr.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != 0 {
			t.Fatal("partial batch persisted", table, n, e)
		}
	}
	if tr.captureMetrics.written.Load() != 0 || tr.captureMetrics.failed.Load() != 2 {
		t.Fatal("failure counted as saved")
	}
	if _, e := tr.db.Exec(`DROP TRIGGER reject_capture`); e != nil {
		t.Fatal(e)
	}
	tr.writeCaptureBatch(jobs)
	if n, e := tr.Count(); e != nil || n != 2 {
		t.Fatal("writer did not recover", n, e)
	}
	if tr.captureMetrics.commit.calls.Load() != 1 || tr.captureMetrics.written.Load() != 2 {
		t.Fatal("records not committed as one batch")
	}
	var refs int
	if e := tr.db.QueryRow(`SELECT count(*) FROM blob_refs`).Scan(&refs); e != nil || refs != 2 {
		t.Fatal("shared body references not restored", refs, e)
	}
	rows, e := tr.query("fixture.test", "", "searchable", 0, 10)
	if e != nil || len(rows) != 2 {
		t.Fatal("fulltext index inconsistent", e)
	}
}
func TestCaptureBlobFailureDoesNotSaveTruncatedEvidence(t *testing.T) {
	tr, dir := openTraffic(t)
	if e := os.WriteFile(filepath.Join(dir, "_blobs", "sha256"), []byte("obstruction"), 0600); e != nil {
		t.Fatal(e)
	}
	tr.record(newFlow("fixture.test", "POST", "/large", nil, bytes.Repeat([]byte("x"), maxInlineBody+1)))
	if n, e := tr.Count(); e != nil || n != 0 {
		t.Fatal("truncated body recorded as complete", n, e)
	}
	if tr.captureMetrics.failed.Load() != 1 {
		t.Fatal("blob failure missing")
	}
	if e := os.Remove(filepath.Join(dir, "_blobs", "sha256")); e != nil {
		t.Fatal(e)
	}
	tr.record(newFlow("fixture.test", "POST", "/large", nil, bytes.Repeat([]byte("x"), maxInlineBody+1)))
	if n, e := tr.Count(); e != nil || n != 1 {
		t.Fatal("recovery failed", n, e)
	}
}
func TestCaptureQueuedBeforeToggleNeverReappears(t *testing.T) {
	tr, _ := openTraffic(t)
	arrived, release := make(chan struct{}), make(chan struct{})
	tr.SetSecretSource(func(context.Context) ([]string, error) { close(arrived); <-release; return nil, nil })
	done := make(chan struct{})
	go func() { tr.record(newFlow("fixture.test", "GET", "/old", nil, []byte("old response"))); close(done) }()
	<-arrived
	tr.SetCaptureEnabled(false)
	tr.SetCaptureEnabled(true)
	close(release)
	<-done
	if n, e := tr.Count(); e != nil || n != 0 {
		t.Fatal("old-generation capture reappeared", n, e)
	}
	tr.SetSecretSource(nil)
	tr.record(newFlow("fixture.test", "GET", "/new", nil, []byte("new response")))
	if n, e := tr.Count(); e != nil || n != 1 {
		t.Fatal("new generation not captured", n, e)
	}
}
func TestCaptureAdmissionAndCloseDrain(t *testing.T) {
	for _, large := range []bool{false, true} {
		t.Run(fmt.Sprint(large), func(t *testing.T) {
			tr, dir := openTraffic(t)
			body := []byte("small")
			limit := captureMaxRecords
			if large {
				body = bytes.Repeat([]byte("x"), 5<<20)
				limit = 3
			}
			release := make(chan struct{})
			var arrived atomic.Int32
			tr.SetSecretSource(func(context.Context) ([]string, error) { arrived.Add(1); <-release; return nil, nil })
			var wg sync.WaitGroup
			for i := range 20 {
				wg.Go(func() {
					f := newFlow("fixture.test", "POST", fmt.Sprintf("/%d", i), body, body, withRespType("application/octet-stream"))
					f.Request.Header.Set("Content-Type", "application/octet-stream")
					tr.record(f)
				})
			}
			captureWait(t, func() bool { return arrived.Load() == int32(limit) })
			tr.captureWriter.mu.Lock()
			active, size := tr.captureWriter.active, tr.captureWriter.bytes
			tr.captureWriter.mu.Unlock()
			if active != limit || size > captureMaxBytes {
				t.Fatal("admission exceeded bounds", active, size)
			}
			closed := make(chan error, 1)
			go func() { closed <- tr.Close() }()
			captureWait(t, func() bool {
				tr.captureWriter.mu.Lock()
				defer tr.captureWriter.mu.Unlock()
				return tr.captureWriter.closing
			})
			select {
			case e := <-closed:
				t.Fatal("close returned before admitted captures", e)
			default:
			}
			close(release)
			wg.Wait()
			if e := <-closed; e != nil {
				t.Fatal(e)
			}
			reopened, e := Open(dir, "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if n, e := reopened.Count(); e != nil || n != limit {
				t.Fatal("close lost admitted records or accepted waiters", n, e)
			}
		})
	}
}
