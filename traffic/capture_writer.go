package traffic

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

const captureMaxRecords = 16
const captureMaxBytes = 32 << 20

// Admission bounds concurrent captures by their input payload size, not all
// proxy buffers, redaction allocations or total heap usage. Callers retain
// their original flow while waiting.
type captureWriter struct {
	mu               sync.Mutex
	changed          *sync.Cond
	active           int
	bytes            int
	closing, running bool
	pending          []*captureJob
}
type captureJob struct {
	flow   *mproxy.Flow
	epoch  uint64
	queued time.Time
	done   chan struct{}
}

func newCaptureWriter() *captureWriter {
	w := &captureWriter{}
	w.changed = sync.NewCond(&w.mu)
	return w
}
func (w *captureWriter) reserve(size int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for !w.closing && (w.active >= captureMaxRecords || w.bytes+size > captureMaxBytes) {
		w.changed.Wait()
	}
	if w.closing {
		return false
	}
	w.active++
	w.bytes += size
	return true
}
func (w *captureWriter) release(size int) {
	w.mu.Lock()
	w.active--
	w.bytes -= size
	w.changed.Broadcast()
	w.mu.Unlock()
}
func (w *captureWriter) close() {
	w.mu.Lock()
	w.closing = true
	w.changed.Broadcast()
	for w.active > 0 || w.running {
		w.changed.Wait()
	}
	w.mu.Unlock()
}
func captureSize(f *mproxy.Flow) int {
	n := len(f.Request.Body) + len(f.Response.Body)
	for _, h := range []map[string][]string{f.Request.Header, f.Response.Header} {
		for k, vs := range h {
			n += len(k)
			for _, v := range vs {
				n += len(v)
			}
		}
	}
	// Synthetic/internal flows can exceed the live proxy's body limits; admit
	// these alone instead of waiting forever for more than the whole budget.
	if n > captureMaxBytes {
		n = captureMaxBytes
	}
	return n
}
func (t *Traffic) queueCapture(job *captureJob) {
	w := t.captureWriter
	w.mu.Lock()
	w.pending = append(w.pending, job)
	if !w.running {
		w.running = true
		go t.drainCaptures()
	}
	w.mu.Unlock()
	<-job.done // Return only after the transaction (or explicit failure/skip).
}
func (t *Traffic) drainCaptures() {
	w := t.captureWriter
	for {
		w.mu.Lock()
		if len(w.pending) == 0 {
			w.running = false
			w.changed.Broadcast()
			w.mu.Unlock()
			return
		}
		batch := w.pending
		w.pending = nil
		w.mu.Unlock()
		t.writeCaptureBatch(batch)
		for _, j := range batch {
			close(j.done)
		}
	}
}
func (t *Traffic) writeCaptureBatch(jobs []*captureJob) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	live := make([]*captureJob, 0, len(jobs))
	for _, j := range jobs {
		t.captureMetrics.wait.observe(j.queued)
		if j.epoch == t.captureState.Load() && t.captureAllowed(j.flow) {
			live = append(live, j)
		}
	}
	if len(live) == 0 {
		return
	}
	rows := make([]captureRow, 0, len(live))
	for _, j := range live {
		started := time.Now()
		row, e := t.prepareCapture(j.flow)
		t.captureMetrics.prepare.observe(started)
		if e != nil {
			t.captureMetrics.failed.Add(uint64(len(live)))
			log.Printf("[traffic] capture batch preparation failed (%d records): %v", len(live), e)
			return
		}
		rows = append(rows, row)
	}
	if e := t.commitCaptureRows(rows); e != nil {
		t.captureMetrics.failed.Add(uint64(len(live)))
		log.Printf("[traffic] capture batch failed (%d records): %v", len(live), e)
		return
	}
	t.captureMetrics.written.Add(uint64(len(rows)))
}

type captureRow struct {
	id                                       string
	ts                                       int64
	host, method, template, url, contentType string
	status, reqLen, respLen                  int
	reqHead, respHead                        string
	req, resp                                storedBody
}

func (t *Traffic) prepareCapture(f *mproxy.Flow) (captureRow, error) {
	now := time.Now()
	row := captureRow{id: fmt.Sprintf("%d-%d", now.UnixNano(), t.seq.Add(1)), ts: now.Unix(), host: f.Request.URL.Hostname(), method: f.Request.Method, template: db.TemplatePath(f.Request.URL.EscapedPath()), url: f.Request.URL.String(), contentType: f.Response.Header.Get("Content-Type"), status: f.Response.StatusCode, reqLen: len(f.Request.Body), respLen: len(f.Response.Body), reqHead: fmt.Sprintf("%s %s %s\n%s", f.Request.Method, f.Request.URL.RequestURI(), f.Request.Proto, requestHeaderLines(f.Request)), respHead: fmt.Sprintf("HTTP %d\n%s", f.Response.StatusCode, headerLines(f.Response.Header))}
	var e error
	row.req, e = t.spill(f.Request.Body, f.Request.Header.Get("Content-Type"))
	if e != nil {
		return row, e
	}
	row.resp, e = t.spill(f.Response.Body, row.contentType)
	return row, e
}
func insertCaptureRow(tx *sql.Tx, r captureRow, fts bool) error {
	result, e := tx.Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES(?,?,?,?,?,?,?,?,?,?,'')`, r.id, r.ts, r.host, r.method, r.template, r.url, r.status, r.contentType, r.reqLen, r.respLen)
	if e != nil {
		return e
	}
	id, e := result.LastInsertId()
	if e != nil {
		return e
	}
	if _, e = tx.Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob) VALUES(?,?,?,?,?,?,?)`, r.id, r.reqHead, r.req.inline, nullIfEmpty(r.req.hash), r.respHead, r.resp.inline, nullIfEmpty(r.resp.hash)); e != nil {
		return e
	}
	for _, h := range []string{r.req.hash, r.resp.hash} {
		if h != "" {
			if _, e = tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, h, r.id); e != nil {
				return e
			}
		}
	}
	if fts {
		_, e = tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, id, strings.Join([]string{r.url, r.reqHead, r.req.index, r.respHead, r.resp.index}, "\n"))
	}
	return e
}
func (t *Traffic) commitCaptureRows(rows []captureRow) error {
	started := time.Now()
	tx, e := t.db.Begin()
	if e != nil {
		t.captureMetrics.sql.observe(started)
		return e
	}
	defer tx.Rollback()
	for _, r := range rows {
		if e = insertCaptureRow(tx, r, t.fts); e != nil {
			t.captureMetrics.sql.observe(started)
			return e
		}
	}
	t.captureMetrics.sql.observe(started)
	started = time.Now()
	e = tx.Commit()
	t.captureMetrics.commit.observe(started)
	return e
}
