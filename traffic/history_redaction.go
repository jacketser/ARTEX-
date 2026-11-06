package traffic

import (
	"bufio"
	"bytes"
	"errors"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"
)

// HistoricalText is shared by the offline maintenance tool. It detects only
// known credentials, PEM private keys and structured credential fields, not
// arbitrary passwords in prose. No original text is returned in audit reports.
func HistoricalText(raw string, secrets []string) string {
	return string(redactBody([]byte(raw), "application/json", secrets))
}

// HistoricalIndex preserves the recorder's binary exclusion and 4 MiB text cap.
func HistoricalIndex(v ArchiveExchange) string {
	parts := []string{v.URL, v.ReqHead, v.RespHead}
	for _, part := range []struct {
		head string
		body []byte
	}{{v.ReqHead, v.ReqBody}, {v.RespHead, v.RespBody}} {
		lines := strings.SplitN(part.head, "\n", 2)
		ct := ""
		if len(lines) == 2 {
			if h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(lines[1] + "\n"))).ReadMIMEHeader(); err == nil {
				ct = h.Get("Content-Type")
			}
		}
		if !isBinaryBody(ct, part.body) {
			parts = append(parts, string(clipBytes(part.body, maxIndexBody)))
		}
	}
	return strings.Join(parts, "\n")
}

// HistoricalExchange sanitizes full stored bodies, never a truncated preview.
// The caller updates hashes, indexes and references after reviewing the plan.
func HistoricalExchange(in ArchiveExchange, secrets []string) (ArchiveExchange, error) {
	out := in
	u, err := url.Parse(in.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return out, errors.New("历史流量 URL 无效")
	}
	if u.User != nil {
		u.User = url.User("REDACTED")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return out, errors.New("历史流量查询参数无法安全解析")
	}
	changed := false
	for key := range q {
		if sensitiveField(key) {
			q.Set(key, "[REDACTED]")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	out.URL = string(redactBytes([]byte(u.String()), secrets))
	u, err = url.Parse(out.URL)
	if err != nil {
		return out, errors.New("历史流量脱敏 URL 无效")
	}
	out.Host = u.Hostname()
	out.URLTemplate = string(redactBytes([]byte(in.URLTemplate), secrets))
	for _, part := range []struct {
		head    *string
		body    *[]byte
		request bool
	}{
		{&out.ReqHead, &out.ReqBody, true}, {&out.RespHead, &out.RespBody, false},
	} {
		lines := strings.SplitN(strings.ReplaceAll(*part.head, "\r\n", "\n"), "\n", 2)
		if len(lines) != 2 {
			return out, errors.New("历史报文头缺少起始行")
		}
		h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(lines[1] + "\n\n"))).ReadMIMEHeader()
		if err != nil {
			return out, errors.New("历史报文头无法安全解析")
		}
		body := redactBody(*part.body, h.Get("Content-Type"), secrets)
		if enc := h.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") && len(body) > 0 {
			body = []byte("[REDACTED: encoded body omitted]")
			h.Del("Content-Encoding")
		}
		first := string(redactBytes([]byte(lines[0]), secrets))
		if part.request {
			fields := strings.Fields(lines[0])
			if len(fields) != 3 {
				return out, errors.New("历史请求起始行无效")
			}
			first = fields[0] + " " + u.RequestURI() + " " + fields[2]
		}
		safe := redactHeaders(http.Header(h), secrets)
		safe.Del("Content-Length")
		safe.Set("X-Artex-Capture", "sanitized; not-wire-original")
		keys := make([]string, 0, len(safe))
		for k := range safe {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var head strings.Builder
		head.WriteString(first + "\n")
		for _, k := range keys {
			for _, v := range safe[k] {
				head.WriteString(k + ": " + v + "\n")
			}
		}
		*part.head = head.String()
		*part.body = bytes.Clone(body)
	}
	out.ReqLen = len(out.ReqBody)
	out.RespLen = len(out.RespBody)
	out.ContentType = string(redactBytes([]byte(in.ContentType), secrets))
	return out, nil
}
