package traffic

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestHistoricalExchangeRedaction(t *testing.T) {
	in := ArchiveExchange{URL: "https://user:pass@lab.test/p?token=targetsecret", Method: "POST", ReqHead: "POST /p?token=targetsecret HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\nAuthorization: Bearer abc\n", RespHead: "HTTP 200\nContent-Type: application/json\nSet-Cookie: session=abc\n", ReqBody: []byte("password=abc&name=ok"), RespBody: []byte(`{"password":"abc","number":9007199254740993}`)}
	out, err := HistoricalExchange(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{out.URL, out.ReqHead, out.RespHead, string(out.ReqBody), string(out.RespBody)} {
		if strings.Contains(raw, "targetsecret") || strings.Contains(raw, "abc") || strings.Contains(raw, "user:pass") {
			t.Fatal("credential remained")
		}
	}
	if !bytes.Contains(out.RespBody, []byte("9007199254740993")) {
		t.Fatal("large JSON number changed")
	}
	again, err := HistoricalExchange(out, nil)
	if err != nil || !reflect.DeepEqual(out, again) {
		t.Fatal("not idempotent", err)
	}
	if !strings.Contains(in.ReqHead, "Bearer abc") {
		t.Fatal("input mutated")
	}
}

func TestHistoricalCompressedBodyAndMalformedHead(t *testing.T) {
	in := ArchiveExchange{URL: "http://lab.test/", ReqHead: "GET / HTTP/1.1\n", RespHead: "HTTP 200\nContent-Encoding: gzip\n", RespBody: []byte{0, 1, 2}}
	out, err := HistoricalExchange(in, nil)
	if err != nil || !bytes.Contains(out.RespBody, []byte("encoded body omitted")) || strings.Contains(out.RespHead, "gzip") {
		t.Fatal(out, err)
	}
	in.ReqHead = "unparseable"
	if _, err = HistoricalExchange(in, nil); err == nil {
		t.Fatal("malformed header accepted")
	}
}
