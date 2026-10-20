package evidence

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
)

type BodyDifference struct {
	Side            string `json:"side"`
	Status          string `json:"status"`
	BaselineLength  int64  `json:"baseline_length"`
	ProofLength     int64  `json:"proof_length"`
	FirstDifference *int   `json:"first_difference,omitempty"`
	Details         string `json:"details"`
}
type TrafficComparison struct {
	BaselineID  string           `json:"baseline_id"`
	ProofID     string           `json:"proof_id"`
	Differences []string         `json:"differences"`
	Bodies      []BodyDifference `json:"bodies"`
	Limitation  string           `json:"limitation"`
}

// Missing/corrupt saved bodies cannot support a conclusive automatic summary.
// Keep the human review intact, but surface the evidence gap for the next review.
func (r *AutoReview) ApplyComparisons(comparisons []TrafficComparison) {
	r.Comparisons = comparisons
	unavailable, skipped := false, false
	for _, c := range comparisons {
		for _, b := range c.Bodies {
			unavailable = unavailable || b.Status == "unavailable"
			skipped = skipped || b.Status == "skipped"
		}
	}
	if unavailable {
		r.Verdict = "inconclusive"
		r.Basis = "保存的流量正文缺失或校验失败，需重新核对证据"
		r.Missing = append(r.Missing, "可读取且校验通过的对照流量正文")
	}
	if skipped {
		r.Warnings = append(r.Warnings, "部分正文超过比较上限，未参与逐字节比较，请打开证据另行核对。")
	}
}

// CompareTraffic compares saved evidence only. The first baseline is a reference,
// never an assertion that two identities/environments are causally comparable.
// Bound work to eight pairs and 256 KiB per body; never expose header/body secrets.
func (s *Store) CompareTraffic(bindings []db.FindingTrafficBinding) []TrafficComparison {
	out := []TrafficComparison{}
	var baseline *db.FindingTrafficBinding
	for i := range bindings {
		if bindings[i].Role == "baseline" {
			baseline = &bindings[i]
			break
		}
	}
	if baseline == nil {
		return out
	}
	for _, proof := range bindings {
		if proof.Role != "proof" || proof.SnapshotID == baseline.SnapshotID {
			continue
		}
		if len(out) >= 8 {
			break
		}
		a, b := baseline.Snapshot, proof.Snapshot
		c := TrafficComparison{BaselineID: fmt.Sprint(baseline.ID), ProofID: fmt.Sprint(proof.ID), Differences: []string{}, Bodies: []BodyDifference{}, Limitation: "与第一个正常对照比较（最多 8 组）；差异不等于漏洞成立，仍需核对身份、时间和环境。仅显示字段名称、长度与字节偏移，不展示敏感值。"}
		if a.Method != b.Method {
			c.Differences = append(c.Differences, "请求方法不同")
		}
		if a.URL != b.URL {
			c.Differences = append(c.Differences, "请求地址不同")
		}
		if a.Status != b.Status {
			c.Differences = append(c.Differences, fmt.Sprintf("响应状态码：%d → %d", a.Status, b.Status))
		}
		if a.ContentType != b.ContentType {
			c.Differences = append(c.Differences, "响应内容类型不同")
		}
		for _, pair := range []struct{ label, left, right string }{{"请求", a.ReqHead, b.ReqHead}, {"响应", a.RespHead, b.RespHead}} {
			names := changedHeaderNames(pair.left, pair.right)
			if len(names) > 0 {
				c.Differences = append(c.Differences, pair.label+"头差异："+strings.Join(names, ", "))
			}
		}
		for _, side := range []string{"request", "response"} {
			c.Bodies = append(c.Bodies, s.compareBody(a, b, side))
		}
		out = append(out, c)
	}
	return out
}
func changedHeaderNames(a, b string) []string {
	parse := func(s string) map[string]string {
		m := map[string]string{}
		for _, line := range strings.Split(s, "\n") {
			k, v, ok := strings.Cut(line, ":")
			k = strings.ToLower(strings.TrimSpace(k))
			if ok && len(k) <= 100 && !strings.ContainsAny(k, " /\r\t") {
				m[k] += strings.TrimSpace(v) + "\n"
			}
		}
		return m
	}
	left, right := parse(a), parse(b)
	names := map[string]bool{}
	for k, v := range left {
		if right[k] != v {
			names[k] = true
		}
	}
	for k, v := range right {
		if left[k] != v {
			names[k] = true
		}
	}
	out := []string{}
	for k := range names {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 30 {
		out = append(out[:30], "…")
	}
	return out
}
func (s *Store) compareBody(a, b db.TrafficEvidenceSnapshot, side string) BodyDifference {
	al, bl := a.ReqLen, b.ReqLen
	if side == "response" {
		al, bl = a.RespLen, b.RespLen
	}
	out := BodyDifference{Side: side, BaselineLength: al, ProofLength: bl, Status: "unavailable", Details: "正文缺失或校验失败，不能据此判为相同"}
	if al > 256*1024 || bl > 256*1024 {
		out.Status = "skipped"
		out.Details = "正文超过 256 KiB，本次未读取比较"
		return out
	}
	read := func(v db.TrafficEvidenceSnapshot) ([]byte, error) {
		f, _, err := s.OpenBody(v, side)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 256*1024+1))
	}
	left, err := read(a)
	if err != nil {
		return out
	}
	right, err := read(b)
	if err != nil {
		return out
	}
	if bytes.Equal(left, right) {
		out.Status = "equal"
		out.Details = "保存的正文逐字节相同"
		return out
	}
	offset := 0
	for offset < len(left) && offset < len(right) && left[offset] == right[offset] {
		offset++
	}
	out.Status = "different"
	out.FirstDifference = &offset
	out.Details = "首个不同字节位置从 0 开始；一侧结束也记为差异"
	return out
}
