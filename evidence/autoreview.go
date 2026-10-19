package evidence

import (
	"encoding/json"
	"github.com/Autumn-27/artex/db"
	"strings"
)

type AutoReview struct {
	Verdict     string        `json:"verdict"`
	Basis       string        `json:"basis"`
	Checks      []ReviewCheck `json:"checks"`
	Missing     []string      `json:"missing"`
	Warnings    []string      `json:"warnings"`
	Suggestions []string      `json:"suggestions"`
}
type ReviewCheck struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

// ReviewFinding audits saved records, not vulnerability truth. Text presence
// and role labels are never promoted into an independently verified proof.
func ReviewFinding(f *db.DBFinding, retests []*db.FindingRetest) AutoReview {
	out := AutoReview{Verdict: "inconclusive", Basis: "未取得当前证据的有效人工结论，需人工确认", Checks: []ReviewCheck{}, Missing: []string{}, Warnings: []string{"规则审阅只检查已保存记录；通过表示记录具备该项，不代表验证内容真实。不会调用模型、访问目标、覆盖人工复核或更改处置状态。"}, Suggestions: []string{}}
	if f == nil {
		out.Missing = append(out.Missing, "漏洞记录")
		return out
	}
	add := func(key, label string, ok bool, details string) {
		out.Checks = append(out.Checks, ReviewCheck{key, label, ok, details})
		if !ok {
			out.Missing = append(out.Missing, label)
		}
	}
	r := f.Review
	current := r != nil && r.Fingerprint == db.FindingFingerprint(f)
	valid := current && r.Validate() == nil
	if r != nil && !current {
		out.Warnings = append(out.Warnings, "人工复核已过期，不能沿用旧结论。")
	}
	nonempty := func(s string) bool { return strings.TrimSpace(s) != "" }
	add("evidence", "原始文字记录", nonempty(f.Evidence), "仅检查非空，不将摘要或推断视作实际观察")
	add("source", "证据来源记录", f.TrafficCount > 0 || (current && nonempty(r.Sources)), "检查已关联流量或当前复核填写的来源；来源真实性仍需核对")
	add("reproduction", "复现条件与实际观察记录", current && nonempty(r.Reproduction), "摘要不替代环境、前置条件、实际结果与预期结果")
	add("counter", "反证与替代解释记录", current && nonempty(r.CounterEvidence), "当前版本复核中是否记录；文本非空不代表已排除替代解释")
	proof, baseline := map[string]bool{}, map[string]bool{}
	for _, b := range f.TrafficBindings {
		if b.Role == "proof" {
			proof[b.SnapshotID] = true
		}
		if b.Role == "baseline" {
			baseline[b.SnapshotID] = true
		}
	}
	independent := false
	for p := range proof {
		for b := range baseline {
			if p != "" && b != "" && p != b {
				independent = true
			}
		}
	}
	if f.TrafficCount > 0 {
		add("baseline", "独立的证明/正常对照流量", independent, "用途标签仅为记录；仍需核对身份、缓存、输入与响应差异")
	}
	add("review", "当前证据的有效人工复核", valid, "已保存且证据指纹一致；自动审阅不会替代人工判断")
	if valid && len(out.Missing) == 0 {
		out.Verdict = r.Verdict
		out.Basis = "沿用当前版本的人工复核结论，非自动独立确认"
	}
	// Latest attempt takes precedence even if incomplete; no fallback to an older
	// success. A fix addresses current state, not the original finding's truth.
	var latest *db.FindingRetest
	for _, candidate := range retests {
		if candidate != nil && (latest == nil || candidate.ID > latest.ID) {
			latest = candidate
		}
	}
	if latest != nil {
		complete := latest.Status == "completed" && nonempty(latest.Evidence) && nonempty(latest.Summary) && RetestMatchesFinding(f, latest)
		add("retest", "最近一次复测可用于当前证据", complete, "需复测完成、结论和证据非空、复测快照与当前证据一致")
		if !complete {
			out.Verdict = "inconclusive"
			out.Basis = "最新复测未完成、失败、缺证据或快照已过期"
		} else {
			switch latest.Verdict {
			case "fixed":
				out.Verdict = "inconclusive"
				out.Basis = "复测记录为已修复；已修复不等于原漏洞误报或被反驳"
			case "inconclusive":
				out.Verdict = "inconclusive"
				out.Basis = "最新复测无法确认"
			case "reproduced":
				if out.Verdict == "refuted" {
					out.Verdict = "inconclusive"
					out.Basis = "人工反驳与复测复现结论冲突，需核对"
				}
				out.Warnings = append(out.Warnings, "最新复测记录为已复现；标签本身不替代对照、反证和证据审查。")
			default:
				out.Verdict = "inconclusive"
				out.Basis = "最新复测缺少有效结论"
			}
		}
	}
	out.Suggestions = counterEvidenceSuggestions(f.VulnClass)
	return out
}

func RetestMatchesFinding(f *db.DBFinding, r *db.FindingRetest) bool {
	var snap struct {
		Finding struct {
			Version   *int64 `json:"evidence_version"`
			VulnClass string `json:"vulnclass"`
			Severity  string `json:"severity"`
			Summary   string `json:"summary"`
			Evidence  string `json:"evidence"`
		} `json:"finding"`
	}
	if json.Unmarshal(r.Snapshot, &snap) != nil || snap.Finding.Version == nil {
		return false
	}
	v := snap.Finding
	return db.FindingFingerprint(f) == db.FindingFingerprint(&db.DBFinding{EvidenceVersion: *v.Version, VulnClass: v.VulnClass, Severity: v.Severity, Summary: v.Summary, Evidence: v.Evidence})
}

func counterEvidenceSuggestions(class string) []string {
	base := []string{"核对原始记录来源、时间和环境，将观察事实与推断分开。", "检查正常对照、缓存、代理/WAF、错误页或环境差异能否解释观察结果；未排除项应记入限制。"}
	c := strings.ToLower(class)
	switch {
	case strings.Contains(c, "sql"):
		base = append(base, "核对正常/异常输入的已有对照，排除通用错误、网络延迟和缓存差异；报错关键词或单次耗时不足以确认注入。")
	case strings.Contains(c, "xss") || strings.Contains(c, "跨站脚本"):
		base = append(base, "区分文本反射、HTML 注入和浏览器脚本执行；核对编码、上下文与 CSP，单纯出现输入字符串不证明可执行。")
	case strings.Contains(c, "ssrf"):
		base = append(base, "核对请求是否确由服务端发起；排除浏览器请求、缓存、外部回显和 DNS 预取等替代解释。")
	case strings.Contains(c, "idor") || strings.Contains(c, "越权") || strings.Contains(c, "权限"):
		base = append(base, "核对不同身份、对象归属和业务授权规则；排除公开资源、共享资源及同一会话复用。")
	case strings.Contains(c, "rce") || strings.Contains(c, "命令"):
		base = append(base, "区分执行输出与原样回显/模拟错误；核对已有输出的来源和时间，不能仅凭错误关键词确认执行。")
	case strings.Contains(c, "文件") || strings.Contains(c, "traversal"):
		base = append(base, "核对内容确属目标文件，排除应用模板、通用下载页和同名公开资源。")
	}
	return base
}
