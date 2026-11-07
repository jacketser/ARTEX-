package report

import (
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

const FindingsShareNotice = "脱敏分享副本，非原始证据。已处理长度不少于 8 字节的当前已知凭据、完整 JSON 字段中的常见敏感值及 PEM 私钥；未知或已轮换凭据、任意自然语言和其他编码不保证识别，分享前请人工检查。复核状态依据导出时的原始证据。"

// Sanitize before Markdown formatting or CSV escaping can split a credential.
// Rendering uses the source objects read-only, including their review fingerprints.
func SharedFindingsMarkdown(fs []*db.DBFinding, generatedAt time.Time, secrets []string) string {
	return "> " + FindingsShareNotice + "\n\n" + findingsMarkdown(fs, generatedAt, func(s string) string {
		return traffic.HistoricalText(s, secrets)
	})
}

func SharedFindingsCSV(fs []*db.DBFinding, secrets []string) []byte {
	return findingsCSV(fs, func(s string) string {
		return traffic.HistoricalText(s, secrets)
	}, FindingsShareNotice)
}
