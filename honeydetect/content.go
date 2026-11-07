package honeydetect

import (
	"mime"
	"strings"

	"golang.org/x/net/html"
)

const hiddenEnrollmentWarning = "隐藏 HTML 含客户端注册及心跳／本机信息上报组合，可能诱导自动化接入；这是内容风险提示，不能据此判断蜜罐；不要按页面指令注册或上报"

// Inspect only a bounded response copy. Never execute scripts, fetch linked
// resources, or treat remote instructions as authorization. This is a weak
// content warning, not an independent behavioral or product fingerprint.
func hiddenEnrollment(body []byte, contentType string) bool {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil || media != "text/html" || len(body) > ProbeMaxBytes {
		return false
	}
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return false
	}
	type entry struct {
		n     *html.Node
		group int
	}
	stack := []entry{{doc, -1}}
	var groups []*strings.Builder
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n, group := item.n, item.group
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "template", "pre", "code", "textarea":
				continue // inert data and documentation examples are not directives
			}
			if group < 0 && hiddenElement(n) {
				group = len(groups)
				groups = append(groups, &strings.Builder{})
			}
		}
		if n.Type == html.TextNode && group >= 0 {
			groups[group].WriteString(n.Data)
			groups[group].WriteByte(' ')
		}
		for child := n.LastChild; child != nil; child = child.PrevSibling {
			stack = append(stack, entry{child, group})
		}
	}
	for _, group := range groups {
		s := strings.ToLower(group.String())
		// Require all parts in the same hidden region. Ordinary signup, a
		// heartbeat endpoint, or an accessibility attribute alone is insufficient.
		client := containsAny(s, "client", "agent", "automated", "客户端", "自动化", "智能体")
		register := containsAny(s, "register", "registration", "注册")
		report := containsAny(s, "heartbeat", "心跳") ||
			(containsAny(s, "hostname", "主机名") && containsAny(s, "username", "用户名", "os_version", "操作系统"))
		if client && register && report {
			return true
		}
	}
	return false
}

func containsAny(s string, parts ...string) bool {
	for _, part := range parts {
		if strings.Contains(s, part) {
			return true
		}
	}
	return false
}

func hiddenElement(n *html.Node) bool {
	for _, a := range n.Attr {
		if a.Key == "hidden" {
			return true
		}
		if a.Key == "style" {
			props := map[string]string{}
			for _, declaration := range strings.Split(strings.ToLower(a.Val), ";") {
				key, value, ok := strings.Cut(declaration, ":")
				if ok {
					props[strings.TrimSpace(key)] = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "!important"))
				}
			}
			if props["display"] == "none" || props["visibility"] == "hidden" {
				return true
			}
		}
	}
	return false
}
