// Package runtimecheck inventories existing runtime tools without installing or updating them.
package runtimecheck

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

//go:embed tools.json
var manifest []byte

type Tool struct {
	Name           string   `json:"name"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	VersionPattern string   `json:"version_pattern"`
	Required       bool     `json:"required"`
}

func Inventory() []Tool {
	var tools []Tool
	if err := json.Unmarshal(manifest, &tools); err != nil {
		panic(err)
	}
	return tools
}
func CheckTools(report func(string, string, string)) {
	for _, tool := range Inventory() {
		failure := "WARN"
		if tool.Required {
			failure = "FAIL"
		}
		if _, err := exec.LookPath(tool.Command); err != nil {
			report(failure, tool.Name, "未安装或不在 PATH")
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		output, err := exec.CommandContext(ctx, tool.Command, tool.Args...).Output()
		cancel()
		if err != nil {
			report(failure, tool.Name, "版本命令失败或超过 5 秒")
			continue
		}
		version := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
		if len(version) > 240 {
			version = version[:240]
		}
		if tool.VersionPattern != "" && !regexp.MustCompile(tool.VersionPattern).MatchString(version) {
			report("WARN", tool.Name, "版本与当前部署清单不一致: "+version)
			continue
		}
		report("OK", tool.Name, version)
	}
}

type IntegrityFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Baselines are created from the installed image at build time. They detect local
// changes to selected files, not the provenance or integrity of an entire package.
func CheckIntegrity(path string, report func(string, string, string)) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		report("SKIP", "工具文件校验", "未提供构建时指纹清单")
		return
	}
	var files []IntegrityFile
	if err != nil || json.Unmarshal(raw, &files) != nil || len(files) == 0 {
		report("FAIL", "工具文件校验", "指纹清单不可读取或格式无效")
		return
	}
	for _, entry := range files {
		expected, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(expected) != sha256.Size {
			report("FAIL", entry.Path, "无效的 SHA-256 指纹")
			continue
		}
		f, err := os.Open(entry.Path)
		if err != nil {
			report("FAIL", entry.Path, "文件缺失或不可读")
			continue
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			f.Close()
			report("FAIL", entry.Path, "预期普通文件，不能用目录代替")
			continue
		}
		hash := sha256.New()
		_, err = io.Copy(hash, f)
		f.Close()
		if err != nil || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), entry.SHA256) {
			report("FAIL", entry.Path, "文件内容与构建时指纹不符")
			continue
		}
		report("OK", entry.Path, "SHA-256 与构建时一致")
	}
	report("OK", "工具校验范围", fmt.Sprintf("已检查 %d 个清单文件；不代表整个软件包的完整性", len(files)))
}
