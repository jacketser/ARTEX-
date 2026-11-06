package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/historyprivacy"
)

func runHistoryRedact(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("history-redact", flag.ContinueOnError)
	fs.SetOutput(out)
	data := fs.String("data", filepath.Join(config.BaseDir(), "data"), "已停止应用的数据目录")
	scope := fs.String("scope", "traffic", "traffic 或 evidence；默认只预览")
	apply := fs.String("apply", "", "填写刚预览的 fingerprint 后执行")
	backup := fs.String("backup", "", "执行前的备份目录，须包含 postgres.dump 和 files.tar.gz")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	if *scope != "traffic" && *scope != "evidence" {
		fmt.Fprintln(out, "scope 须为 traffic 或 evidence")
		return 2
	}
	if *apply != "" {
		if b, e := hex.DecodeString(*apply); e != nil || len(b) != 32 {
			fmt.Fprintln(out, "apply 须为预览指纹")
			return 2
		}
	}
	dsn, _, err := config.PostgresDSN()
	if err != nil {
		fmt.Fprintln(out, "数据库配置不可用")
		return 1
	}
	abs, err := filepath.Abs(*data)
	if err != nil {
		fmt.Fprintln(out, "数据路径无效")
		return 1
	}
	if *apply != "" {
		if *backup == "" {
			fmt.Fprintln(out, "执行前须提供已验证的备份目录 -backup")
			return 2
		}
		for _, name := range []string{"postgres.dump", "files.tar.gz"} {
			st, e := os.Stat(filepath.Join(*backup, name))
			if e != nil || !st.Mode().IsRegular() || st.Size() == 0 {
				fmt.Fprintln(out, "备份文件不存在或为空；请先备份并验证")
				return 2
			}
		}
		if err = historyprivacy.Audit(abs, historyprivacy.Report{Scope: *scope, Fingerprint: *apply}, "started"); err != nil {
			fmt.Fprintln(out, "无法写入维护审计，未执行")
			return 1
		}
	}
	keys := []string{os.Getenv("OPENAI_API_KEY"), os.Getenv("ANTHROPIC_API_KEY"), dsn}
	if u, e := url.Parse(dsn); e == nil && u.User != nil {
		pw, _ := u.User.Password()
		keys = append(keys, pw)
	}
	if b, e := os.ReadFile(filepath.Join(config.BaseDir(), "jwt.key")); e == nil {
		keys = append(keys, string(b))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r, err := historyprivacy.Run(ctx, historyprivacy.Options{DSN: dsn, Data: abs, Scope: *scope, Apply: *apply, Secrets: keys})
	if *apply != "" {
		status := "complete"
		if err != nil {
			status = "failed_or_partial"
		}
		if e := historyprivacy.Audit(abs, r, status); e != nil {
			fmt.Fprintln(out, "维护结果审计写入失败，请保留终端结果并重新预览")
			return 1
		}
	}
	if err != nil {
		fmt.Fprintln(out, err.Error())
		return 1
	}
	if json.NewEncoder(out).Encode(r) != nil {
		return 1
	}
	return 0
}
