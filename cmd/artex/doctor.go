package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/runtimecheck"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// doctor deliberately avoids db.Open: a diagnostic must not migrate or seed a database.
func runDoctor(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(out)
	integrity := fs.String("integrity", filepath.Join(config.BaseDir(), "tool-integrity.json"), "构建时工具文件指纹清单")
	data := fs.String("data", filepath.Join(config.BaseDir(), "data"), "数据目录")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	failed := false
	report := func(status, name, detail string) {
		fmt.Fprintf(out, "[%s] %s: %s\n", status, name, detail)
		failed = failed || status == "FAIL"
	}
	dsn, _, err := config.PostgresDSN()
	if err != nil {
		report("FAIL", "PostgreSQL", "未配置有效的数据库连接")
		report("SKIP", "LLM", "数据库未连接")
	} else {
		checkDatabase(dsn, report)
	}
	if err := checkWritable(*data); err != nil {
		report("FAIL", "数据目录", "目录不存在或不可写")
	} else {
		report("OK", "数据目录", "可读写，临时检查文件已删除")
	}
	if b, err := os.ReadFile(filepath.Join(config.BaseDir(), "jwt.key")); err != nil || len(strings.TrimSpace(string(b))) < 32 {
		report("WARN", "登录密钥", "未找到有效 jwt.key；首次启动会生成，请确保持久化")
	} else {
		report("OK", "登录密钥", "已存在（不显示内容）")
	}
	runtimecheck.CheckTools(report)
	runtimecheck.CheckIntegrity(*integrity, report)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	modules, err := exec.CommandContext(ctx, "npm", "root", "-g").Output()
	if err != nil {
		report("WARN", "Chromium", "无法定位全局 Playwright")
	} else {
		script := `const fs=require('fs'); const p=require(process.argv[1]); const e=p.chromium.executablePath(); fs.accessSync(e,fs.constants.X_OK); require('child_process').execFileSync(e,['--version'],{timeout:5000,stdio:'pipe'});`
		err := exec.CommandContext(ctx, "node", "-e", script, filepath.Join(strings.TrimSpace(string(modules)), "playwright")).Run()
		if err != nil {
			report("WARN", "Chromium", "浏览器缺失或运行依赖不完整")
		} else {
			report("OK", "Chromium", "浏览器可执行且版本检查通过")
		}
	}
	if failed {
		return 1
	}
	return 0
}

func checkDatabase(dsn string, report func(string, string, string)) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		report("FAIL", "PostgreSQL", "连接配置无效（连接信息已隐藏）")
		return
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		report("FAIL", "PostgreSQL", "连接失败或超时（连接信息已隐藏）")
		report("SKIP", "LLM", "数据库未连接")
		return
	}
	report("OK", "PostgreSQL", "连接正常；未执行迁移或写入")
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM llm_profiles").Scan(&count); err != nil {
		report("WARN", "LLM", "配置表不可读取；请确认数据库已初始化")
	} else if count == 0 {
		if os.Getenv("OPENAI_API_KEY") != "" || os.Getenv("ANTHROPIC_API_KEY") != "" {
			report("OK", "LLM", "检测到环境变量密钥；未发起模型调用")
		} else {
			report("WARN", "LLM", "尚未配置模型")
		}
	} else {
		report("OK", "LLM", fmt.Sprintf("存在 %d 个配置；未验证密钥或发起模型调用", count))
	}
}

func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".artex-doctor-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString("doctor")
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
