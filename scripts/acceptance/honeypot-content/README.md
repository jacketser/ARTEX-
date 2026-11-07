# 蜜罐内容留出复放

本工具验证冻结检测器对来源独立内容的表现，不部署源项目，不运行模型，不执行 HTML／JS 或语料中的指令。分组、选择顺序、来源与统计边界见[测前约定](HOLDOUT.md)。前次 AgentCapture 开发模板结果保留在[专项报告](../../../AGENTCAPTURE-REVIEW.md)。

## 复现

在仓库根目录执行，工作目录应为专用临时目录。首次下载仅访问锁定 GitHub 源码；之后 Docker 检测完全断网，只用容器内 loopback。脚本从固定检测提交导出临时源码，不读取正式数据库、环境文件或数据目录。

```bash
content_run=$(mktemp -d /tmp/artex-content-holdout-XXXXXXXX)
python3 scripts/acceptance/honeypot-content/fetch.py "$content_run/downloads"
python3 scripts/acceptance/honeypot-content/prepare.py "$content_run/downloads" "$content_run/fixtures"
bash scripts/acceptance/honeypot-content/run.sh "$content_run/fixtures" "$content_run/results" > "$content_run/run.log" 2>&1
python3 scripts/acceptance/honeypot-content/check-summary.py "$content_run/fixtures/samples.json" "$content_run/results/measurements.json"
```

要求已有 `golang:1.26-bookworm` 和 Go 依赖／构建缓存卷 `artex-dev-gomod`、`artex-dev-gocache`；断网环境下缺依赖会失败。固定 `GOMAXPROCS=2`、`-p 1`。每个样例约 0.75 秒等待，共 154 个，整轮约两分钟；不启动正式应用或其他服务。自动删除临时源码和容器；下载、夹具、日志及结果由调用者保留，均为公开来源／合成数据。

## 结果与完整性

- `samples.json` 包含来源提交、Git blob SHA-1、SHA-256、分类／索引、呈现方式及响应字节哈希。标签不传给检测器。
- `measurements.json` 记录各次四请求观测和结果；全部测试完成才原子发布。新的运行开始时删除旧测量和摘要，避免失败时沿用旧结果。
- `summary.json` 包含逐项测量和三组四类计数。汇总前从锁定源文件重新生成整个预定语料清单；不接受删样本、改标签、变更渲染内容、混合算法或不完整 HTTP 观测。未知结论必须报错，不当成无信号。
- `check-summary.py` 用隔离副本验证有效结果及 11 类破坏输入；拒绝时删除旧摘要。这是工具完整性测试，不是追加的检测样本。
- 同一攻击文本的可见／隐藏版本不可视为独立攻击样本。BIPIA 是提示注入数据集，不是蜜罐标签库；此处无信号不能表示文本安全或检测器免疫注入。MDN 页面也不是完整正常应用。

脚本读取公开源文件但不将正文提交到仓库。正常样例保留原 HTML；BIPIA 字符串经 HTML 转义放入预定容器，属于有明确转换的内容复放，不是原项目真实响应。每轮观察结果后该内容组即成为已查看回归材料；后续调参需另设新留出。

## 针对性对照与单列反例检查

所有工具保留原默认来源锁；可以显式传入另一个已提交的锁。针对性对照见[测前约定](ENROLLMENT-20261107.md)，测后选择的正常反例检查见[单列约定](COUNTEREXAMPLE-20261107.md)，两组不得混称盲测留出。

```bash
enrollment_run=$(mktemp -d /tmp/artex-enrollment-XXXXXXXX)
enrollment_lock=scripts/acceptance/honeypot-content/sources-enrollment-20261107.json
python3 scripts/acceptance/honeypot-content/fetch.py "$enrollment_run/downloads" "$enrollment_lock" api
python3 scripts/acceptance/honeypot-content/prepare.py "$enrollment_run/downloads" "$enrollment_run/fixtures" "$enrollment_lock"
bash scripts/acceptance/honeypot-content/run.sh "$enrollment_run/fixtures" "$enrollment_run/results" "$enrollment_lock" > "$enrollment_run/run.log" 2>&1
python3 scripts/acceptance/honeypot-content/check-summary.py "$enrollment_run/fixtures/samples.json" "$enrollment_run/results/measurements.json" "$enrollment_lock"
```

`api` 仅切换为固定 Git blob 的 GitHub API 下载，仍校验同一个 blob SHA-1 和大小；默认 `raw` 不变。正常文档全文转义，不注入关键词。Python 模板只经 AST 读取选定字面量，不执行模块、函数或替换占位符。摘要增加 `content_warning_counts`，与普通名称线索触发的复核分开；其含义对应冻结的 v3 固定提示文本。

针对性对照 11 个样例约 8 秒；将锁换为 `sources-enrollment-counterexample-20261107.json` 可复现 2 个补充样例（约 1.5 秒）。原 MDN／BIPIA 的默认命令和历史结果仍然保留，不要覆盖其结果文件。
