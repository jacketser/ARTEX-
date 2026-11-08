# 隔离浏览器验收

当前正式版本为 `dev-0fb610d`／行为 v5。以下命令均从仓库根目录运行；脚本验证所选镜像或固定源码，不自动构建或部署正式应用。

- 当前蜜罐浏览器验收：[v5 稳定性](#v5-服务标记稳定性浏览器验收)。
- 当前真实软件回归：[v5 固定源码计划](honeypot-real/README.md#已发布-v5-的真实软件回归2026-11-08)。
- 各版本结果与限制：[验收记录](../../LOCAL-ENHANCEMENTS-VERIFICATION.md)及[蜜罐评估](../../HONEYPOT-EVALUATION.md)。

## v5 服务标记稳定性浏览器验收

```sh
ARTEX_ACCEPTANCE_BASELINE=1 ARTEX_ACCEPTANCE_IMAGE=jacketser/artex:honeypot-v5-candidate bash scripts/acceptance/run.sh
```

自动启用 content profile，沿用原代理／稳定疑似回归，再通过轮换 Server、持续 X-Powered-By 名称的合成目标验证 v5 无法判断、通用原因、独立内容提示、刷新持久化及四请求边界。随后注入一条 v4 合成疑似历史，验证过期提示与原结论保留。未设置 baseline 时原 v4 工具入口不变。没有新增真实样本／留出；目标中的产品名称仅用于既有规则分支验证。结果和范围见[报告](../../HONEYPOT-BASELINE-STABILITY.md)。

## Markdown／CSV 分享导出

```sh
bash scripts/acceptance/export-run.sh
```

默认验证已构建的 `jacketser/artex:share-export-candidate`／`dev-806bc74`，不自动构建。后续候选可同时设置 `ARTEX_EXPORT_IMAGE` 和 `EXPORT_EXPECTED_VERSION`；依赖宿主 Python 3、Docker Compose，以及镜像中的 Chromium／Playwright。Compose 使用 `--pull never`，须预先具备本地应用和 PostgreSQL 镜像。

仅启动新建内部网络中的应用和 PostgreSQL，不发布端口、不挂载正式数据。使用两个合成发现、一个已完成任务及人工复核：通过实际页面点击下载两格式×全部／筛选／勾选六个文件，独立解析最终 CSV，核对脱敏、BOM、13 列及原 12 列顺序、普通文字／大整数、文件名、响应头及复核状态。另下载 JSON 确认保留原文且未标为脱敏，切换 ZIP 检查未覆盖提示；本工具不下载 ZIP。

第二阶段临时重命名测试库的凭据源表，验证两格式均返回 503、页面提示失败且没有下载事件；恢复表后比对源发现／人工复核／任务／探索／合成凭据的前后摘要。退出清理临时容器、卷和网络，清理失败会返回非零。

结果保留在 `/tmp/artex-export-*`：浏览器 JSON、独立字节验证结果、下载文件、页面截图、源记录摘要及清理日志。下载文件全部来自合成数据，JSON 故意保留合成秘密；容器日志可能包含临时初始化信息，不应直接发布。永久结果只记录结论、版本和哈希，见[导出报告](../../TEXT-EXPORT-REDACTION.md)。这不是大导出、全部副本或任意秘密识别验证。

## HTTP 行为验证与代理设置

在仓库根目录执行：

```sh
bash scripts/acceptance/run.sh
```

指定已构建的历史全局上游代理候选镜像（示例）：

```sh
ARTEX_ACCEPTANCE_IMAGE=jacketser/artex:upstream-candidate bash scripts/acceptance/run.sh
```

需要 Docker Compose 和已构建的源码运行镜像（含 Chromium、Playwright 和前端）。默认使用
`jacketser/artex:local`，也可用 `ARTEX_ACCEPTANCE_IMAGE` 指定待验收镜像。
脚本验证的是所选镜像，不会自动构建工作树中的代码；更改应用后须先构建候选镜像。

每次创建独立、仅内部互通的网络、空 PostgreSQL、模拟 HTTP 服务和带认证的 CONNECT 上游代理。不发布宿主机端口，
不挂载正式数据、密钥或环境文件。临时数据库密码仅用于测试，退出时删除临时容器和卷。
输出目录为 `/tmp/artex-acceptance-*`，保留结果 JSON、容器日志和两张页面截图（失败时另存当前页截图）；日志可能含
隔离实例初始化信息，不应当作正式实例日志发布。

覆盖设置保存与刷新、非法配置拒绝、未确认禁用按钮、显式确认后的四次请求、
历史记录、五分钟冷却、模拟目标未收到凭据、公共配额统计及页面脚本错误。行为验证设置全局上游后实际发出四次固定 IP 的 CONNECT，检查原 Host 保留、代理凭据未传给目标，再清空上游进行原有流量测试。还验证关闭流量保存时普通请求仍可转发、凭据拦截和公共配额仍有效，
开启后可保存记录，再次关闭后历史不增长，以及页面独立显示安全代理状态。还验证 HTTPS 解析失败策略默认拒绝、页面切换兼容模式、
保存刷新后保留、非法模式拒绝及切回拒绝模式。实际隧道路径由 Go 集成测试验证。
模拟服务故意同时提供 Cowrie 名称标记和统一页面；“疑似”只验证规则分支，不证明真实检测准确率。

Go 集成测试另覆盖 HTTPS 目标、可信／不可信 HTTPS 上游、认证 SOCKS5、CONNECT 拒绝／超长响应、取消、目标地址拦截及接口层授权撤回、代理变化、预算耗尽。

后端样本及代理回归（需要 Go 1.26，无需 PostgreSQL）：

```sh
go test -p 1 ./honeydetect ./traffic -count=1
go test -race -p 1 ./honeydetect ./traffic -run 'Test(Behavior|CaptureSwitch|Passthrough|MaybePassthrough|SecurityProxyBlocksBeforeForwarding|TaskBudgetRealHTTPAndHTTPS|PolicyConcurrency)' -count=1
go test ./traffic -run '^$' -bench '^BenchmarkCredentialScan$' -benchmem -benchtime=200ms
```

凭据扫描基准使用八个合成密钥，测试 1 KiB、64 KiB、5 MiB 正文的无命中和尾部命中。
它只测扫描函数，不含数据库、TLS、转发及落库，不能直接代表代理整体吞吐。
Go 样本测试已被现有 `regression.yml` 后端全量测试覆盖；浏览器脚本目前手动运行。


## 历史 v4 内容风险与旧历史浏览器验收

```sh
ARTEX_ACCEPTANCE_CONTENT=1 ARTEX_ACCEPTANCE_IMAGE=jacketser/artex:honeypot-v4-candidate bash scripts/acceptance/run.sh
```

必须选择同时包含 v4 后端及独立提示前端的候选镜像；脚本不构建镜像。未设置 `ARTEX_ACCEPTANCE_CONTENT=1` 时仍只执行原有验收，兼容旧版镜像；新合成服务通过 Compose `content` profile 按需启动。

先保留原有代理／疑似／捕获／限流验证，再重启隔离应用清除该组刻意留下的进程内预算冷却，保留测试数据库。新增合成服务提供隐藏注册内容、普通响应头和未知路径 404，验证四请求后为 `no_signal`／`none`、独立内容提示、折叠摘要、刷新持久化及冷却 429。随后在临时库复制一条缺少新字段的 v3 历史，验证旧结论和提示保留、版本过期及读取不触发探测。目标收到的请求方法／路径、无凭据及原 Host 均单独核对。

输出新增 `result-content.json`、`result-legacy.json`、`content.png`、`legacy.png`；原结果和截图继续保留。两种合成行为分别为疑似和无信号，旧版复核为注入的历史数据，不能合并成真实样本评估。2026-11-07 的构建、失败尝试及最终证据见[分离验证报告](../../HONEYPOT-CONTENT-SEPARATION.md)。

## 历史脱敏维护命令验收

```sh
ARTEX_ACCEPTANCE_IMAGE=jacketser/artex:privacy-candidate bash scripts/acceptance/privacy-run.sh
```

使用独立内部网络、临时 PostgreSQL 和 `/tmp/artex-privacy-acceptance-*` 数据目录，不挂载正式数据或发布端口。
验证应用运行中维护被拒绝、停机后预览不写数据、备份后执行、凭据脱敏、大整数保留、审计完整、再次预览零变更及重启健康。
退出清理测试容器与网络，结果、测试备份和应用日志保留在上述临时目录；测试内容均为合成数据。
证据引用／哈希、旧报告和审阅过期、事务失败回滚、符号链接逃逸及凭据变更拒绝由 `historyprivacy` Go 集成测试覆盖。

历史脱敏的 `privacy-run.sh` 还验证三批处理（包含旧目录格式及两级目录 blob 迁移）、成功游标在新命令进程间恢复、第二批注入失败后的原指纹重试，以及失败审计不产生下一游标、旧报文提交后清理、用户其他文件保留和恢复文件继承迁移开关。宿主机 `--resume` 文件校验另用 Docker 参数替身验证，不访问正式部署。

## 完整代理链路压测

```sh
ARTEX_ACCEPTANCE_IMAGE=jacketser/artex:local bash scripts/acceptance/proxy-load/run.sh
```

需要 Docker Compose、宿主机 Python 3 和可用的 `golang:1.26-bookworm` 构建镜像。脚本编译仓库内的施压器，
测试 `ARTEX_ACCEPTANCE_IMAGE` 指定的应用镜像；应用改动必须先构建候选镜像。默认过程约数分钟。
只在内部 Docker 网络连接合成目标，无宿主机端口，不挂载正式数据，也不读取正式配置或密钥。
测试实例单独将代理监听设为容器网卡以供施压器连接，正式实例的回环监听不受影响。

测试经过真实 PostgreSQL 凭据查询、HTTP/HTTPS 解密代理和 SQLite/正文存储。使用固定字节的 `application/octet-stream` 合成正文（不代表真实页面全文索引负载），包含匹配负载的直连基线、
捕获开关、1/8/16 并发、1 KiB/64 KiB 请求及响应、4 并发 5 MiB 请求、认证 HTTP 上游及 HTTPS CONNECT，
并进行 90 秒、最高 80 请求/秒的 HTTPS+上游+捕获持续负载。突发场景按固定请求数执行，
包含建连和 TLS 初始开销，无预热；持续场景按时间限速。保留全程延迟，包含失败请求，不对性能数字设通过阈值。

为区分正常防护限流与处理能力，测试库请求配额临时提高到允许的 30000/分钟；正式设置不变。
每轮核对目标实际收到的请求数、请求/响应 SHA-256、目标认证保留、上游确实使用、捕获记录数一致。
额外混合并发验证普通请求通过、平台凭据原文/Base64 与超限正文在目标前被阻止，最后验证主动触发 429。
出现错误或缺失记录会退出非零；不会修改断言来将遗漏抓取视为成功。

每 0.5 秒采集应用进程 RSS、CPU 时间、线程数和 FD，以及可用的 cgroup 内存/事件计数、`memory.stat` 和 `io.stat`。每场景保留保存阶段计数器的前后快照；支持统计的镜像还要求写入失败不增加、成功计数与新增记录数一致。
结果保存在 `/tmp/artex-proxy-load-*` 的 `summary.json`、`summary.md`、`results.json`、`resources.jsonl`、
`guard.json` 和 `security-stats.json`；镜像、健康版本和主机信息一并保存。清理测试容器、卷与网络后保留结果。
原始容器日志含测试实例初始化信息，不应直接作为正式日志发布。

这是同机合成负载下的基线：采样可能错过短时峰值，90 秒不是数小时稳定性证明；
未覆盖多任务身份并发、HTTP/2、WebSocket、HTTPS/SOCKS5 上游的负载表现、真实互联网延迟或未知凭据。
这些路径已有的功能回归不能代替对应负载测试。超过缓冲阈值的响应及 SSE 流式捕获不在本次完整记录断言范围。

设置 `ARTEX_LOAD_MODE=profile` 可运行保存专用的 8 场景短轮：HTTP/HTTPS 各包含 1 KiB 单并发／16 并发、8 并发 64 KiB `text/plain`、4 并发 5 MiB 请求，全部开启捕获；共 4248 次正常请求，并保留混合拦截与配额验证。该模式不含直连、上游或 90 秒持续场景，不能代替完整模式。文本为重复合成内容，不能代替真实词汇分布。对比方法、阶段指标语义和结果见[保存性能报告](../../CAPTURE-PERFORMANCE.md)。

## 文本持续负载与重启校验

```sh
ARTEX_LOAD_MODE=soak bash scripts/acceptance/proxy-load/run.sh
```

默认 20 个 60 秒窗口，每秒最多 8 次、4 并发，轮换 HTTP/HTTPS＋认证 HTTP 上游＋捕获。
每窗口单独统计延迟与保存计数，窗口间会关闭客户端连接池并检查记录，应用和数据库全程保留，数据持续累积。
这不是同一条连接不间断运行 20 分钟，也不是最大吞吐测试。
`ARTEX_SOAK_WINDOWS`（1–120）、`ARTEX_SOAK_SECONDS`（1–300）、`ARTEX_SOAK_RPS`（1–30）可调整，延长时间会增加磁盘使用量。
管理 API 使用测试实例的刷新 Cookie，每十分钟自动续期；凭据仅在施压器内存中保留。

语料从当前 Git HEAD 的 `README.md` 和 `DEPLOYMENT.md` 生成，不读取工作区私密配置、不访问外部网站。
包含 8 组文档 HTML／JSON，响应目标约 16／64 KiB，实际字节数与 SHA-256 存在 `corpus.json`；请求为文档摘要 JSON。
保留文档词汇、中文、标点和嵌套 JSON，超过源文档长度时循环段落；并非真实网站抓包或广泛行业语料。
每次先用八组语料做短烟雾，再跑持续窗口，最后验证凭据／正文大小／配额拒绝和全文检索。

完成后只停止本轮隔离应用，复制其 SQLite 文件；离线校验使用项目相同版本的 Go SQLite 驱动，检查数据库完整性、
每条语料请求／响应的落盘 SHA-256、正文与索引数量、检索标记命中数及目标 Authorization 脱敏。
随后启动同一测试容器，重新登录并核对总数和全文检索。任一步失败整个脚本非零退出，缺少重启结果不计通过。
`index-snapshot/`、`offline-integrity.json`、`restart-check.json`、逐窗口资源摘要和原始采样保留在输出目录；测试容器与网络仍自动清理。
离线全量哈希覆盖本轮语料记录，混合防护样例另核对总数；仅普通停机／重启，不模拟断电或强杀。

快速验证脚本本身可运行 `ARTEX_LOAD_MODE=soak ARTEX_SOAK_WINDOWS=2 ARTEX_SOAK_SECONDS=3 bash scripts/acceptance/proxy-load/run.sh`。
这只验证流程，不能作为持续负载通过的依据。


## 真实蜜罐程序隔离评估

当前 v5 使用预先固定的源码／镜像计划，在内部 Docker 网络复跑三组既有样本：

```sh
for corpus in tuning holdout holdout-20261107; do
  bash scripts/acceptance/honeypot-real/run.sh "$corpus" scripts/acceptance/honeypot-real/regression-v5-20261108.json
done
```

16 个有效部署各测三次；三组全部已查看，均为回归集。保留四类结论、来源标签、配置／规则／镜像哈希及逐次结果；不跟随跳转或放宽 TLS。蜜罐为 0 疑似／3 复核／0 无信号／3 无法判断，正常为 0／4／5／1；没有新增独立留出或真实疑似命中。

[方法与构建要求](honeypot-real/README.md)、[实际评估报告](../../HONEYPOT-EVALUATION.md)、[v5 逐项比较](results/honeypot-v5-real-comparison-20261108.json)。原 v1 七部署基线、v2 分组评估与 2026-11-07 新应用留出保留历史版本含义；省略第二参数的旧入口检查 v2 源码，不能用来测 v5。脚本完成只表示测量完整，不代表效果达标或公网准确率。
