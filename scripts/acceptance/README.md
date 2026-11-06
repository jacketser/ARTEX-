# HTTP 行为验证与代理设置浏览器验收

在仓库根目录执行：

```sh
bash scripts/acceptance/run.sh
```

验收本轮已构建的本地候选版本：

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

测试经过真实 PostgreSQL 凭据查询、HTTP/HTTPS 解密代理和 SQLite/正文存储。包含匹配负载的直连基线、
捕获开关、1/8/16 并发、1 KiB/64 KiB 请求及响应、4 并发 5 MiB 请求、认证 HTTP 上游及 HTTPS CONNECT，
并进行 90 秒、最高 80 请求/秒的 HTTPS+上游+捕获持续负载。突发场景按固定请求数执行，
包含建连和 TLS 初始开销，无预热；持续场景按时间限速。保留全程延迟，包含失败请求，不对性能数字设通过阈值。

为区分正常防护限流与处理能力，测试库请求配额临时提高到允许的 30000/分钟；正式设置不变。
每轮核对目标实际收到的请求数、请求/响应 SHA-256、目标认证保留、上游确实使用、捕获记录数一致。
额外混合并发验证普通请求通过、平台凭据原文/Base64 与超限正文在目标前被阻止，最后验证主动触发 429。
出现错误或缺失记录会退出非零；不会修改断言来将遗漏抓取视为成功。

每 0.5 秒采集应用进程 RSS、CPU 时间、线程数和 FD，以及可用的 cgroup 内存/事件计数。
结果保存在 `/tmp/artex-proxy-load-*` 的 `summary.json`、`summary.md`、`results.json`、`resources.jsonl`、
`guard.json` 和 `security-stats.json`；镜像、健康版本和主机信息一并保存。清理测试容器、卷与网络后保留结果。
原始容器日志含测试实例初始化信息，不应直接作为正式日志发布。

这是同机合成负载下的基线：采样可能错过短时峰值，90 秒不是数小时稳定性证明；
未覆盖多任务身份并发、HTTP/2、WebSocket、HTTPS/SOCKS5 上游的负载表现、真实互联网延迟或未知凭据。
这些路径已有的功能回归不能代替对应负载测试。超过缓冲阈值的响应及 SSE 流式捕获不在本次完整记录断言范围。
