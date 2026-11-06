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
