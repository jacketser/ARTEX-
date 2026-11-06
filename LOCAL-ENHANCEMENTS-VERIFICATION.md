# 本地增强验收记录

最近验收日期：2026-11-06（Asia/Shanghai）；保留此前发布记录。

按版本阅读功能变化和升级注意事项见[二开更新日志](CHANGELOG-LOCAL.md)。本文保存验证证据与发布详情；下文候选验收中的“未部署”等状态仅指当时阶段，后续正式发布以对应发布记录为准。

- 源码目录：`/home/ARTEX`。
- 本地分支：`feature/local-enhancements`，已推送到 [jacketser/ARTEX-](https://github.com/jacketser/ARTEX-/tree/feature/local-enhancements)。
- 当前部署版本：`dev-3d72515`，应用源码对应 `3d72515`，正式服务已更新。
- 最新发布加入历史活动流量和证据的停机预览／指纹脱敏命令；保留行为验证上游代理、HTTPS 解析失败策略及此前增强。其他已完成功能及未移植范围见 [二次开发计划](SECONDARY-DEVELOPMENT-PLAN.md) 与 [部署说明](DEPLOYMENT.md)。
- 应用与 PostgreSQL 容器健康；宿主机仍仅发布 `127.0.0.1:8787`，SSH 隧道方式不变。

## 正式发布：历史活动数据脱敏维护（2026-11-06）

- 功能提交 `3e513c2`，维护锁修正与命令验收提交 `3d72515`；正式版本 `dev-3d72515`。候选镜像 `jacketser/artex:privacy-candidate`，镜像 ID `sha256:be38dd3f8dc5ba24e412cbdc4dfa2b3ec5d2bad67c8764cef71fe65d4fa84225`。复用现有运行环境及前端，未升级基础镜像依赖。
- 新增 `artex history-redact` 与 `scripts/history-redact.sh`：停机只读预览、内容／凭据指纹校验、备份后执行、数量摘要审计。活动流量同步重建全文索引、更新正文长度及 blob 引用；证据重算哈希与快照 ID、更新绑定、递增证据版本，旧报告和审阅过期，处置状态保留。JSON 脱敏使用精确数字表示，避免大整数失真。详见[维护说明](HISTORY-REDACTION.md)。
- Go 专项覆盖预览不改业务数据、拒绝过期指纹和变化后的凭据、完整 blob／内联正文与索引脱敏、哈希与绑定一致性、证据事务失败回滚、原报告／审阅过期、重复执行无变更、缺失正文和逃逸符号链接拒绝、审计权限与 CLI 参数保护。
- 初次候选启动发现维护锁与复测初始化使用相同编号，导致隔离应用启动等待；正式服务未受影响。修正为独立编号并增加其他应用锁可用性回归后，专项 race、候选启动、维护和重启验收通过。初次候选未发布。
- 最终空 PostgreSQL 完整 Go 回归通过，日志：`/tmp/artex-privacy-full-final.log`；维护与命令专项 race：`/tmp/artex-privacy-race-final.log`；流量脱敏 race：`/tmp/artex-privacy-race.log`。最终编译／镜像日志：`/tmp/artex-privacy-compile-final.log`、`/tmp/artex-privacy-image-final.log`。
- 可重复命令验收 `scripts/acceptance/privacy-run.sh` 通过：运行中拒绝维护、停机预览 1 条待变更合成流量、备份后清理、再次预览 0 变更、审计开始／完成两条记录、重启健康，大整数及未泄露目标凭据断言通过。日志 `/tmp/artex-privacy-cli-final.log`，产物 `/tmp/artex-privacy-acceptance-mvokQYyS/`。
- 候选 Chromium 回归通过：四次行为验证继续经过上游，目标无凭据、原 Host 保留，冷却、配置保存、HTTPS 策略及关闭捕获仍防护均通过，页面错误 0。日志 `/tmp/artex-privacy-browser-final.log`，产物 `/tmp/artex-acceptance-iSnYbcOq/`。本轮未修改前端源码，未重新运行前端构建。
- 发布前正式库任务总数为 0；停止应用写入后备份至 `/home/ARTEX/backups/pre-history-redaction-20261106-183525/`。数据库及文件包可读性校验通过；环境、JWT 和初始登录文件哈希未变。发布日志 `/tmp/artex-privacy-publish.log`。
- 使用候选镜像对正式存储执行停机预览，`traffic` 和 `evidence` 均为 `rows:0, changes:0, applied:false`；结果保存在上述备份目录的 `traffic-preview.json` 与 `evidence-preview.json`。正式数据未执行脱敏重写。
- 正式健康接口版本为 `dev-3d72515`，未登录访问行为配置返回 401；运行中执行维护命令返回非零并提示停机。doctor 返回 0，唯一警告仍为未配置模型，日志 `/tmp/artex-privacy-doctor.log`。管理页保持 `127.0.0.1:8787` 与 SSH 隧道访问。
- 回退镜像 `jacketser/artex:rollback-before-history-redaction` 对应 `dev-2490a72`；无新增数据库表结构。旧程序不持有维护锁；只回退镜像无法恢复已脱敏内容，内容恢复需同批数据库和文件备份。
- 测试容器和网络均已清理，保留合成数据验收产物与正式备份。
- 剩余范围：大库分批、旧目录格式迁移、备份／冷归档／导出及日志／会话／资产元数据脱敏未实现；不保证未知凭据识别或物理擦除。真实样本效果评估和完整代理链路压测仍待补充。

## 正式发布：行为验证兼容全局上游代理（2026-11-06）

- 应用源码 `2490a72`，正式版本 `dev-2490a72`；候选镜像 `jacketser/artex:upstream-candidate`，镜像 ID `sha256:98e347cad397bd6c0cb6776fcce3b75043832e739ff0413db709c9307a5c189d`。复用现有运行环境，更新编译程序和嵌入前端，未升级基础镜像依赖。
- HTTP/HTTPS 目标通过 HTTP/HTTPS CONNECT 或 SOCKS5 连接本机已检查的固定 IP，保留目标 Host、SNI 和证书校验；HTTPS 代理证书也严格校验。代理凭据只用于握手，失败不回退直连。代理配置变化、撤回来源授权或公共预算耗尽时停止后续请求。
- 空 PostgreSQL 完整 Go 回归通过：`/tmp/artex-upstream-full-final.log`。首轮新增接口测试复用了已取消服务上下文的只读夹具而失败；修正该测试的上下文后，专项及新空库完整回归通过，未放宽断言。
- 行为验证专项 race 通过：`/tmp/artex-upstream-race.log`。覆盖认证 HTTP CONNECT、可信／不可信 HTTPS 上游、HTTPS 目标证书与 SNI、认证 SOCKS5 数值 IP、超长握手响应、拒绝与取消，以及接口级授权撤回、代理变化、预算和审计记录。
- 前端类型检查、13 项测试与静态生产构建通过：`/tmp/artex-upstream-web.log`；编译和候选镜像日志：`/tmp/artex-upstream-compile.log`、`/tmp/artex-upstream-image.log`。
- 隔离 Chromium 验收通过：四次行为验证请求全部走带认证 CONNECT 上游，原 Host 保留，目标未收到代理或目标凭据；冷却 429、设置保存刷新、原有解析失败策略、关闭捕获仍防护及切换保留历史均通过，页面错误 0。日志 `/tmp/artex-upstream-browser.log`，结果和截图 `/tmp/artex-acceptance-wPQVspxm/`。样例仅位于内部测试网络，无真实目标扫描或模型调用。
- 发布前正式库任务总数为 0；停止写入后备份至 `/home/ARTEX/backups/pre-behavior-upstream-20261106-175549/`。数据库 dump 经 `pg_restore --list` 验证，文件包经 `tar -tzf` 验证；环境、JWT 及初始登录记录哈希未变。
- 回退镜像 `jacketser/artex:rollback-before-behavior-upstream` 对应 `dev-50a2b6a`；无新增表结构，回退会恢复配置上游时拒绝行为验证的旧限制。发布日志 `/tmp/artex-upstream-publish.log`。
- 正式健康接口返回 `dev-2490a72`，未登录访问行为配置返回 401；`doctor` 完成，唯一警告为未配置模型，日志 `/tmp/artex-upstream-doctor.log`。管理页继续仅发布 `127.0.0.1:8787`。临时测试容器和网络已清理。
- 当前兼容边界：HTTP/HTTPS 上游须允许 CONNECT 到目标端口；目标须能在本机解析，尚不支持仅代理端可解析的域名。已发出请求不因配置变化撤回；真实误报／漏报数据、模型效果及完整代理链路压测仍待补充。

## 正式发布：HTTPS 解析失败策略（2026-11-06）

- 功能提交 `5e406f3`，下拉框可访问名称修正提交 `50a2b6a`；部署版本 `dev-50a2b6a`。候选镜像 `jacketser/artex:tunnel-candidate` 复用上一正式版本运行环境，装入本轮编译并嵌入新前端的程序；未更新基础镜像依赖。
- 默认拒绝已记录 HTTPS 协议解析失败的服务的新 CONNECT；可选择兼容透传。失败标记按主机及端口保留五分钟、最多 4096 项；原请求不重放。兼容模式仍检查任务身份、CONNECT 头及连接配额，并遵循全局上游；隧道正文不可检查，已有隧道需断开重连。
- 独立空 PostgreSQL 完整 Go 回归通过：`/tmp/artex-tunnel-full.log`。解析失败策略、捕获切换、任务配额和并发专项 race 通过：`/tmp/artex-tunnel-race.log`。覆盖真实畸形 HTTPS 响应、拨号前拒绝、兼容转发及全局上游、任务/公共配额、秘密来源故障、策略切换期间复核、旧配置缺省迁移、失效时间和缓存上限。
- 前端 TypeScript、13 项前端测试及最终静态生产构建通过：`/tmp/artex-tunnel-web.log`、`/tmp/artex-tunnel-web-final.log`。首次浏览器测试发现原生 select 的可访问名称混入选项文字，补明确标签后重新构建并通过最终验收。
- Chromium 最终验收通过：默认拒绝、切换兼容模式及提示、保存刷新后保留、非法模式不覆盖有效配置、切回拒绝；原有行为验证和捕获开关/防护回归同时通过，页面脚本错误 0。结果和截图：`/tmp/artex-acceptance-O95e57z2/`；日志：`/tmp/artex-tunnel-browser-final.log`。实际隧道转发由 Go 集成测试验证。
- 发布前任务总数/排队数均为 0。停止应用写入后备份至 `/home/ARTEX/backups/pre-tunnel-policy-20261106-171154/`；数据库 dump 通过 `pg_restore --list`，文件包通过 `tar -tzf`。环境、JWT 和初始登录记录文件哈希与发布前相同；未重置密码。
- 回退镜像：`jacketser/artex:rollback-before-tunnel-policy`，旧版为 `dev-protection-20261106-local`。无新增表结构；回退旧程序会恢复原先自动透明透传的兼容行为。
- 正式健康检查版本匹配；未登录统计接口返回 401；数据库配置检查确认有效策略为 `block`、捕获保持关闭。`doctor` 返回 0，唯一警告仍为尚未配置模型。访问端口保持 `127.0.0.1:8787`，继续 SSH 隧道访问。
- 发布/自检日志：`/tmp/artex-tunnel-publish.log`、`/tmp/artex-tunnel-doctor.log`。独立测试容器和网络已清理。

## 正式发布：代理防护与流量保存拆分（2026-11-06）

- 发布应用源码：`befdce2`。直接使用通过隔离浏览器验收的 `jacketser/artex:protection-candidate` 镜像，正式标签更新为 `jacketser/artex:local`；运行版本保留为 `dev-protection-20261106-local`，没有因改版本名重新编译。
- 发布前数据库任务总数和排队数均为 0。停止应用写入后备份到 `/home/ARTEX/backups/pre-protection-20261106-164459/`，包含 `postgres.dump`、`files.tar.gz`、镜像/源码记录和文件哈希。数据库备份通过 `pg_restore --list` 校验，文件包通过 `tar -tzf` 校验。
- 回退镜像：`jacketser/artex:rollback-before-protection-split`，对应旧运行版本 `dev-3635912`。本次未更改数据库表结构；回退镜像会恢复旧版“捕获关闭即无代理防护”的行为。
- 应用与 PostgreSQL 健康，仍绑定 `127.0.0.1:8787`。健康接口版本匹配；未登录访问代理统计返回 401。`doctor` 返回 0，唯一警告仍是未配置模型。
- 正式库只读确认：流量捕获保持关闭；内置 browser MCP 已保留本地安全代理和 CA 配置。`.env`、`jwt.key`、`.deployment-credentials` 的 SHA-256 与发布前一致；未读取并输出其内容，也未重置密码。
- 发布日志：`/tmp/artex-protection-publish.log`；自检日志：`/tmp/artex-protection-doctor.log`。以下候选验收段落为发布前记录。

## 本地候选：代理防护与流量保存拆分（2026-11-06）

- 已在本地代码完成拆分：关闭流量捕获仍向 Agent 和内置浏览器提供安全代理、任务归属和 CA，保留凭据检查与限额；开关只影响流量保存和 Agent 流量查询工具。原历史保留，切换期间的请求不会在重新开启后补录。
- 后端完整回归在独立空 PostgreSQL 通过：`/tmp/artex-protection-full.log`。捕获切换、真实 HTTP/HTTPS 拦截、任务配额和并发专项 race 通过：`/tmp/artex-protection-race.log`。包含保存状态重启恢复、内置浏览器代理/CA 配置、配额不被切换清零及请求进行中切换不落库。
- 前端 TypeScript、13 项测试及静态生产构建通过：`/tmp/artex-protection-web.log`、`/tmp/artex-protection-web-build.log`。
- 候选镜像 `jacketser/artex:protection-candidate`，版本 `dev-protection-20261106-local`。标准 `Dockerfile.source` 构建触发基础镜像/依赖重新下载后主动停止；改用现有运行镜像 `sha256:e948df1514eb207f3b3ce5d9262605308751e9b9d4e0c72696c8af1de0130f89`，装入本轮 Go 编译并嵌入新前端的程序。编译/镜像日志：`/tmp/artex-protection-compile.log`、`/tmp/artex-protection-candidate.log`。本次不声称验证了更新后的基础镜像依赖。
- 隔离 Chromium 最终验收通过：保存关闭时普通请求仍转发、私钥标记请求返回 403、收紧公共配额后返回 429；保存开启时生成记录，再次关闭后记录数量不变。行为验证原有四请求、冷却、历史、参数保存/刷新也通过，页面脚本错误 0。
- 最终结果及截图：`/tmp/artex-acceptance-2bHh21xC/`；日志：`/tmp/artex-protection-browser-final.log`。首次浏览器运行在设置页等待超时，诊断重跑通过；脚本已将测试登录状态改为在页面初始化前写入，并保留失败时的地址、脚本错误及截图，最终重跑通过。内部测试网络不能访问 GitHub，更新检查提示离线属于预期。
- 临时数据库、应用和网络已清理。本轮未改正式数据库、未部署或推送；正式服务只读健康检查仍为 `dev-3635912`。

## 浏览器验收与样本回归（2026-11-06）

- 新增可重复运行的 `scripts/acceptance/run.sh`：每次使用独立 Docker 内部网络、空 PostgreSQL 和模拟 HTTP 服务，不挂载正式数据或发布端口，退出自动清理测试容器和卷。
- 实际执行 Chromium 验收通过：行为验证开关与精确来源保存、代理限额保存和刷新、非法参数拒绝、未确认按钮禁用、确认后四次请求、历史记录、冷却返回 429、模拟目标未收到认证凭据、公共预算统计为 4；页面脚本错误 0。
- 最终浏览器输出：`/tmp/artex-acceptance-aiu7yPeJ/result.json`；同目录保留设置/资产截图和隔离容器日志。浏览器验收的应用镜像版本为 `dev-3635912`。
- `go test -p 1 ./honeydetect ./traffic -count=1` 通过：新增十个正常服务兼容样本及请求间撤回授权检查；真实代理集成回归扩展到 HTTP 与 HTTPS，验证被拒请求不抵达目标、普通目标认证可以转发、凭据源读取失败拒绝转发。日志：`/tmp/artex-acceptance-go.log`。
- 行为验证、HTTP/HTTPS 凭据拦截、任务配额和并发限额专项 `-race` 检查通过；八个合成密钥的扫描基准完成，64 KiB 无命中约 156.4 μs/次、5 MiB 约 12.7 ms/次，不代表完整代理吞吐。日志：`/tmp/artex-acceptance-race-bench.log`。
- 代理覆盖核查及剩余事项见 [代理验证说明](PROXY-SECURITY-VALIDATION.md)。本轮仅修改测试、验收工具及文档，未执行新部署；合成样本不能替代真实误报/漏报评估。

## 上一轮验收：蜜罐、恢复、冻结补偿、场景提示词（2026-10-20）

- 固定源码后，以独立 PostgreSQL 空库运行完整 `go test -p 1 ./... -count=1`，全部通过（`/tmp/artex-next-stable-tests.log`）。此前一次完整运行曾在旧人工结论过期断言失败；当时测试与代码修改重叠，停止修改后重新全量运行通过。
- 场景指导、任务计时、蜜罐配置、恢复通知及冻结补偿专项 race 检查通过。覆盖时钟前跳/回拨/长停顿、关闭/超上限、并发幂等、无截止任务恢复计时、数据库失败暂缓超时、旧规则恢复不复活人工结论、同规则保存不失效。
- TypeScript、前端 9 项测试、Next.js 静态生产构建及完整源码镜像构建通过。
- 隔离候选镜像 Chromium 验收通过：恢复失败确认与历史备注、冻结参数/非法配置拒绝/补偿历史、蜜罐规则编辑与来源、场景编辑/预览/字符上限/关闭、通知默认不勾选；页面脚本错误 0。样例均为合成数据，未调用模型、未扫描目标、未发送外部消息。
- 单独通过 API 保存新规则并轮询资产，确认后台自动重评完成，无需手动识别。页面快照不会实时替换后台结果，已打开的列表需刷新或执行本页识别。
- 场景提示词验证显式标签持久化及 Worker 每轮注入、关闭/无效配置处理；固定授权边界与长度上限保留。没有进行真实模型质量或 Token 成本 A/B 验证。
- 蜜罐仍为已有元数据规则提示，默认产品名规则不视为经验证的产品指纹。冻结补偿通过模拟时间差验证，未主动冻结宿主机；不补偿进程重启停机或撤销单次调用/Worker 自身超时。
- 正式实例只读检查：健康/版本、原密码登录、新 API 鉴权、默认配置、设置与资产页面、原并发限制通过；`doctor` 返回 0，仍未配置模型。

## P1 验收（2026-10-20）

- 独立 PostgreSQL 全套 Go 回归全部通过（`/tmp/artex-p1-release-full.log`）；企业范围缺失测试已恢复通过，异步任务测试保留原断言并改为截止时间轮询与取消清理。
- P1/恢复专项 `go test -race ./server -run 'Test(P1|Recovery)' -count=1` 通过。覆盖观察结果、错误 Worker 不算进展、晚于观察期的结果不改写成功、暂停中断、提醒清除、参数边界、历史分页。
- 蜜罐测试覆盖元数据变化后评估及人工结论过期、旧指纹拒绝、自动重评、过滤及不覆盖其他 extra 字段。重复应用迁移 SQL 通过，旧版无时间标记评估会排队重评。
- 流量比较覆盖相同、不同、正文缺失/损坏、256 KiB 上限、8 组上限、不泄露头值/正文；缺失正文不能沿用支持结论。审阅历史验证 GET 不写历史、POST 写入、旧指纹拒绝、继承上下文只读。
- TypeScript、Next.js 静态生产构建、源码镜像构建通过；前端 9 项测试通过（Node 22，`--experimental-transform-types`，覆盖 SSE、活动合并、聊天引用）。
- 候选镜像 Chromium 验收通过：恢复参数保存及非法参数拒绝、恢复历史/站内提醒、自动蜜罐评估、人工排除/状态筛选、流量对比/证据跳转、自动及人工审阅历史、复测说明预填；发现处置状态未变化，页面脚本错误 0。
- 隔离实例修改资产元数据后，后台重新评估完成，旧人工结论保持过期。没有调用真实模型或向目标发送探测请求。
- 正式实例只读验收：健康/版本、原密码登录、设置/接口鉴权/页面、默认恢复参数、并发配置通过；`doctor` 返回 0，仍提示未配置模型。
- 新增 `.github/workflows/regression.yml`：临时 PostgreSQL 全套 Go 回归、前端类型/9 项测试/静态构建。远端实际运行结果以 Actions 为准。

## 历史增强验收

| 验证 | 结果 |
| --- | --- |
| 前端 TypeScript 检查、静态生产构建、完整源码镜像构建 | 通过 |
| 模型调用超时、调用方取消、短截止、流式提前退出、静默终止 | 通过；另运行 `TestCall*` 的 Go race 检查 |
| 任务等待原因分类及工具生命周期清理 | 通过 |
| 自动反证审阅：证据指纹、人工复核、独立对照、最新复测和类别建议 | 通过；只读，不访问目标、不调用模型、不改处置状态 |
| 任务卡住自动恢复：暂停/排队/审批/工具/模型/任务操作门控、冷却、持久化次数上限、进度重置 | 专项测试及 Go race 检查通过；只唤醒引擎，不重放工具 |
| 静态蜜罐识别：签名归一化、评分/置信度、重复字段去重、资产 extra 保存 | 规则及接口测试通过；校验 1–200 个 ID、去重、鉴权、缺失资产和非法请求，保留已有元数据；不发行为探针 |
| 初始化保护、页面改密、哈希重置吊销旧令牌、条件更新防并发覆盖 | 通过 |
| SSE 票据有效期、路由绑定、一次消费、容量限制、改密后未用票据失效 | 通过 |
| 已打开 SSE 在凭据吊销后关闭 | 通过 |
| 前端流重连领取新票据、恢复游标、卸载时取消连接 | 通过 |
| 证据复核必填项、旧证据拒绝覆盖、独立于处置状态、导出不掩盖不确定性 | 通过 |
| 工具版本清单、文件变化及目录误用检查 | 通过 |
| 独立全新数据库的 `db` 包及 `server` 包完整回归 | 通过 |
| 全仓库 Go 回归 | P1 已修复下述既有失败，`go test -p 1 ./... -count=1` 全部通过 |
| Chromium 页面验收 | 登录、强制切断 SSE 后自动重连、无长期 JWT URL、复核保存、过期提示、报告导出、任务总览诊断均通过；页面脚本错误 0 |
| 正式容器只读验收 | 健康检查、原密码登录、受保护 API、SSE 票据消费及重放拒绝、URL JWT 拒绝通过 |
| 正式容器 `artex doctor` | 返回 0；唯一警告为尚未配置模型 |

上一轮在镜像 `dev-7fb5db5` 上重新进行 Chromium 验收：恢复开关保存及刷新、
漏洞自动审阅、自动审阅失败时仍可填写人工复核、保存后同步审阅、证据变更后过期提示、
漏洞处置状态不变、全局/任务服务资产列表的识别与刷新、任务总览恢复状态均通过，页面脚本错误 0。
正式实例仅进行健康、登录、设置、接口鉴权与页面只读验收；测试样例全部留在隔离库中。

上一轮采用独立 PostgreSQL 容器，并为各 Go 包分配独立空库。初次把构建与回归并行时，
`server.TestCoreTaskLifecyclePG` 的 3 秒异步等待曾超时；停止并行构建后，另建空库运行
完整 server 回归通过。另修正 `llmrec` 测试未自行初始化计量表、依赖其他包先建表的问题，
再次在空库验证通过；该改动仅涉及测试准备。完整 db 包、新增规则/接口测试和恢复 race 检查均通过。

上一轮全仓库测试中的既有失败为 `agent.TestGraphOverviewExpandsAssociatedCompanyScope`：
`task scope missing: <nil>`。已在未修改的原版提交
`4379d692905ccd142547c73d7d11c2ff8958cdaa`、另一个独立数据库上复现。
该问题现已在 P1 修复：总览重新包含任务范围、关联企业范围和关键词，并对条数和文本长度设上限；P1 全套回归通过。

数据库测试使用临时 PostgreSQL，并以独立空库完成最终验收。浏览器验收中的任务和发现均为
临时数据库里的合成样例，没有写入正式库；未执行真实模型调用或目标扫描。
自动反证审阅改善的是证据完整性和人工核对效率，尚未进行真实模型误报/漏报或 Token 成本 A/B 评估；蜜罐识别是签名提示，不代表目标被确认。

## 未移植功能

尚未落地的是完整内网作战、会话/隧道/凭据库、分布式节点、伪装门控、限时自动放行、非 HTTP 协议行为探针，以及自动发起按类别的证伪请求。HTTP/HTTPS 人工行为验证已实现，并在 2026-11-06 补齐上述浏览器验收。详情见 [二次开发计划](SECONDARY-DEVELOPMENT-PLAN.md)。

## 发布与备份

### 冻结补偿与场景提示词发布（2026-10-20）

2026-10-20 20:00（Asia/Shanghai）发布 `dev-e0556f7`，源码提交 `e0556f7`。
发布前确认没有运行或排队任务，停止应用写入后备份：

`/home/ARTEX/backups/pre-clock-scenes-20261020-200039/`

包含 `postgres.dump`、`files.tar.gz`、`release.json`，数据库备份通过 `pg_restore --list` 校验。
回退镜像 `jacketser/artex:rollback-before-clock-scenes` 对应上一运行版本 `dev-d114064`。
新表与旧蜜罐评估增量迁移，未删除正式数据；原密码、JWT 密钥和环境配置哈希不变。
应用及数据库健康，保持 `127.0.0.1:8787` 与 SSH 隧道访问。回退镜像不自动回退数据库，必要时使用上述备份。

### P1 发布

版本 `dev-d114064`；发布前确认无运行或排队任务，停止应用写入后创建备份：

`/home/ARTEX/backups/pre-p1-20261020-174518/`

备份包含 `postgres.dump`、`files.tar.gz` 和 `release.json`；数据库备份已通过 `pg_restore --list` 校验。
回退镜像 `jacketser/artex:rollback-before-p1` 对应上一运行版本 `dev-7fb5db5`。
发布后应用及数据库健康，仅绑定 `127.0.0.1:8787`，通过 SSH 隧道访问；密码、JWT 密钥及环境配置保持不变。
数据库历史表与蜜罐重评队列已增量迁移，不删除已有数据。回退镜像不会自动回退数据库，必要时使用上述备份。

### 反证审阅、恢复与静态蜜罐发布（2026-10-19）

2026-10-19 23:51（Asia/Shanghai）发布前再次确认正式库没有运行或排队任务，停止应用写入后创建：

`/home/ARTEX/backups/pre-review-recovery-20261019-235120/`

- `postgres.dump`：发布前完整数据库备份，已用 `pg_restore --list` 验证。
- `files.tar.gz`：数据、技能、密钥、环境配置和初始登录记录。
- `release.json`：源码提交、运行版本和回退镜像 ID。
- 回退镜像：`jacketser/artex:rollback-before-review-recovery`（上一运行版本 `dev-2ac7047`）。

正式更新后程序版本为 `dev-7fb5db5`；应用及数据库均健康，仍仅绑定 `127.0.0.1:8787`。
原登录密码可用，密钥、环境配置和初始登录文件的 SHA-256 与发布前一致；单 worker、
单任务并发设置保持不变。新增恢复状态表已迁移，自动恢复默认开启。
该次升级不改变认证格式，不要求额外改密或重新生成密钥。

### 首轮增强的历史备份

首轮发布也在确认空闲、停止应用写入后创建备份：

`/home/ARTEX/backups/pre-enhancements-20261019-210622/`

- `postgres.dump`：PostgreSQL 自定义格式备份，已通过 `pg_restore --list` 读取校验。
- `files.tar.gz`：`data`、`skills`、JWT 密钥、环境配置和初始登录记录。
- `release.json`：发布源码提交及回退镜像名称。

备份目录权限为 700，文件仅本机管理员可读。正式更新后已逐字节比对 `jwt.key`、`.env`、
`.deployment-credentials` 与备份中的内容，保持一致。
回退镜像保留为 `jacketser/artex:rollback-before-enhancements`；回退数据库和旧版认证的注意事项见部署说明。

首轮认证增强升级需要重新登录。后续正常重启保留新版登录；改密或重置密码会吊销已有登录。
验收完成后，临时应用、临时数据库及 Go 测试容器已清理；Go 构建缓存与前端依赖保留供后续二次开发使用。

## 代理安全与续期开发验证（2026-10-20）

- 全新隔离 PostgreSQL 完整 Go 回归通过（/tmp/artex-security-go-clean.log）。初轮保留旧测试库时出现残留样例干扰，另有旧输出格式/原文保存断言，已更新为信任封装与脱敏语义；未修改正式数据。
- 前端 TypeScript、9 项已有回归与 4 项续期专项、静态构建通过。覆盖并发合并刷新、上传正文保留、401 仅重试一次、临时故障保留登录、退出与进行中刷新竞争。
- 后端专项覆盖首次设置/登录签发刷新 Cookie、轮换、并发重试、CSRF、错误凭据、上一代过窗复用吊销、退出/改密失效、空闲/绝对期限、数据库故障拒绝及 Secure Cookie。
- 代理真实 HTTP 集成测试验证已知密钥和超长 chunked 正文均未到达本地模拟目标，普通请求可以到达；另测 UA、熔断冷却/主机隔离、JSON 编码、脱敏不改线上原文、工具数据 JSON 隔离。
- 后续专项和候选验收使用 internal Docker 网络，无外网出口。测试密钥、密码和目标均为合成样例，不使用正式模型凭据。功能限制见二次开发计划；未进行真实模型提示注入攻防成功率评估。
- 认证/代理/信任边界专项 race 检查通过（/tmp/artex-security-race.log），包括 8 个真正并发的刷新请求返回同一后继；末次代理包完整回归通过。
- 完整源码候选镜像与静态前端构建通过，版本 dev-ec9fe3d。Chromium 验收通过：HttpOnly/Strict 刷新 Cookie、双标签页访问令牌过期后仅刷新一次、真实退出菜单同步到其他标签页、退出/改密后旧令牌拒绝、重启后自动恢复、设置页提示，页面脚本错误 0。
- 候选实例真实代理验证：数据库新写入的合成平台密钥在目标收到前被拒绝，目标 Authorization 和响应内容不被改变；SQLite 的 query/头/JSON 凭据已脱敏且带 X-Artex-Capture 提示。模拟目标只监听隔离容器的回环地址。
- 正式实例验收：原密码可登录、刷新/退出吊销、受保护 API、健康版本、并发配置通过；doctor 返回 0，唯一警告仍为没有配置模型。保持每任务 1 worker、最多 1 个任务和既有流量捕获开关。未在正式库创建业务测试样例。

## 代理安全与续期发布

2026-10-20 21:06（Asia/Shanghai）发布 dev-ec9fe3d，源码提交 ec9fe3d。确认无运行/排队任务后停止应用写入并备份：

/home/ARTEX/backups/pre-security-refresh-20261020-210656/

包含 postgres.dump、files.tar.gz、release.json；pg_restore --list 校验通过，目录权限 700。回退镜像 jacketser/artex:rollback-before-security-refresh 已校验，对应 dev-e0556f7。新 auth_sessions 表增量迁移，不删除旧业务数据。原密码哈希、jwt.key、.env 和初始登录文件哈希保持不变。应用/数据库健康，仍只绑定 127.0.0.1:8787。此次认证格式升级需要重新登录一次；回退旧认证方式时须更换签名密钥以免接受旧凭据。

验收结束后已清理隔离应用、测试 PostgreSQL 及其数据卷、Go 测试容器和隔离网络；保留源码镜像与命名构建缓存。
