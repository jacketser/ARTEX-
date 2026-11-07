# 内容风险与蜜罐结论分离验证

日期：2026-11-07。开发基线 `2b761e7`，算法 `http-behavior-v4`；应用源码 `6d4aa09` 已正式发布为 **`dev-6d4aa09`**。下文开发／候选验收中的未部署状态为对应阶段记录。

## 变化与依据

前序 [AgentCapture 审阅](AGENTCAPTURE-REVIEW.md)及[接入／诊断对照](HONEYPOT-ENROLLMENT-CHECK.md)表明，隐藏注册与心跳文字只能提示内容风险：合法运维说明也可能包含同一组合，尚无足够独立证据将其作为蜜罐判断依据。v3 虽未让该提示参与疑似升级，但会单独触发 `needs_review`。

v4 将提示从 `signals` 移至独立 `content_warnings: string[]`，无提示时返回空数组。它不改变蜜罐 `outcome`／`confidence`：仅有此内容且完成稳定对照时为 `no_signal`／`none`；若还有名称或行为差异，仍按原有规则复核；只有原有行为差异和持续响应头佐证才能升级疑似。内容匹配条件、静态名称表、四请求范围、严格 TLS、跳转停止及授权策略不变。

共用历史组件在折叠摘要显示“有内容风险提示”，详情单独显示提示与“未发现行为线索不代表内容可信”。不展示原文、回连 URL 或令牌。即使探测后来无法判断，已从完整响应取得的内容提示仍保留；截断内容不产生提示。

行为版本升级使 v3 及更早历史按现有机制标记过期，不改写其原始 JSON、不自动重测。前端兼容旧历史缺少新字段；旧版 `signals` 中的内容提示仍照原记录展示，无历史迁移。正式更新时须同时发布前后端，否则旧页面不能展示新字段。

## 本轮证据

仅做开发回归，不新增独立留出或真实软件部署测量。`TestBehaviorHiddenEnrollment` 的七种合成服务合计 25 次请求；下表不是检测准确率统计：

| 合成场景 | 蜜罐结论 | 内容提示数 |
| --- | --- | ---: |
| 隐藏注册内容、普通响应头、未知路径 404 | 无信号 | 1 |
| 隐藏内容＋持续名称响应头，无行为差异 | 人工复核 | 1 |
| 隐藏内容＋统一页面，无名称响应头 | 人工复核 | 1 |
| 隐藏内容＋统一页面＋持续名称响应头 | 疑似 | 1 |
| 两次主页正文不稳定 | 无法判断 | 1 |
| 正文截断 | 无法判断 | 0 |
| 首次响应跳转，立即停止 | 无法判断 | 1 |

总计 1 疑似／2 人工复核／1 无信号／3 无法判断。提示独立计数，重复响应去重；测试同时验证置信度、JSON 往返、提示未混入 `signals`、无诱导 URL 泄出和未访问注册／心跳路径。合成文本已知并用于开发，不能当作真实合法服务反例或留出。

- `go test -p 1 ./honeydetect -count=1 -v`：全包通过，29.072 秒，包含原有产品文档回退、TLS／跳转／代理等边界。日志 `/tmp/artex-content-v4-go.log`。
- 全新内部 Docker 网络、独立 PostgreSQL：`go test -p 1 ./server -run '^TestBehaviorAuthorizationAuditAndPolicyAPI$' -count=1 -v` 通过，包耗时 1.553 秒。验证 v4 独立提示经历史 API 原样返回，v3／v2／v1／无版本结果过期且原始字段保持。日志 `/tmp/artex-content-v4-api.log`。
- 前端 `node node_modules/typescript/bin/tsc --noEmit --incremental false` 通过；`node --test src/components/honeypot-behavior.test.mjs` 两项通过，覆盖四种结论下的独立提示、折叠摘要、文本转义和旧历史。日志 `/tmp/artex-content-v4-tsc.log`、`/tmp/artex-content-v4-ui.log`。组件测试使用真实 React 静态渲染并注入历史状态，不等同浏览器交互验收。

Go 使用 `golang:1.26-bookworm`、`GOMAXPROCS=2`、`-p 1` 与现有模块／编译缓存。仅挂载跟踪源码的独立快照，未挂载正式数据或凭据；全包容器无网络，API 容器仅内部网络。测试数据库容器及其匿名卷、网络已清理。临时日志不是永久制品，回归源码随提交保存。

## 候选构建与真实浏览器补充（2026-11-07）

应用源码固定 `6d4aa09`，运行版本 `dev-6d4aa09`；构建前工作区干净。候选镜像 `jacketser/artex:honeypot-v4-candidate`，ID `sha256:1357072ed9e5329d5879253da779a6e56b3101cf8b0b956fa34c09f1f845ddbd`。从 Git 归档构建全新 Next.js 静态前端（31 页、类型检查通过），随后 Go `-p 1 -tags embedui` 编译并嵌入，未复用旧前端。使用现有 `node:22-bookworm-slim`、指定 Go 镜像及缓存，运行环境复用 `honeypot-v2-candidate`；无依赖升级，不声称重新验证基础依赖供应链。

构建容器 `--network none`，仅挂载源码快照／前端依赖／缓存；没有加载正式 `.env`。构建脚本 `/tmp/artex-content-v4-build.sh`，日志 `/tmp/artex-content-v4-build.log`，源码与产物目录 `/tmp/artex-content-v4-build-y5OxnAwF/`。永久版本、二进制／工具／结果哈希见[结构化记录](scripts/acceptance/results/honeypot-v4-browser-20261107.json)。

以该候选运行[浏览器验收](scripts/acceptance/README.md#v4-内容风险与旧历史浏览器验收)，全部服务使用内部网络、新建 PostgreSQL、无宿主机端口及正式数据挂载，真实 Chromium 验证：

- 原有检查通过：持续响应头＋统一页面为疑似，四次请求全部经过认证 CONNECT 上游，目标无凭据且 Host 正确；五分钟冷却、策略保存／刷新、捕获关闭仍防护和捕获历史保持不变。
- 内容合成服务：四次状态 200/200/200/404，蜜罐 `no_signal`／`none`，`signals=[]`，独立 `content_warnings` 仅一条；折叠摘要提示风险、展开详情可见、刷新后持久化。再次发起为 429，目标仅收到预定四次 GET／HEAD，无注册／心跳请求或目标凭据。
- 复制一条 v3 合成历史后，旧 `needs_review`／`low`、旧提示和缺少新字段的 JSON 保持；页面标记过期，不伪装成 v4 提示区。读取／展开新旧历史后目标请求仍为四次，无自动重测。
- 三个浏览器阶段页面脚本错误均为 0；人工查看最终截图确认新旧结果分别展示。原始目录 `/tmp/artex-acceptance-rXoq3sqs/`，最终日志 `/tmp/artex-content-v4-browser-final.log`。

前两次尝试中原有验收通过，新增内容探测却被上一组刻意触发的进程内限流冷却阻止（`security_budget_or_policy`，未发出目标请求）。第一轮日志 `/tmp/artex-content-v4-browser.log`，补诊断复现日志 `/tmp/artex-content-v4-browser-retry.log`。修正验收编排，在两组之间重启临时应用、保留测试数据库，最终通过；没有放宽检测器或冷却逻辑，失败不计为通过。

测试容器、网络及临时数据库已清理。正式健康接口仍为 `dev-b7877ca`，本轮**未部署**，只新增验收工具与报告。

## 正式发布（2026-11-07）

在 `57b4938` 干净工作区核对候选镜像、程序哈希和验收工具摘要后，发布同一已验收镜像；未重新编译、未改基础依赖或数据库结构。发布前正式任务、归档、活动复测和运行中的行为探测均为 0；停止应用后再次确认无任务／活动复测／探测，数据库继续运行。

- 备份 `/home/ARTEX/backups/pre-honeypot-v4-20261107-110527/`：数据库自定义格式 dump 通过 `pg_restore --list`，`data`、`skills`、JWT、环境和初始登录文件的压缩包通过 `tar -tzf` 可读性检查；目录 700、文件 600。未开展将正式数据恢复到测试库的演练。
- 运行镜像 ID 与候选一致；程序 SHA-256 为 `6f0d3749dfde7c377c8623b662ebb64cc2c52f38a700faed6c3eb240d8b5b37b`。正式健康接口 `dev-6d4aa09`，应用和数据库健康；仅发布 `127.0.0.1:8787`。
- `.env`、`jwt.key`、`.deployment-credentials` 哈希与发布前一致，未显示其内容。资产页面 HTML 及两个含独立内容提示的 JS 包与候选构建产物逐字节一致。
- doctor 无失败，唯一警告是尚未配置模型；未调用模型。发布后任务／活动复测／活动探测仍为 0，其他应用未重启。正式环境只做只读状态、自检和公开静态资源核对，未写入验收样例或发起目标探测。
- 回退镜像 `jacketser/artex:rollback-before-honeypot-v4` 对应 `dev-b7877ca`。回退可读取现有数据，但失去内容提示能力，旧界面不显示 v4 独立字段，v4 历史会过期；原始 JSON 保留。操作见[部署文档](DEPLOYMENT.md#当前-v4-发布与回退)。

发布日志 `/tmp/artex-honey-v4-publish.log`，自检日志 `/tmp/artex-honey-v4-doctor.log`；[正式发布记录](scripts/acceptance/results/honeypot-v4-release-20261107.json)保存非敏感证据。前述[候选浏览器结果](scripts/acceptance/results/honeypot-v4-browser-20261107.json)保持当时未部署的历史事实，没有重写。

## 限制与剩余工作

这次改善结论表达与证据边界，没有扩大匹配覆盖，也没有证明提高真实蜜罐命中率或防止模型被接管。v3 的开发模板、154 个内容留出及后续针对性对照均未重跑，原结果与冻结工具保持原版本含义，不能用它们报告 v4 命中率。

仍缺独立注册型阳性和覆盖完整词组合的真实正常反例。前后端构建、隔离浏览器验收、备份及正式发布均已完成。本轮没有新增真实样本评估、长负载或模型实验；后续按证据缺口选样，或转入纯文本分享导出脱敏等短任务。其他优先级见 [PROJECT-STATUS.md](PROJECT-STATUS.md)。
