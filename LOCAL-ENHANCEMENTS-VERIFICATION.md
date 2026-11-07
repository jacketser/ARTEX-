# 本地增强验收记录

最近验收日期：2026-11-07（Asia/Shanghai）；保留此前发布记录。

当前状态及剩余工作统一见[项目总览](PROJECT-STATUS.md)。本文是按次留存的验证证据；后续文档整理不会新增或改变历史测试结论。

按版本阅读功能变化和升级注意事项见[二开更新日志](CHANGELOG-LOCAL.md)。本文保存验证证据与发布详情；下文候选验收中的“未部署”等状态仅指当时阶段，后续正式发布以对应发布记录为准。

- 源码目录：`/home/ARTEX`。
- 本地分支：`feature/local-enhancements`，已推送到 [jacketser/ARTEX-](https://github.com/jacketser/ARTEX-/tree/feature/local-enhancements)。
- 当前部署版本：`dev-b7877ca`，应用源码对应 `b7877ca`，正式服务已更新。
- 最新发布收紧蜜罐行为疑似升级并标记旧算法历史过期；保留有界流量合并提交、保存阶段统计、正文失败保护、格式 4 历史归档恢复、脱敏维护及此前增强。其他已完成功能及未移植范围见 [二次开发计划](SECONDARY-DEVELOPMENT-PLAN.md) 与 [部署说明](DEPLOYMENT.md)。
- 应用与 PostgreSQL 容器健康；宿主机仍仅发布 `127.0.0.1:8787`，SSH 隧道方式不变。

## 验证补充：冻结判定的新应用留出与旧样本回归（2026-11-07）

- 本轮仅修改验收工具、结果及文档，正式版本保持 `dev-b7877ca`，无部署／迁移／正式数据库测试。检测源码对比 `b7877ca` 无差异；`metadata-v2`、`http-behavior-v2` 和默认规则修订不变。
- 预先约定与配置提交 `e9bad8b` 后首次测量新留出：固定 Log4Pot 两个原装配置、httpbin 及 Datasette，共 4 部署／12 次，全部完成稳定四请求。蜜罐 0 疑似／2 复核／0 无信号／0 无法判断，正常 0／0／2／0；静态均无命中。Log4Pot 两配置只是一个新家族，不算两个独立家族。
- 原七部署和前次五部署都转为回归用途，各重复三次，共 36 次；逐轮结论、置信度和 HTTP 状态／错误码与 11 月 6 日一致。文档回退反例、认证、跳转及 TLS 停止全部保留。两组历史结果未重写，新的三组结果分别入库，见[评估报告](HONEYPOT-EVALUATION.md)。
- 新组每个 Log4Pot 日志核验预定的 15 次请求，全部 GET／HEAD、无凭据和非预期路径、无 exploit 事件；六类审计反例拒绝。三个分组均通过汇总有效输入与十类损坏反例；新增标签／观测／请求计数检查，失败删除旧摘要。
- `go test -p 1 ./honeydetect ./scripts/acceptance/honeypot-real -count=1`、驱动构建、Shell/Python 语法通过。沿用 `golang:1.26-bookworm`、`GOMAXPROCS=2` 和既有缓存：`/tmp/artex-honey-20261107-go.log`。正式后端／前端未改，未重复全量应用、race、浏览器或正式部署。
- 新留出镜像 `jacketser/artex:honeypot-holdout-20261107`，ID `sha256:68179e94ba989d6079d87cf73dbb7cfe7b92de9a5eb99ce6700adbe36a6d9cc2`；源码归档 SHA-256、配置、脚本／检测文件和依赖均留档。构建日志 `/tmp/artex-honey-20261107-build.log`。Git/raw 获取源码停滞后改为 API 固定归档；三组正式测量各一次完成，无排除的失败部署。
- 原始目录：新组 `/tmp/artex-honeypot-real-tYapeq5k/`、原调试回归 `/tmp/artex-honeypot-real-fQl3EaFb/`、原留出回归 `/tmp/artex-honeypot-real-YojPy8fD/`。完整运行、汇总反例、目标审计日志路径见评估报告。测试容器／网络已清理，正式健康正常，管理入口仍只在 `127.0.0.1:8787`。
- 结论：新增可分析的真实蜜罐和独立正常应用，但没有真实疑似命中，不证明识别能力提高。暂不调规则；统一页面与正常回退重叠，下一次判定修改须先有独立区分证据和新留出。数小时负载、敏感独立副本、大归档／残留和模型效果验证仍未实施。

## 正式发布：蜜罐文档回退误报收紧（2026-11-06）

- 源码 `b7877ca`，版本 `dev-b7877ca`，行为算法 `http-behavior-v2`。正文名称＋统一页面降为低置信复核；升级疑似要求两次主页 GET 与 HEAD 持续命中同一响应头字段／规则并存在行为差异。静态算法、默认名称表和 TLS／跳转／请求安全边界不变；旧算法历史过期但不改写、不自动重测。
- 全新隔离 PostgreSQL 全仓库回归通过：`/tmp/artex-honey-v2-full.log`；`honeydetect` 全包普通／race 通过：`/tmp/artex-honey-v2-tests.log`、`/tmp/artex-honey-v2-race.log`。Go 统一用 `golang:1.26-bookworm`、`GOMAXPROCS=2`、`-p 1` 与既有缓存。未在正式库跑测试。
- 判定在首次留出测量前冻结为 `b7877ca`。调试集 7 部署、21 次：蜜罐 0 疑似／1 复核／0 无信号／2 无法判断；正常 0／3／1／0。留出集 5 部署、15 次：Heralding 蜜罐 0／0／0／1；正常 Apache／Python 0／1／2／1。重复结论一致。原 nginx 文档回退疑似降为复核，新增 Apache 文档回退也只复核，真实蜜罐覆盖未提高。详细来源、原始目录及局限见[评估报告](HONEYPOT-EVALUATION.md)和分开的[调试结果](scripts/acceptance/results/honeypot-v2-tuning-20261106.json)／[留出结果](scripts/acceptance/results/honeypot-v2-holdout-20261106.json)。
- 最终验收驱动编译、Shell／Python 语法通过；两组离线汇总均通过有效输入与七类损坏反例，日志 `/tmp/artex-honey-v2-summary-tuning.log`、`/tmp/artex-honey-v2-summary-holdout.log`。
- 候选镜像 `jacketser/artex:honeypot-v2-candidate`，ID `sha256:03d7d6e9e18c9a178dbdab4af1cb8fa0be6f367cd0b6fb84b5a1c79bc27fdf40`，与实际运行镜像一致。从 Git 提取冻结源码、复用现有嵌入前端与运行环境编译，无前端、依赖、数据库结构或归档格式变更；未重复前端构建。编译日志 `/tmp/artex-honey-v2-release-build.log`；其中首次封装用本机镜像 ID 作为 FROM 被 Docker 拒绝，换为指向同一镜像的本地标签后成功：`/tmp/artex-honey-v2-image-final.log`。一次路径筛选脚本误把日志当目录的准备失败未计为验收通过。
- 候选实际 Chromium 隔离验收通过：四次行为请求经认证上游、无目标凭据、原 Host 保留、冷却 429、策略保存、捕获关闭仍防护与历史保持，页面错误为 0。合成持续响应头样本仍为疑似，不能代替真实阳性证据。日志 `/tmp/artex-honey-v2-browser-final.log`，原始目录 `/tmp/artex-acceptance-LbLfFg1O/`。
- 发布前正式任务／归档均为 0；停机后再次确认无任务，备份 `/home/ARTEX/backups/pre-honeypot-v2-20261106-233557/`。数据库 dump 经 `pg_restore --list`、文件包经 `tar -tzf` 校验；环境、JWT 和初始登录文件哈希保持不变。发布日志 `/tmp/artex-honey-v2-publish.log`。
- 正式健康接口为 `dev-b7877ca`，应用／数据库健康，仅发布 `127.0.0.1:8787`，仍经 SSH 隧道访问。doctor 返回 0，唯一警告为未配置模型：`/tmp/artex-honey-v2-doctor.log`。隔离测试容器／网络清理完毕，其他应用未修改。
- 回退镜像 `jacketser/artex:rollback-before-honeypot-v2` 对应 `dev-4a56616`。可读取现有数据，回退会恢复文档＋统一页面升级疑似的旧行为及旧历史过期判断；本次没有重写历史内容。备份与回退流程沿用部署文档。
- 剩余：更多独立正常应用／蜜罐家族和版本、能够完成对照的真实阳性与新的留出集；认证、跳转、严格 TLS 及非 HTTP 协议覆盖仍有限。P2 的长负载、独立敏感副本、大归档／残留与模型质量评估本轮未实施。

## 验证补充：蜜罐真实程序隔离评估（2026-11-06）

- 验收源码 `0f7a837`；固定 OpenCanary／QeeqBox 两个家族和 nginx 四种正常配置。7 个有效部署各测三次，21 次测量完整且结论一致；上游 basicLogin 缺少页面的部署单列排除，未计入分母。
- 蜜罐侧：元数据可评估 2 个、均未命中；行为仅 1 个完成对照并提示复核，另 2 个因 302／严格 TLS 无法判断。正常侧：2 个低置信名称命中；行为 1 个无信号、2 个复核、1 个疑似误报。详见[评估报告](HONEYPOT-EVALUATION.md)及[结构化测量](scripts/acceptance/results/honeypot-real-20261106.json)，不外推公网准确率。
- `honeydetect` 回归、驱动编译、Shell／Python 语法检查通过；删除测量、重复轮次、缺少目标和缺少完成标记四种反例均被汇总拒绝。原始结果 `/tmp/artex-honeypot-real-kez5efD5/`，成功日志 `/tmp/artex-honeypot-real-final2.log`，完整性反例 `/tmp/artex-honey-summary-negative-w6mjs45c/`。前四轮失败原因见方法报告，未计为通过。
- 本轮只增加验收工具和报告；无检测规则、正式依赖、数据库或前端修改，无重新部署。测试容器和网络清理完毕，正式健康接口保持 `dev-4a56616`，管理入口仍为 `127.0.0.1:8787`。
- 当前优先剩余：文档＋统一页面误报改进、独立正常／蜜罐留出集和授权现场样本；其他仍有长时间／更多语料与协议负载、独立历史副本脱敏、大归档／无引用残留维护。下文的未完成项为各次验收当时记录。

## 验证补充：20 分钟文档语料负载（2026-11-06）

- 应用保持 `dev-4a56616`；验收工具提交 `d1437e0`。测试镜像与正式镜像相同，仅在内部 Docker 网络和全新数据库运行，没有部署或重启正式服务。
- 8 组来自 Git 文档的 HTML／JSON 语料，20 个一分钟窗口、4 并发、最高 8 RPS，通过认证 HTTP 上游轮换 HTTP/HTTPS 并开启捕获。9612 次语料请求零错误，保存失败计数为 0，自动续期两次；混合 16 次普通请求成功、64 次预期拒绝未抵达目标，主动配额拒绝通过。
- 停止隔离应用（退出码 0）后检查约 1.01 GiB SQLite 快照，逐条校验全部语料的双向正文 SHA-256、长度及保存 Authorization 脱敏；正文／全文索引数量及标记匹配一致。重启后全部 9628 条记录与全文检索保持一致。
- 应用 RSS 峰值 64.6 MiB、空闲后 54.0 MiB；容器内存峰值 957.8 MiB、结束 935.9 MiB，其中结束文件缓存 877.8 MiB、匿名内存 30.1 MiB。无内存限额事件或 OOM。部分重复窗口尾延迟略升；这不是持续高并发或数小时稳定性证明。
- 完整日志 `/tmp/artex-text-soak-20m.log`，原始目录 `/tmp/artex-proxy-load-qpx39o9u/`；[结构化结果](scripts/acceptance/results/text-soak-20261106.json)和[方法报告](TEXT-SOAK-RESULTS.md)已入库。短烟雾 `/tmp/artex-soak-smoke4.log`、损坏正文拒绝检查 `/tmp/artex-soak-integrity-negative-yc5dsno3/rejection.log`。前三轮脚本适配失败及修正原因见方法报告，未计为成功验收。
- Python／Shell 语法检查和 Go 施压器编译通过；正式后端与前端未修改，未重复全量回归。隔离容器、卷、网络已清理；原始语料和测试快照保留在 `/tmp` 供复核，不包含正式数据。
- 主要剩余：数小时／更多真实语料／多任务及更多协议验证、蜜罐真实样本评估、独立历史副本脱敏、大归档及无引用残留维护。

## 正式发布：保存阶段分析与有界合并提交（2026-11-06）

- 应用源码 `4a56616`，正式版本 `dev-4a56616`。候选 `jacketser/artex:capture-batch-candidate`，镜像 ID `sha256:2da302f5c596c25085501ce8133d8e0b67f4b79268172de56756e5b12fa69b48`，与实际运行镜像一致。无数据库结构、归档格式、前端或依赖变更。
- 先对旧保存实现增加累计阶段计时，确认小请求逐条提交和写锁等待是主要开销；再实现无定时等待的合并提交，同时接纳最多 16 条、按输入大小记账 32 MiB。保留同批事务和同步等待语义；预算不等于整个代理内存上限。
- 两轮短对照各 4248 次请求零错误；16 并发小请求约提升 2.8～3.7 倍，合成文本约提升 31%～39%；单请求和大正文没有稳定收益，内存占用未降低。方法、计时口径和限制见[保存性能报告](CAPTURE-PERFORMANCE.md)。
- 新增回归验证 SQL 失败整批回滚（包含共享 blob 引用与全文索引）、故障解除后恢复、正文文件错误不保存截断记录、捕获关闭再开启不补录旧代次、16 条／32 MiB 准入边界及关闭排空后重开计数。记录 ID 使用纳秒时间与不取模序号，避免高吞吐回绕覆盖。
- `traffic` 全量回归通过：`/tmp/artex-capture-batch-tests.log`。`traffic` 全量 race 通过：`/tmp/artex-capture-batch-race.log`，包含恰好 5 MiB、HTTP/HTTPS、已知长度／chunked 及完整正文哈希回归。
- 全新隔离 PostgreSQL 的完整 Go 回归通过：`/tmp/artex-capture-batch-full.log`；该日志末尾另包含补强共享正文引用断言后的批量回滚专项 race。未修改前端，未重复浏览器检查。测试数据库与网络已清理。
- 正式源码实际镜像完整负载：31 场景、36337 次普通请求零错误；目标计数、双向哈希、目标认证、上游路由、捕获数量及保存计数一致，失败计数无增长。另有混合 16 次普通请求和 64 次预期拒绝，及一次主动配额拒绝。90 秒持续负载 7191 次、约 79.8 RPS、p95 27.3 ms。结果：[结构化数据](scripts/acceptance/results/capture-batch-full-20261106.json)，日志 `/tmp/artex-capture-batch-load.log`，原始目录 `/tmp/artex-proxy-load-b6J9WTRT/`。
- 进程 RSS 峰值 312.5 MiB、空闲后 60.6 MiB；cgroup 峰值约 1024.1 MiB、结束约 1019.3 MiB，其中结束时文件缓存约 948.9 MiB、匿名内存约 40.4 MiB。触及上限 1200 次，无 OOM；不能据 90 秒结果断言长期容量充足。
- 构建日志 `/tmp/artex-capture-batch-release-build.log`。正式任务／归档为 0；停机备份 `/home/ARTEX/backups/pre-capture-batch-20261106-213723/`，数据库 dump 与文件包可读性通过，环境、JWT 和初始登录文件哈希不变。活动流量／证据／旧目录预览均零记录、零变更，未重写正式内容。发布日志 `/tmp/artex-capture-batch-publish.log`。
- 健康接口 `dev-4a56616`，管理端口仍仅 `127.0.0.1:8787`。doctor 返回 0，唯一警告为未配置模型：`/tmp/artex-capture-batch-doctor.log`。隔离压测容器、卷和网络已清理，其他服务器应用未变更。
- 回退镜像 `jacketser/artex:rollback-before-capture-batch` 对应 `dev-074305e`，兼容新记录与既有归档格式；回退将失去合并提交、阶段指标和正文写入失败保护。文件先写后提交仍可能留下无引用文件，本轮没有新增断电保证或持久化失败重试队列。
- 下一步优先数小时持续负载与真实文本语料，观察文件缓存／内存和尾延迟；多任务／更多协议、真实蜜罐评估、独立副本脱敏、大归档／无引用残留维护仍待完成。

## 正式发布：完整代理负载基线与大正文漏记修复（2026-11-06）

- 应用源码 `074305e`，正式版本 `dev-074305e`；测试等待期限适配及报告 `534bfab`。候选 `jacketser/artex:proxy-load-candidate`，镜像 ID `sha256:47f28fc1a1a9dc72bcc32e6f0b5e2db2aedf30d3bae9967872aeb800372ad5ad`。仅调整代理缓冲切换边界，无数据库、前端或依赖变更。
- 隔离实际应用的 31 场景／36340 次正常合成请求零错误；目标计数、双向哈希、目标认证、上游路由及捕获记录数量均一致。另测混合 16 次正常请求和 64 次预期拒绝，以及一次主动配额拒绝。90 秒 HTTPS+上游+捕获负载完成 7194 次、约 79.9 请求/秒、p95 34.0 ms。
- 进程 RSS 峰值 244.7 MiB、结束约 58.8 MiB；cgroup 总内存约 1 GiB，触发上限事件但无 OOM。保存开启的小正文吞吐明显降低，后续需做保存链路计时及缓存／磁盘观测。完整方法、各场景数据和适用限制见[负载报告](PROXY-LOAD-RESULTS.md)与[结构化结果](scripts/acceptance/results/proxy-load-20261106.json)，不据此承诺真实站点容量或长期无泄漏。
- 旧镜像的 24 次恰好 5 MiB HTTP 请求成功转发却新增记录为 0，压测明确失败；定位到库在 >=5 MiB 时转为流式且跳过记录。将切换阈值移到请求硬上限加 1 字节后，候选 HTTP/HTTPS 各 24 次都完整保存，原请求上限保留。
- `traffic` 全量回归通过：`/tmp/artex-proxy-load-regression.log` 前半段。该日志的初轮竞态测试因大正文 SQLite／脱敏被插桩后超过测试 20 秒期限而失败，无数据竞态报告；仅将该测试期限改为 90 秒后，捕获／防护／任务配额专项 race 通过：`/tmp/artex-proxy-load-race-final.log`。边界测试验证 Content-Length/chunked、HTTP/HTTPS、请求与响应恰好 5 MiB 的完整存储哈希及超限拒绝。
- 编译／镜像日志：`/tmp/artex-proxy-load-compile.log`、`/tmp/artex-proxy-load-image.log`。最终实际负载日志 `/tmp/artex-proxy-load-final.log`，原始产物 `/tmp/artex-proxy-load-x5A4I7Dq/`。初轮隔离脚本监听配置修正和第二轮漏记失败见负载报告。测试容器、卷和内部网络均已清理；没有访问外部目标或正式业务数据。
- 正式任务／归档为 0；停机备份 `/home/ARTEX/backups/pre-proxy-load-20261106-210711/`，dump 与文件包可读性校验通过，配置／JWT／初始登录文件哈希不变。活动流量、证据和旧目录迁移预览零记录／零变更。发布日志 `/tmp/artex-proxy-load-publish.log`。
- 健康接口 `dev-074305e`，端口仍仅 `127.0.0.1:8787`。doctor 返回 0，唯一警告为未配置模型：`/tmp/artex-proxy-load-doctor.log`。本次没有修改正式捕获开关、请求配额或工具授权。
- 回退镜像 `jacketser/artex:rollback-before-proxy-load` 对应 `dev-cff6317`，兼容现有数据库和格式 4 归档；回退将重新出现本次修复的边界漏记。
- 主要待办：保存链路性能分析／优化、更长时间与真实文本索引／多任务负载；蜜罐真实样本评估；备份／导出／日志／会话等独立副本脱敏；大归档及无引用残留维护。

## 正式发布：复测与审阅历史归档恢复（2026-11-06）

- 应用源码 `cff6317`，正式版本 `dev-cff6317`；候选镜像 `jacketser/artex:history-archive-candidate`，镜像 ID `sha256:0ff2b1cb466be305236468e3474a25ed6ea52f01533cf606cb24a16d90f4ff27`。复用运行环境和嵌入前端，无新增业务表；调整归档默认版本和人工审阅历史触发器。
- 格式 4 保存终态复测及快照、当前人工复核、全部人工／自动审阅历史。恢复保留原 ID、时间、状态、指纹与过期语义；不会再次执行复测、改变处置结论或生成额外历史。有效会话链接保留，原会话已删除／类型改变时解除链接并提示；聊天正文仍独立保存在活动库。
- 活跃复测阻止归档，归档排队后拒绝新增复测、人工复核和自动审阅写入。清单校验表存在性、计数、任务归属、ID 唯一性、复测终态及会话引用。恢复任一步失败或 ID 冲突整笔回滚，不覆盖外部记录。审阅触发器仅在恢复事务内暂缓历史写入，后续正常保存继续生成一次历史。
- `archive-evidence` 覆盖格式 4 历史文本与 JSON，保留嵌套大整数、原指纹和时间；相关漏洞证据版本仅递增一次。兼容旧格式 1–3，无法补造其缺失的历史。
- 全新测试库全量 Go 回归通过：`/tmp/artex-history-archive-full.log`；归档、复测和审阅专项 race 通过：`/tmp/artex-history-archive-race.log`。专项链路日志：`/tmp/artex-history-archive-roundtrip.log`。首轮旧测试固定格式 3／错误类型断言未适配，更新断言并保持旧格式覆盖后重跑通过：`/tmp/artex-history-archive-focused2.log`。
- 新增测试验证三种终态复测、人工／自动历史精确恢复、失效会话、故障回滚及重试、ID 冲突保留外部记录、归档和发起复测并发互斥、排队后写入拒绝、非法清单和旧格式兼容。真实服务归档／离线脱敏／恢复测试确认历史与清单一致且无重复、旧报告／审阅过期、后续保存继续记历史，另一个活动任务共享的原始证据完整保留。
- 编译／镜像日志：`/tmp/artex-history-archive-compile.log`、`/tmp/artex-history-archive-image.log`。实际 CLI 验收通过：`/tmp/artex-history-archive-cli.log`；产物 `/tmp/artex-privacy-acceptance-27LPnfel/`。覆盖活动数据三批及故障重试、旧目录迁移、格式 3 流量和格式 4 历史证据包维护、ID／时间／指纹／整数保留、包哈希与大小、独立副本保留、审计、重复预览零变更和重启健康。本次前端未改，不重复浏览器验收。
- 正式任务、归档、复测及审阅表总数均为 0。停机备份 `/home/ARTEX/backups/pre-history-archive-20261106-203648/`，包含数据库 dump、文件包及版本信息，完成可读性校验。活动流量、证据和旧目录迁移预览均零记录／零变更，未改写正式业务内容。发布日志 `/tmp/artex-history-archive-publish.log`。
- 健康接口为 `dev-cff6317`，管理端口仅 `127.0.0.1:8787`；归档默认版本 4、事务内审阅恢复标记已迁移。环境、JWT 和初始登录文件哈希不变。doctor 返回 0，唯一警告为未配置模型：`/tmp/artex-history-archive-doctor.log`。运行中维护拒绝检查通过。临时测试容器及网络已清理。
- 回退镜像 `jacketser/artex:rollback-before-history-archive` 对应 `dev-523ce72`。旧恢复器无法读取格式 4；产生新包后，完整回退须用升级前配套数据库／文件备份并处理升级后新增内容。只回退程序不恢复脱敏原文。
- 主要剩余：备份／导出文件、日志／会话／资产元数据／工作区等独立副本脱敏；超大包和无引用残留维护；真实蜜罐样本评估与完整代理链路性能压测。系统级出网隔离不实施。

## 正式发布：冷归档证据与报告脱敏（2026-11-06）

- 应用源码 `523ce72`，正式版本 `dev-523ce72`；命令验收脚本校验修正为 `82f232b`。候选镜像 `jacketser/artex:archive-evidence-candidate`，镜像 ID `sha256:6acaed1172f86259d9066bd913bfbacbe4ff464ea8731e8dfe7bf6d2bd0541a0`。复用既有运行环境和嵌入前端，无新增业务表或运行依赖。
- 增加 `archive-evidence --archive-id ID`：处理包内漏洞名称／摘要／证据／报告、独立流量证据快照／正文与绑定备注。重算正文哈希、快照 ID 和长度，更新绑定；每个受影响漏洞只递增一次证据版本，保留报告旧版本和处置状态。普通归档流量与活动库仍各自单独维护。
- 复用单包停机预览、备份、指纹确认、唯一候选包落盘校验及目录事务提交；提交成功后才回收无引用旧包。检查计数／归属／引用完整性、版本和大小上限；未知证据字段、非空复测／审阅扩展表、未关联正文、缺失快照及脱敏后快照合并冲突整包拒绝，不自动丢弃证据。
- 其他 JSON 表值和精确整数保留，清单可能规范化空白／键顺序；普通流量、LLM 记录和任务文件等其他成员保持原字节。该版本归档写入和恢复流程未保存复测、人工审阅及审阅历史；当时未补造缺失内容，后续格式 4 已补齐新包的归档／恢复。完整边界见[维护说明](HISTORY-REDACTION.md)。
- 全新测试库完整 Go 回归通过：`/tmp/artex-archive-evidence-full.log`。归档维护、CLI 参数及真实归档恢复专项 race 通过：`/tmp/artex-archive-evidence-race.log`。针对性测试日志：`/tmp/artex-archive-evidence-focused.log`、`/tmp/artex-archive-evidence-restore.log`。
- 测试覆盖预览无写入、SQL 发布失败保留原包并重试、旧格式缺省版本、版本溢出、快照／绑定冲突、未知扩展、重复执行零变更、精确大整数、共享正文去重、同一漏洞仅递增一次和无变化漏洞不递增。真实服务器归档／脱敏／恢复链路确认绑定 ID／角色／位置、原采集时间及处置状态保留，证据正文可读且已脱敏、旧报告过期；另一个活动任务共享的原始快照和正文完整保留。
- 编译和镜像日志：`/tmp/artex-archive-evidence-compile.log`、`/tmp/artex-archive-evidence-image.log`。实际 CLI 验收覆盖活动三批（含旧格式迁移及失败重试）、冷归档流量与证据两个范围、校验值和包大小、报告旧版本、绑定和快照一致性、独立普通流量／任务文件保留、审计、重复预览零变更及重启健康。最终日志 `/tmp/artex-archive-evidence-cli-final.log`，产物 `/tmp/artex-privacy-acceptance-cLH4h28u/`。
- 首轮 CLI 结果校验因 Python 使用 JSON 出现顺序而非 Go 结构体固定顺序计算快照 ID 失败；生产实现和恢复测试没有该问题。修正验收脚本后，对原结果复核通过，再完整重跑 CLI 生命周期通过。原日志 `/tmp/artex-archive-evidence-cli.log`，原产物 `/tmp/artex-privacy-acceptance-Jr9vHt8S/`。本次未改前端，不重复浏览器回归。
- 发布前正式库任务／归档总数均为 0；停机备份 `/home/ARTEX/backups/pre-archive-evidence-20261106-201622/`，数据库 dump 和文件包可读性校验通过，环境、JWT 及初始登录文件哈希未变。普通流量、证据、旧格式迁移预览均零记录／零变更；正式库无冷归档可执行本范围维护，未重写正式业务内容。发布日志 `/tmp/artex-archive-evidence-publish.log`。
- 健康接口版本为 `dev-523ce72`，端口仅 `127.0.0.1:8787`，SSH 隧道访问不变；运行中执行新范围维护被拒绝。doctor 返回 0，唯一警告为未配置模型；日志 `/tmp/artex-archive-evidence-doctor.log`。临时测试容器与网络已清理。
- 回退镜像 `jacketser/artex:rollback-before-archive-evidence` 对应 `dev-da4fc54`；原恢复器可读取重写后的包，旧命令不支持新范围。仅回退程序不能还原原文，恢复内容需配套数据库和文件备份。
- 该版本当时的优先剩余项：复测／审阅历史的完整归档与恢复（后续格式 4 已完成）；备份／导出文件及日志／会话／资产元数据／工作区等独立副本脱敏；超大包和中断残留处理；真实蜜罐样本评估、完整代理链路压测。系统级出网隔离不实施。

## 正式发布：冷归档流量副本脱敏（2026-11-06）

- 应用源码 `da4fc54`，正式版本 `dev-da4fc54`；候选镜像 `jacketser/artex:archive-candidate`，镜像 ID `sha256:db7cee153c24b4e5e8e89173451cda389c7ede657598e119261a7cc620e72795`。复用运行环境和嵌入前端，无新增业务表或依赖升级。
- 新增 `archive-traffic --archive-id ID`，只处理单个就绪包中的流量清单与正文。独立证据、报告、会话、任务文件等仍保留原字节。按包核对清单、目录、大小、哈希和正文引用；流量 ID／时间保留，完整脱敏正文内联，旧流量 blob 不再随恢复导入。
- 使用唯一候选文件，落盘及目录 fsync、完整性复核后事务更新 PostgreSQL 路径／哈希／大小；提交成功再回收无引用旧包。失败或提交回执不明时保留包文件，不覆盖原包。中断残留不会自动清扫，详见[维护说明](HISTORY-REDACTION.md)。
- 支持任务格式 1–3、流量格式 1；压缩和展开各最多 128 MiB，10000 个 tar 成员／流量记录，单正文 16 MiB。拒绝未知流量字段／文件、重复路径／ID、父子冲突、链接、尾随数据、缺失／损坏／超限正文和旧混合 HTTP 格式。整包不使用活动库游标。
- 全量 Go 回归通过：`/tmp/artex-archive-full.log`。维护／CLI race 通过：`/tmp/artex-archive-race.log`；该轮服务端通知用例因复用测试库残留上一轮渠道，预期一条投递得到两条，未出现数据竞态报告。全新库服务端 race 重跑通过：`/tmp/artex-archive-race-clean.log`。新增整包指纹变更和空包版本专项通过：`/tmp/artex-archive-extra.log`。
- 测试覆盖预览无写入、包损坏／目录状态拒绝、有效包变更后旧指纹失效、SQL 提交失败保留原包及重试、其他成员字节保留、重复执行零变更、真实归档写入器／恢复解包器／文件安装／流量导入兼容。首轮新增兼容测试提前提交文件恢复导致提取目录已清理，修正测试使其与正式恢复的“先导入后清理”顺序一致后，全量回归通过；未更改正式恢复流程。
- 候选编译／镜像日志：`/tmp/artex-archive-compile.log`、`/tmp/artex-archive-image.log`。真实 CLI 验收通过，新增冷归档种子、停机备份、预览执行、目录和包哈希／大小、脱敏正文、工作区保留、审计与重启检查；沿用旧迁移三批和失败重试。日志 `/tmp/artex-archive-cli.log`，产物 `/tmp/artex-privacy-acceptance-RXPZiAO2/`。宿主机验收脚本使用 Python 3 与 libzstd，不修改正式数据。
- Chromium 回归通过：四次行为请求经上游、目标无凭据泄漏、Host 保留、冷却 429、设置保存和关闭捕获仍防护，页面错误 0。日志 `/tmp/artex-archive-browser.log`，产物 `/tmp/artex-acceptance-OG9aC8l5/`。
- 发布前正式库任务和归档总数均为 0。停机备份 `/home/ARTEX/backups/pre-archive-traffic-20261106-195520/`，数据库及文件包可读性校验通过；环境、JWT 和初始登录文件哈希未变。普通流量、证据与旧格式迁移预览均为 0 条／0 变更；没有正式冷归档可预览，未对正式业务内容执行重写。日志 `/tmp/artex-archive-publish.log`。
- 发布后健康版本 `dev-da4fc54`，管理端口仍仅 `127.0.0.1:8787`。doctor 返回 0，唯一警告仍是未配置模型；日志 `/tmp/artex-archive-doctor.log`。运行中归档维护拒绝检查通过。临时验收容器及网络已清理。
- 回退镜像 `jacketser/artex:rollback-before-archive-traffic` 对应 `dev-c9f56ec`，保留的包格式仍可被原恢复器读取。旧版本没有本次命令范围；回退程序不能恢复原文，内容恢复须使用同一份数据库与文件备份。
- 主要剩余：归档独立证据／文本、备份／导出副本及日志／会话／资产元数据脱敏；大包／未知格式处理及中断无引用残留核查；真实蜜罐样本效果评估、完整代理链路性能压测。系统级出网隔离不实施。

## 正式发布：旧目录格式流量迁移（2026-11-06）

- 应用源码 `c9f56ec`，正式版本 `dev-c9f56ec`。候选镜像 `jacketser/artex:legacy-candidate`，镜像 ID `sha256:536a5c69d20f0f2bef40278a250084b0bbb659d239a3a05883097939641c217e`。复用现有运行环境与前端，无新增业务表或基础依赖升级。
- `--migrate-legacy` 显式开启旧目录迁移，仅适用于 `traffic`。还原 `request.http`／`response.http` 和原版完整 blob 指针，支持两种哈希目录，校验长度、SHA-256 和可选元数据。迁移同步脱敏，并保留流量 ID、时间和 rowid，更新当前行全文索引。默认不开启，预览显示本批 `legacy_rows`，成功结果／审计继承开关续跑；版本变更后须从头生成预览和游标。
- 数据库事务成功后才清理核验过的旧报文与元数据；再次核对文件哈希及旧路径引用。拒绝越界、符号链接、非普通文件、缺失／损坏／超限内容、未知引用变体以及双份正文冲突。用户其他文件及空目录保留；提交后中断残留和保守延后的 blob 回收边界见[维护说明](HISTORY-REDACTION.md)。
- 混合批次中的现代记录不再回收可能被未迁移旧记录引用的 blob；只要旧行尚存就保守延后。迁移完成后，当前批次无引用 blob 可回收，较早批次延后对象交由正常存储回收处理，不宣称立即清空所有历史副本或物理擦除。
- 完整 Go 回归通过：`/tmp/artex-legacy-full.log`；维护／脱敏／CLI 专项 race 通过：`/tmp/artex-legacy-race.log`。新增旧版内联与完整 blob 迁移、混合分页共享正文保护、原文件变更导致指纹失效、SQL 失败保留源文件、清理前文件和引用复查、未知文件保留、路径和元数据拒绝、二进制／CRLF／字面量指针解析、迁移后读取／搜索／归档和重复执行零变更验证。
- 候选编译与镜像日志：`/tmp/artex-legacy-compile.log`、`/tmp/artex-legacy-image.log`。实际命令验收通过：运行中拒绝、停机三批处理（含一条旧目录及两级 blob 记录）、第二批故障重试、第三批旧记录迁移与原文件清理、用户附加文件保留、完整审计、复查零变更和重启健康；脚本参数替身验证恢复文件继承迁移开关。日志 `/tmp/artex-legacy-cli.log`，产物 `/tmp/artex-privacy-acceptance-FsEYdLAY/`。
- Chromium 回归通过：四次行为请求经过上游、无目标凭据泄漏、原 Host 保留、冷却 429、策略保存及关闭捕获仍防护，页面错误 0。日志 `/tmp/artex-legacy-browser.log`，产物 `/tmp/artex-acceptance-EQwUYOxe/`。本次前端源码未改变。
- 发布前正式库任务总数为 0；停机备份 `/home/ARTEX/backups/pre-legacy-traffic-20261106-192822/`，数据库与文件包可读性校验通过，环境、JWT 与初始登录文件哈希未变。普通流量、证据和开启迁移的流量预览均为 0 条、0 变更、0 旧格式记录，`more:false, applied:false`；未重写正式业务内容。发布日志 `/tmp/artex-legacy-publish.log`。
- 健康接口版本为 `dev-c9f56ec`，管理端口仍只绑定 `127.0.0.1:8787`；运行中迁移拒绝检查通过。doctor 返回 0，唯一警告为未配置模型，日志 `/tmp/artex-legacy-doctor.log`。隔离验收容器和网络已清理。
- 回退镜像 `jacketser/artex:rollback-before-legacy-traffic` 对应 `dev-97b8349`。已迁移行采用既有 SQLite 结构，可被回退版本读取；该版本不支持迁移开关，旧预览／游标不可跨版本复用。程序回退不恢复原始内容，恢复内容仍需同一份数据库和文件备份。
- 后续主要范围：备份／冷归档／导出副本及日志／会话／资产元数据脱敏，真实样本效果评估和完整代理链路性能压测；未知分支旧格式与无引用残留需单独核查。系统级出网隔离仍按既定决定不实施。

## 正式发布：历史脱敏大库分批与续跑（2026-11-06）

- 应用源码 `97b8349`，正式版本 `dev-97b8349`。候选镜像 `jacketser/artex:batch-candidate`，镜像 ID `sha256:c53a12fb2dc6cb6dc7866354089471ec71aa6ca48a96825e76762f79214c6ff8`。复用现有运行环境与前端，未升级基础依赖。
- 默认每批 1000 条，最多 10000 条，按 128 MiB 序列化预算自动提前分页。单正文上限仍为 16 MiB；每批五分钟超时。整库不再限制为 10000 条；预览没有下一游标，成功执行后才返回进度。每批独立事务，前面成功批次不会因后续失败回滚。
- `--resume` 读取同一范围的成功结果或成功审计 JSON；拒绝预览、失败及已到末尾的文件。游标绑定数据源配置、目录、规则与已知凭据；维护必须持续停机，恢复写入／导入／恢复备份后从头扫描。完整流程见[历史脱敏维护](HISTORY-REDACTION.md)。
- 新增真实 SQLite／PostgreSQL 测试：分别处理 10001 条流量和漏洞；按字节预算拆分 600 条共享大正文记录；失败不推进、原指纹重试、审计恢复、未处理批次索引保留、最后引用才回收正文、缺失正文不跳过、范围和凭据变化拒绝。多快照单行批次覆盖快照 ID 改变、跨表文本与触发器新增审阅历史，完成后零变更。
- 完整 Go 回归通过：`/tmp/artex-batch-full.log`；维护／脱敏／CLI 专项 race 通过：`/tmp/artex-batch-race.log`。编译和镜像日志：`/tmp/artex-batch-compile.log`、`/tmp/artex-batch-image.log`。
- 实际命令验收通过：运行中拒绝维护，停机两批预览和执行，第二批注入 SQL 失败、审计无下一游标，故障移除后原指纹重试成功，最终零变更且重启健康。宿主机脚本的恢复文件校验使用 Docker 参数替身验证，不连接正式部署。日志 `/tmp/artex-batch-cli.log`，产物 `/tmp/artex-privacy-acceptance-fPkuFdgD/`。
- Chromium 回归通过：四次行为请求走上游、无凭据泄漏、原 Host 保留、冷却 429、策略保存及关闭捕获继续防护，页面错误 0。日志 `/tmp/artex-batch-browser.log`，产物 `/tmp/artex-acceptance-btmI4jvk/`。本次未修改前端源码。
- 发布前正式库任务总数为 0；停机备份 `/home/ARTEX/backups/pre-history-batches-20261106-190855/`，数据库与文件包可读性验证通过，环境、JWT 与初始登录文件哈希未变。正式两个 scope 预览均为 `rows:0, changes:0, more:false, applied:false`；无正式业务内容重写。发布日志 `/tmp/artex-batch-publish.log`。
- 健康接口 `dev-97b8349`，管理端口仍只绑定 `127.0.0.1:8787`；运行中维护拒绝检查通过。doctor 返回 0，唯一警告仍为未配置模型，日志 `/tmp/artex-batch-doctor.log`。临时测试容器和网络已清理。
- 回退镜像 `jacketser/artex:rollback-before-history-batches` 对应 `dev-3d72515`；无新增业务表。回退版本不支持本次游标，需重新预览；程序回退不恢复已脱敏内容，恢复内容需同一份数据库和文件备份。
- 剩余范围：旧目录格式迁移，备份／冷归档／导出及日志／会话／资产元数据脱敏，真实样本效果评估和完整代理链路性能压测；未知凭据识别与物理擦除不作保证。系统级出网隔离按既定决定不实施。

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
