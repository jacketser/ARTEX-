# 独立敏感副本盘点与分步计划

> 当前状态（2026-11-08）：Markdown 汇总／CSV 有限脱敏自 `dev-806bc74` 发布，当前正式 `dev-0fb610d` 继承，详见[报告](TEXT-EXPORT-REDACTION.md)。JSON／ZIP 扩展暂停；日志、会话和完整恢复备份等仍未新增覆盖。下文为初次盘点的基线与计划，不是当前开发排期；当前主线见[项目总览](PROJECT-STATUS.md)。

审阅日期：2026-11-07。源码基线：`8dceb13`；盘点时正式应用版本为 `dev-b7877ca`。本次只读审阅 Git 跟踪源码和维护文档，没有读取正式数据库、备份、日志、会话或凭据内容，没有运行数据清理、模型请求、压测或部署。

本文记录的是保存路径和覆盖缺口，不是实际泄露报告，也不证明本机存在对应副本。以下位置来自代码／部署模板，运行配置可能改变位置。按用户“先不做耗时间的任务”的要求，初次盘点仅完成范围审阅，当时所有新增脱敏能力尚待实现；后续已发布范围见页首。

## 已有维护边界

[历史维护](HISTORY-REDACTION.md) 已支持活动 `traffic`／`evidence` 和指定冷归档 `archive-traffic`／`archive-evidence`，不能据此推导整个数据库、整个任务包或备份已经脱敏。

[证据维护字段表](historyprivacy/evidence.go) 的 `evidenceTextTables` 明确列出漏洞名称／摘要／证据／报告、复测、人工复核、审阅历史和绑定备注；不含任务描述、聊天活动、服务日志和模型记录。新流量在保存前脱敏，其后复制的证据可继承这部分处理，但复制动作本身不会重新检查新加入的文字或旧数据。

## 副本位置与缺口

| 副本 | 写入／读取依据 | 存放位置与现有保护 | 尚未覆盖的部分 |
| --- | --- | --- | --- |
| 完整恢复备份 | [部署备份步骤](DEPLOYMENT.md)、[Compose 模板](compose.source.yml) | `backups/` 中 PG dump 和文件包；`umask 077`；文件包包含 `data`、`skills`、JWT、环境及初始凭据文件 | 按设计保留恢复所需凭据和业务内容；权限控制不是脱敏。活动库清理不追溯旧备份，外部复制的位置未盘查 |
| 漏洞文本／结构化导出 | [findingsExport](server/server.go)、[报告渲染](report/findings.go) | `md-single`、CSV、JSON 下载；JSON 特意清空证据快照请求／响应头，CSV 不含大段报告／证据全文 | 未见统一凭据脱敏出口；名称、摘要、任务描述、报告、审阅等所选字段仍取自数据。JSON 去头、CSV 字段裁剪、文件名过滤不等于脱敏 |
| 漏洞 ZIP 与临时副本 | [StageFindingsExport](evidence/store.go)、[ZIP 构建](server/finding_traffic_export.go) | 临时 `artex-finding-export-*` 目录，正常返回后 `RemoveAll`；ZIP 0600，下载前校验 CRC；正文先私有复制 | ZIP 含 Markdown、绑定／快照 manifest、请求／响应 `.http` 和 `.bin`；当前复制和校验不新增脱敏。清理报告文字不能覆盖清单和正文，进程异常退出可能留下临时目录 |
| 流量／证据正文下载 | [getTrafficBlob](server/server.go)、[证据下载](server/finding_traffic.go) | 从活动流量或证据存储流式发送；源记录可由已有 scope 维护 | 已下载到浏览器或外部目录的文件不受后续源数据维护影响；未见独立下载副本追踪／清理能力 |
| 后端服务日志 | [logSinkT.Write / SetDB](server/logsink.go)、[InsertLog](db/logs.go) | 标准 Go 日志先原样写 stderr，再进入内存 ring、PG `server_logs` 和订阅者；重启从 PG 恢复最近 100 条 | 未见统一脱敏。只在 DB 插入前处理会漏掉 stderr／实时订阅；DB 写错直接输出 stderr 还会绕过标准 sink；旧日志读取也需独立处理 |
| Docker 日志 | [Compose 日志配置](compose.source.yml) | 应用与 PG 的 `json-file`，每份 10 MiB、最多 3 份；具体文件位置本轮未查询 | 轮转只约束保留量。应用日志改进不能覆盖 PG 或其他直接 stdout/stderr 输出，已有 Docker／外部日志仍是独立副本 |
| 任务与聊天活动 | [AppendActivity](db/exploration.go)、[AppendConvActivity](db/conversation.go)、[会话执行](server/conversations.go) | PG `activity`、`conversation_activities`，含摘要、详情、工具信息及部分 metadata；聊天标题在 `conversations` | 写入端的 UTF-8 清理不是凭据脱敏。模型／工具输出、用户消息与错误可能复制到这些字段；现有 evidence scope 不覆盖它们 |
| 可恢复会话／压缩原文 | [会话装配](server/server.go)、[ChatAgent](agent/chat.go)、[NOA 接入](agent/noa.go)、[旁支问答](db/side_questions.go) | `data/transcripts/` 由外部 norma Store 管理；启用 NOA 时 `data/noa/` 保存压缩原文；PG 另有旁支 snapshot、memory、问题／回答 | 关闭模型正文记录不等于停用会话保存；运行上下文和展示副本需分开设计，直接修改可能破坏续跑。外部依赖的文件内部格式本轮未审阅 |
| 模型调用正文记录 | [Recorder](llmrec/llmrec.go)、[Capture](llmrec/capture.go)、[InsertLLMRecord](db/commands.go) | `llm_record` 开关控制 PG `llm_records` 的 request/response、raw_request/raw_response、error；独立 `llm_usage` 保存用量 | 已读链路未见正文脱敏；raw 保存请求正文和已读取的响应正文／重试片段，不应误称为已记录全部 HTTP 认证头。关闭开关不会清理已有记录，也不关闭用量统计 |
| 工作区／上传／工具大输出 | [上传](server/chatupload.go)、[工作区接口](server/workspace.go)、[聊天工作目录](agent/chat.go) | `data/tasks/`、`data/sessions/<id>/`，上传暂存为 `data/drafts/<id>/uploads/`；会话工具大输出写 `cmd-output/`；工作区文件可下载 | 文件类型不限于文本，名称与内容均可能敏感；路径安全检查不是内容脱敏。不能用通用字符串替换任意二进制文件 |
| 冷归档中的其他内容 | [任务文件打包](server/task_archive_package.go)、[归档维护](historyprivacy/archive.go) | 任务包可包含任务工作区和 `exp<id>-` transcripts；格式 4 还保存已支持的复测／审阅数据 | 现有 archive scopes 只处理指定流量／证据字段；独立 `conv-*` 聊天正文不能因格式 4 有复测关联就视为已打包或已脱敏；包内其他活动、工作区和会话仍需另列范围 |

登录续期的 `auth_sessions` 与业务聊天不是同一类数据；[认证实现](server/auth_refresh.go) 已使用刷新令牌哈希，不应把它列为明文聊天内容。备份仍需按包含认证材料的完整恢复副本管理。

## 可复用能力与限制

[traffic.HistoricalText / HistoricalExchange](traffic/history_redaction.go) 可供后续适配评估：已知凭据、常见结构化敏感字段与 PEM 等处理已有基础；HTTP 全量正文处理还涉及长度、哈希、引用和“非线上原始报文”标记。文本工具不保证识别自然语言中的任意未知密码，也不能对任意二进制／压缩包提供通用脱敏。

[Manager.trafficSecrets](server/traffic_security.go) 从环境、模型配置和部分设置加载当前已知秘密；代理查询失败会拒绝继续。其他出口还没有自动获得这个契约。复用前应核对启动时序、动态凭据更新和读取失败策略；尤其不能在日志输出里同步查库并再次写日志，造成递归或死锁。已经轮换且未提供的旧凭据无法仅凭当前列表保证匹配。

## 建议实施顺序与验收边界

1. **下一短任务：新增纯文本分享导出脱敏。** 先限定 `md-single` 和 CSV，以完整的导出数据副本为输入，覆盖名称、任务描述、摘要、报告及实际包含的审阅字段；不改活动库。输出明确标记为脱敏副本，读取凭据失败不得发送原文。JSON／ZIP 保留明确的未覆盖状态，不把单个格式完成写成“所有导出已脱敏”。用合成已知秘密、编码变体、PEM、结构化字段和普通文本检查最终下载字节，同时验证源对象不被改写、普通内容保留和失败无正文；无需真实数据或长压测。
2. **再处理 JSON／ZIP 的分享副本。** 按字段处理 JSON；ZIP 同时处理 Markdown、文件名、manifest、`.http`、`.bin`，重算派生副本的长度／哈希／关联并与原证据身份明确区分。保留原审阅依据及过期语义，不能把脱敏内容冒充原始证据。先用小型合成包逐项解压核验，再单独安排大包与中断测试。
3. **新服务日志统一处理。** 在 stderr、ring、PG、SSE 分流之前脱敏；单独覆盖错误旁路及旧 PG 日志读取。验收包括并发、秘密动态变更、启动未就绪、数据库错误和多行输入，检查无递归／阻塞；明确不覆盖外部进程与旧 Docker 文件。历史 `server_logs` 清理另设停机预览／指纹／备份方案。
4. **模型记录、活动与可恢复会话分开实施。** 先选只供查看的 `llm_records`／活动副本，确认是否有其他功能读取；再研究 transcripts、旁支 memory、NOA 和工具输出的恢复依赖。历史维护必须独立 scope、分批计数与指纹、失败／中断恢复，审计不含原文。仅在隔离数据上验证续跑、工具调用配对和任务恢复；不要对活动会话直接全局替换。
5. **备份与外部副本制定保留／分享流程。** 完整恢复备份继续受限保管，不能改写唯一回退点。需要分享时另产最小化副本，并与可恢复备份明确区分；恢复演练与分享副本脱敏验证分别记录。已下载／外部复制的文件不承诺自动追溯删除；保留期和外部位置须另行确认。大归档、无引用文件和物理残留维护继续独立排期。

以上是实施计划，不是本轮功能承诺或已完成测试。后续涉及正式部署仍遵守现有备份和隔离验证流程，不引入系统级出网隔离或逐工具网络放行。

## 本轮证据与剩余工作

- 已核对 Git 基线、上述源码入口、维护 scope 与文档之间的对应关系；文档链接及 `git diff --check` 用作本轮轻量检查。
- 没有运行 Go／浏览器／数据库回归；没有修改应用或验收工具，无需重新部署。未检查实际数据规模、敏感内容、文件权限或外部副本位置，因此不能报告泄露数量或“已清理”。资产元数据及其他业务表尚未逐字段审阅，完整数据库盘点也仍待补齐。
- 独立副本脱敏实现、大归档／中断残留维护仍未完成。数小时负载、广泛样本评估和模型质量／Token 收益验证按用户偏好暂缓；蜜罐判定与已有反例继续保留。
