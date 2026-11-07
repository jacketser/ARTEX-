# 纯文本分享导出脱敏

日期：2026-11-07。开发基线 `7d95ef5`，应用源码 `806bc74`；**`dev-806bc74` 已完成构建、浏览器验收及正式发布**，前序候选阶段中的未部署状态保留当时含义。实现副本盘点中的第一个短任务，未对正式源数据执行脱敏重写或清理历史下载文件。

## 范围与使用变化

发现页导出的 `md-single` 与 `csv` 默认生成脱敏分享副本，适用于勾选、筛选和全部三种范围。JSON、Markdown ZIP、独立证据正文下载及其他报告出口不在本次范围内。导出对话框按所选格式提示覆盖边界，没有增加确认步骤。

- 文件名改为 `findings-sanitized-时间.md/.csv`；响应带 `Cache-Control: no-store` 和 `X-Artex-Export: sanitized-copy; not-original-evidence`。
- Markdown 在开头标明处理范围、遗漏可能及“非原始证据”。CSV 保留原有 12 列顺序与 UTF-8 BOM，末尾新增第 13 列“脱敏副本说明”，每行包含同样说明；空 CSV 仍有列名。依赖固定列数的下游脚本需适配。
- 不修改活动库、人工审阅、绑定、证据快照或原始文件；证据编号仍用于引用原记录，不能据此把导出文字视为原文。人工复核和报告过期状态依据原始证据计算，不因脱敏而变新或变旧。

## 字段与判定边界

渲染器读取完整的导出对象（包含所属任务描述、审阅与流量绑定），仅对待输出文字副本处理；在 Markdown 的换行／反引号处理及 CSV 引号转义之前脱敏，避免格式化拆开已知凭据。排序和审阅指纹仍使用原对象。

| 格式 | 本次实际处理的输出文字 | 仍未包含／未处理的内容 |
| --- | --- | --- |
| Markdown 汇总 | 名称、类别、等级／状态文字、所属任务描述、摘要、证据文字、报告全文、人工复核的来源／复现／反证／限制、流量绑定角色／备注及快照方法／URL | 不下载或脱敏关联 `.http`／`.bin` 正文；不是所有历史审阅或数据库字段的导出 |
| CSV | 原有 CSV 的每个单元格在转义前处理，包括名称、类别、所属任务、摘要；保留原审阅结果及过期判断 | 原格式不含报告／证据全文或人工复核长文本，不能据此声称这些内容已被 CSV 导出或清理 |

复用 `traffic.HistoricalText`，未修改代理或历史维护规则：匹配长度不少于 8 字节的当前已知秘密，以及原文、QueryEscape、PathEscape、标准 Base64、无填充 URL Base64、十六进制变体；处理完整 PEM 私钥块。一个字段本身是完整 JSON 时，还递归处理常见敏感键值，并保留大整数。普通文字及非敏感 JSON 信息保留。

**这是有限的凭据脱敏，不是全面匿名化。** 短凭据、已轮换且未提供的旧秘密、任意自然语言密码、嵌在普通段落／代码围栏中的未知 JSON 值、未知 HTTP 头／URL 参数凭据、其他编码／混淆和个人信息均不保证识别。完整 JSON 解析可能改变其空白／键顺序；脱敏副本不能作为逐字节原始证据。已下载副本不会追溯清理，JSON／ZIP 仍可能包含原始信息。

每次导出重新调用现有 `Manager.trafficSecrets`，读取环境中的模型密钥／数据库连接及密码、数据库模型密钥与已有认证／搜索设置；这是当前凭据源覆盖范围，不是对全部配置和历史凭据的枚举。查询最多三秒，不跨请求缓存；凭据读取失败返回通用 503 错误，不附下载头或原始导出内容，也不把底层数据库错误发送给用户。内容完全生成后才写下载响应。

## 验证证据

全部使用合成数据及 Git 跟踪源码快照，未读取正式配置、凭据、数据库、日志或会话内容。Go 沿用 `golang:1.26-bookworm`、`GOMAXPROCS=2`、`-p 1` 和现有缓存。

- `report` 全包三项通过，最终包耗时 0.006 秒：六种已知秘密呈现、带引号／逗号／反引号内容、完整 JSON 与大整数、PEM、空导出标记、普通内容、源对象与嵌套绑定不变、当前／过期人工复核语义。CSV 先解析最终下载格式再检查单元格，未只检查转义前字符串。
- 独立内部网络、全新 PostgreSQL：`TestFindingsShareExportAPI`、`TestFindingTrafficAPIAndExport`、`TestFindingTrafficUTF8SegmentsAndInheritedWrites` 三项通过，最终包耗时 2.356 秒。覆盖两格式×三范围、实际响应头／文件名／最终字节、CSV 13 列、当前凭据更新、原库记录保持、JSON 未标成脱敏、既有 ZIP／流量导出兼容。在临时库中故意使凭据源表不可访问，两格式均返回通用 503，未输出下载文件或底层错误。
- 前端 `node node_modules/typescript/bin/tsc --noEmit --incremental false` 通过；本轮未做完整静态构建或浏览器点击／下载验收。

最终 Go 日志 `/tmp/artex-share-export-api-final.log`，初次报告测试 `/tmp/artex-share-export-report.log`，前端日志 `/tmp/artex-share-export-tsc.log`；测试源码分别在 [report/findings_share_test.go](report/findings_share_test.go) 和 [server/findings_share_test.go](server/findings_share_test.go)。独立源码快照 `/tmp/artex-share-export-eoq5k371/`，API 运行脚本 `/tmp/artex-share-export-api-check.sh`，测试容器、网络及数据库匿名卷已清理。

首次 API 测试错误假设“全部导出”只含本测试的一条记录；同库前一测试保留的发现使该断言失败。修正为核对目标行及所有下载单元格，最终新建测试库复跑通过，没有修改应用逻辑来绕过失败。失败日志 `/tmp/artex-share-export-api.log` 保留，不计为通过。

## 候选构建与真实浏览器下载（2026-11-07）

固定 `806bc74` 的 Git 跟踪源码，全新构建静态前端并嵌入 Go 程序；Node 22 和 Go 1.26 构建使用已有依赖／缓存、关闭容器网络、两 CPU，Go 维持 `GOMAXPROCS=2`／`-p 1`。运行环境继承已验收的 v4 镜像，未更新依赖或正式镜像标签。

- 候选 `jacketser/artex:share-export-candidate`，版本 `dev-806bc74`；镜像 ID `sha256:6bbb74bef7fc8e21298c74477f60b9caa1a9c02e91cd7e61b9d48f220bd47dc6`。
- 程序 SHA-256 `52c3235b20ea36ae8e6747f5df4a71f50cde2013b45f462a7ccee5df40bf50c2`；构建日志 `/tmp/artex-share-export-build.log`，源码／构建制品 `/tmp/artex-share-export-build-wOF5WjV7/`。
- 新增[可复跑浏览器工具](scripts/acceptance/export-run.sh)，只启动全新内部网络、临时应用和 PostgreSQL，不发布宿主端口；使用两个合成发现、一个已完成任务和原文指纹匹配的人工复核。

| 浏览器实际操作 | 取得的证据 |
| --- | --- |
| Markdown／CSV × 全部／筛选／勾选 | 六次真实下载，文件名及响应头符合脱敏副本约定；全部有两条，筛选／勾选只有目标一条 |
| 独立解析下载字节 | 六种已知凭据呈现均被处理；完整 JSON 敏感值及 PEM 从 Markdown 消失，普通文字、大整数、报告和审阅普通内容保留 |
| CSV 兼容及复核 | BOM、原 12 列顺序及新增第 13 列说明通过；含逗号、引号、换行的单元格可解析；原人工复核仍为支持且不过期 |
| 四种格式页面提示 | Markdown／CSV 显示有限覆盖和非原始证据，JSON／ZIP 显示尚未增加统一脱敏；JSON 真实下载保留合成原文且无脱敏标记，ZIP 本轮只检查提示 |
| 凭据源故障 | 临时库重命名 `llm_profiles` 后，两格式均返回 503，无下载头或原始导出内容；页面显示失败，两个场景下载数均为 0 |
| 源记录及页面运行 | 发现、人工复核、任务、探索和合成凭据前后摘要一致；正常／故障两阶段页面脚本错误均为 0 |

正常阶段七个下载（六个脱敏文件＋一个原始 JSON），故障阶段两次拒绝。完整结果、工具和下载制品哈希保存于[结构化记录](scripts/acceptance/results/text-export-browser-20261107.json)。最终日志 `/tmp/artex-share-export-browser-second.log`，截图／文件／源摘要 `/tmp/artex-export-XXbP0Tqc/`；临时容器、卷、网络已清理。正式健康检查仍为 `dev-6d4aa09`，未部署或测试正式数据库。

首轮在勾选步骤超时：验收脚本按 `row` 角色定位，但现有表格行显式使用 `button` 角色。将脚本改为定位实际 `tr` 后，新建实例完整复跑通过；没有修改应用来绕过失败。失败日志 `/tmp/artex-share-export-browser-first.log`、截图及下载 `/tmp/artex-export-QtsBriFQ/` 保留，不计为通过。

## 正式发布（2026-11-07）

11:31（Asia/Shanghai）开始发布已验收镜像，运行版本 **`dev-806bc74`**，应用 `806bc74`，验收工具与记录 `8e99580`。前后端同时更新，无数据库结构、依赖、归档或认证格式变化；不要求更换凭据。CSV 仍需留意新增第 13 列对固定列数脚本的影响。

- 发布前任务、归档、活动复测／探测均为 0；停止应用写入后备份到 `/home/ARTEX/backups/pre-share-export-20261107-113141/`。数据库 dump 目录和文件包列表读取校验通过，目录 700、文件 600。备份保留完整恢复内容，不视为脱敏副本。
- 正式镜像／程序哈希与上文候选一致；发现页 HTML 和含导出提示的 JS 包逐字节匹配。环境、JWT、初始登录文件哈希不变；管理端口仍仅 `127.0.0.1:8787`，其他应用和数据库容器 ID／启动时间保持。
- 健康检查 `dev-806bc74`；doctor 返回 0、无失败，唯一警告仍为未配置模型。正式仅执行健康、只读状态、静态前端及运行自检，没有创建测试业务记录、导出正式发现或运行长评估。
- 回退镜像 `jacketser/artex:rollback-before-share-export` 对应 `dev-6d4aa09`。回退会失去 Markdown／CSV 分享脱敏及新增说明列，仍保留蜜罐 v4；本次无源数据重写，通常无需恢复数据库。操作见[部署说明](DEPLOYMENT.md)。

发布日志 `/tmp/artex-share-export-publish.log`、doctor 日志 `/tmp/artex-share-export-doctor.log`，永久[发布结果](scripts/acceptance/results/text-export-release-20261107.json)保存校验结论。原浏览器结果保持候选阶段的未部署标记，不改写历史记录。

## 剩余工作

代码、专项验证、完整构建、隔离浏览器下载验收及正式发布已完成，正式 Markdown／CSV 已获得有限脱敏能力。下一短任务先明确 JSON 分享副本的字段与原证据关系再实施。浏览器仅使用小型合成数据，没有运行长负载、大导出或模型实验，也不代表任意秘密识别率。

JSON／ZIP 需要独立处理清单、正文、哈希和原证据关系；日志、模型记录、活动、可恢复会话、完整恢复备份及已下载副本仍未新增脱敏能力。大包、有引用／无引用残留和当前凭据源之外的秘密按[副本盘点](SENSITIVE-COPIES-INVENTORY.md)与[项目状态](PROJECT-STATUS.md)继续安排。
