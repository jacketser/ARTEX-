# 历史流量与证据脱敏维护

历史脱敏使用停机命令 `artex history-redact`，不是后台自动修改。先预览，再以预览返回的指纹执行。本文针对本 fork 的 `compose.source.yml`；版本变化见[二开更新日志](CHANGELOG-LOCAL.md)。

## 处理范围

| scope | 处理内容 | 一致性保证 |
| --- | --- | --- |
| `traffic` | 活动 SQLite 流量的 URL、请求／响应头、完整正文；包括引用的大正文文件 | 保留流量 ID 和时间，更新长度、全文索引及 blob 引用；提交后仅回收不再被引用的已替换正文 |
| `evidence` | PostgreSQL 证据快照及正文、漏洞名称／摘要／证据／报告、复测内容、人工复核、审阅历史和流量绑定备注 | 重新计算正文哈希与快照 ID，更新绑定；相关漏洞证据版本递增，旧报告和审阅保持过期，处置状态不变 |

脱敏规则包括当前已知平台凭据及其常见编码、PEM 私钥、HTTP 敏感头、URL 敏感参数，以及 JSON／表单中的敏感字段。带 `Content-Encoding` 的正文以省略标记替代。保存内容带有“非线上原始报文”标记。

`changes` 是预计重写的记录数，不是已确认泄露数。整理头顺序、补齐脱敏标记也可能产生变更；预览不展示原文、URL、密钥或正文片段。

## 停机、备份和预览

先等待任务完成，记录本轮更新的镜像与版本。在仓库目录执行以下命令，保持应用停止直到维护完成；PostgreSQL 继续运行。

```bash
cd /home/ARTEX
docker compose -f compose.source.yml stop artex
umask 077
privacy_backup="/home/ARTEX/backups/pre-redaction-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$privacy_backup"
docker compose -f compose.source.yml exec -T postgres pg_dump -U artex -d artex -Fc > "$privacy_backup/postgres.dump"
tar -czf "$privacy_backup/files.tar.gz" data skills jwt.key .env .deployment-credentials
docker compose -f compose.source.yml exec -T postgres pg_restore --list < "$privacy_backup/postgres.dump" > /dev/null
tar -tzf "$privacy_backup/files.tar.gz" > /dev/null

bash scripts/history-redact.sh preview traffic
bash scripts/history-redact.sh preview evidence
```

若部署没有 `.deployment-credentials`，从打包命令中移除该文件名；不要忽略其他打包错误。

预览返回本批的 `scope`、`rows`、`changes`、`fingerprint`、`batch_size`、`more`、`applied:false` 和范围限制。预览不迁移数据库，不更改业务行或正文，也不创建脱敏审计文件。两个 scope 的指纹不同，不能互换。`more:false` 才表示已扫描到末尾；单批 `changes:0` 不表示整个库已经清理。预览不会返回可推进进度的 `next_cursor`。

脚本检查应用容器确实已停止；新版本应用与维护命令还通过 PostgreSQL 共享／独占维护锁互斥。旧版本不持有该锁，维护旧数据时仍必须通过脚本检查停机，不要直接绕过脚本运行命令。

## 执行与检查

以下是单批完成的示例。若返回 `more:true`，按下一节继续逐批处理，不能直接重启。把对应预览的完整 `fingerprint` 填入命令：

```bash
bash scripts/history-redact.sh apply traffic '替换为流量预览的64位指纹' "$privacy_backup"
bash scripts/history-redact.sh apply evidence '替换为证据预览的64位指纹' "$privacy_backup"

# 再次预览，确认没有剩余计划内变更。
bash scripts/history-redact.sh preview traffic
bash scripts/history-redact.sh preview evidence
docker compose -f compose.source.yml up -d --no-build --wait artex
```

脚本检查备份文件存在并能被 `pg_restore --list` / `tar -tzf` 读取；这不替代数据库恢复演练。二进制直接运行时仅检查备份文件存在且非空，推荐使用脚本。

执行时重新计算计划；目标内容或所用凭据发生变化就拒绝旧指纹，需重新预览。每一批独立提交，不存在跨批次或跨 SQLite 与 PostgreSQL 的共同事务。`traffic` 成功、`evidence` 失败时，前者不会自动回滚。

执行开始及结束在 `data/privacy-audit/` 写入权限为 `0600` 的 JSON，只有时间文件名、范围、数量、指纹、批量参数、进度游标和状态，不保存原文。结果为 `failed_or_partial`，或仅有 `started` 时，先重新预览并保留备份：SQL 事务失败会回滚该库变更，但提交后文件回收失败、进程中断可能留下旧正文或已脱敏的无引用文件。审计写入失败也返回非零，不应据此推断业务库未修改。

证据正文先持久化，再提交哈希／绑定变更；提交失败最多留下无引用的新文件。不会自动合并脱敏后发生唯一约束冲突的证据绑定，以免丢失不同用途或备注；冲突会使证据事务失败，须人工核对。

清理影响证据重放与审阅依据。恢复时需在停机状态下使用同一份 PostgreSQL 和持久化文件备份一起恢复；只回退程序镜像不能恢复被脱敏的内容。

## 分批预览、执行与断点续跑

默认每批最多 1000 条，可通过 `--batch-size 1–10000` 调整。正文较大时还会按 128 MiB 序列化预算提前结束本批；这不是进程内存峰值承诺。`rows` 和 `changes` 都只统计当前批次。单个正文仍限制 16 MiB，无法安全处理的记录会报错，不自动跳过。

第一批按以下方式保存结果（仍须停机且已有本轮完整备份）：

```bash
bash scripts/history-redact.sh preview traffic --batch-size 500 > "$privacy_backup/traffic-preview-001.json"
privacy_fp=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' "$privacy_backup/traffic-preview-001.json")
bash scripts/history-redact.sh apply traffic "$privacy_fp" "$privacy_backup" --batch-size 500 > "$privacy_backup/traffic-applied-001.json"
```

成功执行返回 `applied:true`。如果还有数据，会同时返回 `more:true` 和 `next_cursor`，可以用结果文件继续下一批：

```bash
bash scripts/history-redact.sh preview traffic --batch-size 500 --resume "$privacy_backup/traffic-applied-001.json" > "$privacy_backup/traffic-preview-002.json"
privacy_fp=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' "$privacy_backup/traffic-preview-002.json")
bash scripts/history-redact.sh apply traffic "$privacy_fp" "$privacy_backup" --batch-size 500 --resume "$privacy_backup/traffic-applied-001.json" > "$privacy_backup/traffic-applied-002.json"
```

后续逐次使用上一成功批次的结果，直到 `more:false`。`evidence` 使用相同流程，单独从第一批开始。`--resume` 也接受 `data/privacy-audit/` 中同一范围、`status:complete` 且 `more:true` 的成功审计文件；预览、失败和已经结束的结果文件均会拒绝。不要把输出重定向到正在作为 `--resume` 输入的同一个文件，否则 shell 会先清空输入。

- 同一批的预览和执行必须使用相同的游标与批量大小，指纹还校验本批内容、边界和已知凭据。调整批量大小后重新预览。也可手动传 `--cursor '上一成功批次的 next_cursor'`，不能与 `--resume` 同用。二进制对应参数为 `-batch-size`、`-cursor`；`--resume` 是宿主机脚本提供的 JSON 读取功能，需要 Python 3。
- 本批 `changes:0` 且 `more:true` 时，仍需以本批指纹执行一次来确认进度；不会改写业务内容，会保存成功审计并给出下一游标。整轮完成后，从头逐批复查，每批均应为 `changes:0`，不能只看第一批。
- 中断后先核对审计。最新批次只有 `started` 或为 `failed_or_partial` 时，从**它之前最后一个成功批次**继续，重新预览尚未确认的批次；如果第一批失败则不传游标。不要使用失败批次中的 `cursor` 作为“已完成”证明，也不要自行增加游标位置。已成功的早期批次不会回滚。提交状态不明时重新预览能避免把失败当作完成，但旧文件回收失败仍需按审计核查。
- 游标绑定数据源连接配置、数据目录、脱敏规则版本与已知凭据，且只适用于同一轮停机维护。应用重启并产生写入、导入数据、恢复备份或直接修改数据库后，必须清空游标从头重新扫描；它不是跨运行周期的一致性快照。更换连接／目录或已知凭据后也从头开始。
- 流量按 SQLite rowid 扫描；证据先处理快照，再依次处理漏洞、复测、人工复核、审阅历史和绑定备注。快照 ID 改变后，新产生的已脱敏快照可能再被扫描一次，所以 `rows` 累计值可能超过最初记录数，但不会重复增加证据版本。审阅更新触发的新历史记录在后续阶段覆盖。同一漏洞在不同批次出现实际变更时，每个相关批次都递增证据版本。
- 只替换当前批次的全文索引条目；其他批次仍可搜索。共享正文直到最后一个活动引用被替换才会回收。不得在批次之间压缩／重建 SQLite 行号或手工改动数据。

## 有界维护与剩余限制

- 每批最多 10000 条记录，默认 1000；单正文最多 16 MiB，总计划序列化计量上限为 128 MiB，单次命令最多五分钟。整库条数不再限制为 10000。单条记录超限仍拒绝本批；超时可减小批量后在原位置重新预览。
- 历史流量重写后将完整正文放回 SQLite，不再引用旧 blob；后续新捕获仍按正常阈值存储。这可能增大 SQLite 文件，不是空间压缩功能。
- 旧目录格式流量（`exchanges.path` 非空）、缺失／损坏的正文或哈希、不可解析的头／URL会阻止对应 scope 的维护。越界文件路径和逃逸符号链接不会读取。
- 不处理备份、冷归档包、已导出报告、日志、对话、资产元数据及未关联的旧文件。恢复旧备份或导入旧归档后，需重新预览；不能把一次活动库清理当作所有历史副本都已脱敏。
- 不保证识别自由文本中的未知密码、已轮换且不再配置的密钥、任意编码或加密内容。没有命中不代表没有敏感信息。
- SQLite 全文索引按当前批次更新，已替换且无引用的正文文件会回收；数据库历史页、WAL、磁盘快照和备份不保证物理擦除。旧备份保留策略与物理介质清除需独立管理。

当前服务器首次核查时，活动流量、证据快照、漏洞、复测和审阅均为 0；无需对正式业务记录执行重写。正式预览结果与部署验证见[验收记录](LOCAL-ENHANCEMENTS-VERIFICATION.md)。
