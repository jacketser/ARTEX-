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

预览返回 `scope`、`rows`、`changes`、`fingerprint`、`applied:false` 和范围限制。预览不迁移数据库，不更改业务行或正文，也不创建脱敏审计文件。两个 scope 的指纹不同，不能互换。每个 scope 的 `changes` 为 0 时无需执行该 scope。

脚本检查应用容器确实已停止；新版本应用与维护命令还通过 PostgreSQL 共享／独占维护锁互斥。旧版本不持有该锁，维护旧数据时仍必须通过脚本检查停机，不要直接绕过脚本运行命令。

## 执行与检查

把对应预览的完整 `fingerprint` 填入命令，再执行有变更的 scope：

```bash
bash scripts/history-redact.sh apply traffic '替换为流量预览的64位指纹' "$privacy_backup"
bash scripts/history-redact.sh apply evidence '替换为证据预览的64位指纹' "$privacy_backup"

# 再次预览，确认没有剩余计划内变更。
bash scripts/history-redact.sh preview traffic
bash scripts/history-redact.sh preview evidence
docker compose -f compose.source.yml up -d --no-build --wait artex
```

脚本检查备份文件存在并能被 `pg_restore --list` / `tar -tzf` 读取；这不替代数据库恢复演练。二进制直接运行时仅检查备份文件存在且非空，推荐使用脚本。

执行时重新计算计划；目标内容或所用凭据发生变化就拒绝旧指纹，需重新预览。每个 scope 独立提交，不存在跨 SQLite 与 PostgreSQL 的共同事务。`traffic` 成功、`evidence` 失败时，前者不会自动回滚。

执行开始及结束在 `data/privacy-audit/` 写入权限为 `0600` 的 JSON，只有时间文件名、范围、数量、指纹和状态，不保存原文。结果为 `failed_or_partial`，或仅有 `started` 时，先重新预览并保留备份：SQL 事务失败会回滚该库变更，但提交后文件回收失败、进程中断可能留下旧正文或已脱敏的无引用文件。审计写入失败也返回非零，不应据此推断业务库未修改。

证据正文先持久化，再提交哈希／绑定变更；提交失败最多留下无引用的新文件。不会自动合并脱敏后发生唯一约束冲突的证据绑定，以免丢失不同用途或备注；冲突会使证据事务失败，须人工核对。

清理影响证据重放与审阅依据。恢复时需在停机状态下使用同一份 PostgreSQL 和持久化文件备份一起恢复；只回退程序镜像不能恢复被脱敏的内容。

## 有界维护与剩余限制

- 每个 scope 最多 10000 条记录，单正文最多 16 MiB，总计划序列化计量上限为 128 MiB，单次命令最多五分钟。超过上限整体拒绝，不悄悄跳过；大库需另行设计分批迁移。
- 历史流量重写后将完整正文放回 SQLite，不再引用旧 blob；后续新捕获仍按正常阈值存储。这可能增大 SQLite 文件，不是空间压缩功能。
- 旧目录格式流量（`exchanges.path` 非空）、缺失／损坏的正文或哈希、不可解析的头／URL会阻止对应 scope 的维护。越界文件路径和逃逸符号链接不会读取。
- 不处理备份、冷归档包、已导出报告、日志、对话、资产元数据及未关联的旧文件。恢复旧备份或导入旧归档后，需重新预览；不能把一次活动库清理当作所有历史副本都已脱敏。
- 不保证识别自由文本中的未知密码、已轮换且不再配置的密钥、任意编码或加密内容。没有命中不代表没有敏感信息。
- SQLite 全文索引重建，已替换且无引用的正文文件会回收；数据库历史页、WAL、磁盘快照和备份不保证物理擦除。旧备份保留策略与物理介质清除需独立管理。

当前服务器首次核查时，活动流量、证据快照、漏洞、复测和审阅均为 0；无需对正式业务记录执行重写。正式预览结果与部署验证见[验收记录](LOCAL-ENHANCEMENTS-VERIFICATION.md)。
