# 当前云服务器部署与二次开发

源码目录：`/home/ARTEX`。`origin` 指向 `jacketser/ARTEX-`，`upstream` 指向
`trhhubsd/ARTEX`。部署配置和本次增强在 `feature/local-enhancements` 分支，该分支已推送到
[GitHub](https://github.com/jacketser/ARTEX-/tree/feature/local-enhancements)。

## 当前运行方式

当前部署版本为 `dev-e0556f7`，源码提交 `e0556f7`（2026-10-20）；发布验证与备份见 [验收记录](LOCAL-ENHANCEMENTS-VERIFICATION.md)。

- 使用 `Dockerfile.source` 从当前工作目录编译 Next.js 静态前端及 Go 后端。
- Compose 文件是 **`compose.source.yml`**，不是上游的 `docker-compose.yml`。
- 本地应用镜像名为 `jacketser/artex:local`，不会上传镜像仓库。
- PostgreSQL 16 在独立容器中运行，数据库端口不发布到宿主机。
- 页面仅绑定 `127.0.0.1:8787`；流量代理仅监听应用容器内部 `127.0.0.1:8788`。
- 数据保存在 `artex-jacketser_pgdata` 卷、`data/`、`jwt.key` 和 `skills/`。
- `.env`、`jwt.key`、`.deployment-credentials` 均为本机私有文件，不进入 Git 和构建上下文。
- `dev-*` 版本标识禁用上游页面内的版本升级，避免覆盖自定义程序。
- 当前服务器使用 `.env` 中指定的 Debian 镜像源、Go 模块代理和 Playwright 下载镜像加速构建；
  Debian 签名和 Go 模块校验保持启用，不修改宿主机软件源。

## SSH 隧道访问

在自己的电脑执行（替换服务器地址；本机 8787 被占用时可将左侧改为 18787）：

```bash
ssh -N -L 8787:127.0.0.1:8787 -p 22521 root@服务器地址
```

保持 SSH 窗口打开，浏览器访问 `http://127.0.0.1:8787`。
当前部署已创建初始管理员，账号为 `ARTEX`，随机密码保存在
`/home/ARTEX/.deployment-credentials`。登录后可在系统配置中修改密码。
该文件仅记录初始密码，后续在页面修改密码不会同步更新此文件。

在 LLM 配置页添加自己的模型 API 地址、密钥及模型名称后，才能运行需要模型的功能。
服务器为 2 核 / 4 GB，当前已设置每任务 1 个 worker、同时最多 1 个任务。

初次部署基线为 `4379d69`；当前本地增强内容及测试边界见
[SECONDARY-DEVELOPMENT-PLAN.md](SECONDARY-DEVELOPMENT-PLAN.md)。运行版本可用以下命令核对：

```bash
curl -fsS http://127.0.0.1:8787/api/health
```

## 本地增强使用方法

```bash
cd /home/ARTEX
docker compose -f compose.source.yml exec -T artex /app/artex doctor
```

自检不迁移数据库、不调用模型。`OK/WARN/FAIL/SKIP` 表示通过、警告、失败和跳过；
返回码 0 允许有警告，1 表示有失败，2 表示命令参数错误。未配置模型会提示警告。
工具版本要求在 `runtimecheck/tools.json`，镜像内 `/app/tool-integrity.json` 是构建时
生成的关键文件指纹，检测的是这些文件的变化，不涵盖整个软件包。

模型单次逻辑调用默认限时 600 秒（含连接重试和限流等待）。如需调整，在 `.env` 加入：

```dotenv
ARTEX_LLM_CALL_TIMEOUT=900
```

然后执行 `docker compose -f compose.source.yml up -d --wait` 使新环境变量生效；设为 `0`
关闭该限制。调用方取消或更短的任务截止仍优先。任务详情“心跳”提供等待原因及人工操作建议。

本次升级会使旧版登录凭据失效，需要重新登录。之后每次改密或使用 `reset-password.sh`
都会吊销已有登录；已打开的 SSE 在下一轮校验（约 15 秒内）关闭。密码、JWT 文件仍持久化，
正常重启不吊销当前版本签发的登录。实时页面使用 45 秒一次性票据并在断线后重新领票。

漏洞详情新增“证据与反证复核”和“自动审阅现有证据”。自动审阅只读取当前证据、人工复核、证明/正常对照流量和最新复测，按漏洞类别给出核对建议；不访问目标、不调用模型、不更改漏洞处置状态。修改证据或相关结论内容后，旧复核标记过期。Markdown、ZIP、CSV、JSON 报告导出包含复核信息。

系统设置中的“任务卡住自动恢复”默认开启。任务有待执行意图、超过 120 秒无活动，并且没有人工审批、工具、模型或其他任务操作时，系统只唤醒已有引擎循环；不会重置 running 意图、重放工具或跳过审批。每任务冷却 5 分钟，连续最多 3 次；任务完成实际 Worker 或人工输入后可重新计数，暂停、排队、终态和超时收尾任务不会恢复。详情与次数在任务总览心跳显示，可在系统设置关闭。

资产页和任务资产页的服务列表可对当前页资产执行“保存本页蜜罐识别”。识别只使用已有服务名、页面标题、技术栈、banner/header/摘要等元数据，把结果写入 `assets.extra.honeypot`；评分不是概率，未发现签名不代表不是蜜罐，不发行为探针，也不会自动改变任务执行。元数据更新后自动标记过期并进入后台重评队列；人工结论也标记过期，需重新确认。展开识别详情可填写依据并确认、排除或撤销人工结论，服务列表可按蜜罐状态筛选。

当前版本没有加入完整二开项目的内网会话/隧道/凭据库、分布式节点、伪装入口、自动放行、
行为型蜜罐探针、Refresh Token 续期或自动发起按漏洞类别的证伪请求。自动审阅和蜜罐识别都是辅助提示，不能替代安全审阅，也不会自动判断漏洞真伪。

新增 `clock_compensations`、`task_recovery_ack`、`task_recovery_notifications`、`finding_reviews`、`task_recovery_state`、`task_recovery_history`、`finding_review_history`、`asset_honeypot_pending` 表及相应触发器，均为增量迁移；蜜罐结果和人工结论使用已有 `assets.extra` JSON 字段。回退旧镜像可保留这些字段/表，旧版会忽略它们。若需恢复数据，
使用发布前备份；不要直接删除数据库卷。回退旧版认证实现会恢复旧版令牌校验方式，回退时应
同时重新生成 JWT 密钥并重新登录，避免重新接受旧版凭据。

## P1 功能入口

- **系统设置 → 任务卡住自动恢复**：修改停滞阈值、重试冷却和观察期限，单位秒；默认 120/300/300，连续最多 3 次。冷却不得短于观察期限。
- **任务详情 → 总览 → 心跳**：查看最近恢复状态，展开恢复历史并加载更早记录。成功表示观察到 Worker 成功结果或任务完成，不证明一定由唤醒导致。观察期内没有有效进展会记入历史，连续耗尽后在任务列表出现站内提醒；关闭自动恢复后仍会完成已开始的观察。
- **漏洞详情 → 证据与反证复核**：展示已保存正常对照与证明流量的差异，点击编号打开证据。每次人工保存/手动自动审阅留存历史，页面打开时的预览不写入历史。最多比较 8 组、每份正文最多 256 KiB；损坏或缺失正文不会被判为相同。
- **将缺失项带入复测**：仅预填对话框，仍需手动点击启动；只有实际启动既有复测才会调用模型。
- **全局/任务资产 → 服务**：可人工确认/排除蜜罐并写明依据；元数据变化后台自动重评，旧人工结论保持过期。快捷筛选会替换当前搜索，可直接使用 DSL，如 `honeypot==excluded`。

审阅与恢复历史每页最多 50 条，保存到所属漏洞/任务删除为止；站内恢复提醒最多列出最近 100 个任务，每 15 秒刷新，默认不发送外部消息；本轮可对实时通知渠道显式启用恢复失败提醒。

## 新增配置入口（2026-10-20）

- **系统设置 → 服务器冻结补偿**：默认开启；阈值默认 60 秒（范围 30–3600），单次补偿默认 86400 秒（不低于阈值、最多 7 天）。查看及分页加载时钟事件。进程存活期间疑似长停顿/时钟跳变可持久化调整截止时间与恢复计时；停机重启、暂停/排队/终态和异常前已过期任务不补偿；超过上限只记录。
- **系统设置 → 蜜罐识别规则**：编辑规则 ID、名称、匹配内容、来源与字段范围，最多 100 条。保存实际变化后后台重新评估服务资产；原人工结论需重新确认。TLS 字段是已有资产 extra 的 tls_subject/tls_issuer/tls_fingerprint，不自动采集证书。
- **系统设置 → 场景化提示词**：默认开启 10 类有界指导；最多选 2 类、总字符最多 8000（含固定边界）。修改对之后启动的 Worker 轮次生效；先保存再预览，预览不调用模型。固定授权边界不可通过配置移除。
- **系统通知 → 渠道过滤条件 → 连续恢复失败时推送**：默认关闭，仅实时模式支持，按任务 ID 过滤，忽略漏洞级别/资产过滤。不包含任务目标、凭据或工具输出；WebHook 模板提供 task_id/kind，详情链接指向任务。已消费的旧事件不补发，已入队投递按现有通知重试策略执行。
- **任务列表 → 连续恢复失败提醒**：填写处理备注后“确认已检查”。隐藏该条提醒并将备注保留在任务恢复历史；不改变任务状态、不重置恢复预算，也不撤销已经入队的通知。

冻结补偿不取消单次模型调用及 Worker 自身超时，不重放已结束的请求。变更开关只影响新运行轮次采用的预算策略；已有固定计时器不反向修改。疑似进程停顿不等于已证明宿主机冻结。时钟事件历史按每页 50 条读取，当前不自动清理；处理备注和通知去重记录随所属恢复历史删除。

## 修改代码并发布

```bash
cd /home/ARTEX
# 修改 web/、server/、agent/ 等源码后：
./deploy-source.sh
```

脚本会复用 Docker 构建缓存，编译成功后替换应用容器并等待健康检查。
构建失败时现有应用保持运行；成功替换容器会中断正在执行的任务，应在空闲时发布。
数据库结构由程序启动时迁移；涉及数据库修改时请先备份，回退镜像不等于回退数据库。
不需要在宿主机安装 Go 或升级 Node.js。

`web/` 是前端；`server/` 是 HTTP API；`agent/`、`engine/` 是 Agent 与调度逻辑；
`db/` 是数据存储。Go module 仍保持上游路径，这是正常的，不需要为了 Fork 改包名。

需要前端热更新时，可另开开发服务并通过 SSH 转发 5173，避免将开发端口公开：

```bash
docker run --rm -it --name artex-frontend-dev --network host \
  -e AUTOPENTEST_API=http://127.0.0.1:8787 \
  -e NEXT_TELEMETRY_DISABLED=1 \
  -v /home/ARTEX/web:/workspace -w /workspace \
  node:22-bookworm-slim \
  sh -lc 'npm ci && npm run dev -- --hostname 127.0.0.1 --port 5173'
```

在本机另建 `-L 5173:127.0.0.1:5173` 隧道后访问 `http://127.0.0.1:5173`。
上述开发前端连接当前运行的后端及数据库；涉及测试数据或后端逻辑的开发，应另建独立数据库和实例。

## 常用维护

```bash
cd /home/ARTEX
docker compose -f compose.source.yml ps
docker compose -f compose.source.yml logs --tail=100 -f artex
docker compose -f compose.source.yml restart artex
```

备份时先停止应用写入，再导出数据库并打包文件；数据库容器继续运行：

```bash
cd /home/ARTEX
umask 077
mkdir -p backups
backup_stamp=$(date +%Y%m%d-%H%M%S)
docker compose -f compose.source.yml stop artex
docker compose -f compose.source.yml exec -T postgres pg_dump -U artex -d artex -Fc > "backups/postgres-$backup_stamp.dump"
tar -czf "backups/files-$backup_stamp.tar.gz" data skills jwt.key .env .deployment-credentials
docker compose -f compose.source.yml up -d --wait
```

备份包含密钥，应另外保存到可信位置。不要用 `docker compose down -v` 卸载日常服务，
`-v` 会删除数据库卷。
