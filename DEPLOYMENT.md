# 当前云服务器部署与二次开发

源码目录：`/home/ARTEX`。`origin` 指向 `jacketser/ARTEX-`，`upstream` 指向
`trhhubsd/ARTEX`。部署配置在本地 `deploy/cloud-source` 分支；是否推送由维护者决定。

## 当前运行方式

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

当前运行版本为 `dev-4379d69`，来源提交为
`4379d692905ccd142547c73d7d11c2ff8958cdaa`。已验证健康检查、管理员登录、未登录访问拦截、
SSE 日志流，以及 Chromium 中的登录页、任务页、模型配置页和系统设置页。
实际重建应用容器后，管理员、JWT 密钥、已有登录凭据和并发配置均保持有效。
尚未配置模型 API，也未执行模型调用或扫描任务。

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
