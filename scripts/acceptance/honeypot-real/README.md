# 真实程序的蜜罐识别评估

在内部 Docker 网络运行真实开源程序，使用固定版本 `honeydetect` 的默认规则和 `Probe` 检测。
这是已知部署标签的实验室样本，不是已获授权的公网实测集；没有外部扫描、登录尝试或攻击载荷。
正常服务对照含有刻意选择的信号重叠配置，不能据此估计这些配置在真实网站中的比例。

当前正式版本为 `dev-0fb610d`／v5。复现当前结果请使用下方显式计划入口；不带计划的命令仍冻结为历史 v2，不能直接用于当前源码。

## v5 新真实服务留出（2026-11-08）

[测前约定](HOLDOUT-20261108.md)及[计划](holdout-v5-20261108.json)冻结 v5 检测器、独立采集器提交、四个新来源、镜像和配置字节。首次运行结果已查看，日常复现使用[回归计划](replay-v5-20261108.json)，今后调参必须把这组转为回归；计划中的 `new_holdout` 只描述该次首次测量，不代表反复运行仍是独立留出。

```sh
# 首次构建只获取已锁定源码和 wheel；已有对应镜像时无需重建。
bash scripts/acceptance/honeypot-real/build-holdout-20261108.sh
bash scripts/acceptance/honeypot-real/run.sh holdout-20261108 scripts/acceptance/honeypot-real/replay-v5-20261108.json
```

新镜像复用固定基础环境，仅增加 termcolor 2.5.0。运行只连接内部网络，不发布端口；正常文件服务仅提供两份合成文件。HoneyHTTPD／Elasticpot 为两新蜜罐家族，RangeHTTPServer／copyparty 为正常服务；RangeHTTPServer 共享 Python 标准库 HTTP 实现血缘。生产检测器不改，最多四请求及 TLS／跳转边界保持。

`schema=2` 计划仅允许新分组，额外锁定来源、采集器、运行镜像和实际配置字节；旧 `schema=1` 保持回归角色，不能重标为新留出。最新入口分别从固定提交取检测器和采集器，不依赖当前工作树修改。汇总完整性通过有效＋21 类损坏反例；`check-requests-20261108.py` 离线核对四目标访问日志与测量请求，报告为 `request-audit.json`。记账不是完整抓包，不用其替代请求代码的凭据边界。

首次新组完成四部署／12 次；蜜罐和正常各为 0 疑似／0 复核／1 无信号／1 无法判断。原七部署另行回归保持，详细漏检、动态正常反例及限制见[报告](../../../HONEYPOT-EVALUATION.md#v5-新真实服务留出2026-11-08)。

## 已发布 v5 的真实软件回归（2026-11-08）

[预先提交的约定](REGRESSION-V5-20261108.md)与[版本／镜像锁](regression-v5-20261108.json)固定已发布应用 `0fb610d`／v5；旧 `tuning`、`holdout`、`holdout-20261107` 都已查看，本轮全部作为回归。三个分组 ID 保留，不代表仍是独立留出。以下命令在仓库根目录运行：

```sh
for corpus in tuning holdout holdout-20261107; do
  bash scripts/acceptance/honeypot-real/run.sh "$corpus" scripts/acceptance/honeypot-real/regression-v5-20261108.json
done
```

第二参数为显式计划，路径相对于调用目录；省略时仍执行原有 v2 源码检查，不能用省略参数的方式测试 v5。新入口先核对样本镜像 ID，再从固定 Git 提交的归档编译检测器和采集器，不挂载正式 `.env` 或数据库；只使用已有镜像和依赖缓存，Compose 禁止自动拉取。结果增加计划哈希、实际编译源码哈希、驱动程序及运行镜像哈希；临时源码、容器和网络退出时清理，清理失败返回非零。

摘要将计划中的全部旧分组标为 `regression`，校验算法版本／规则／检测提交／样本镜像；内容提示单列并参与三次稳定性比较。`check-summary.py` 对计划模式检查有效输入和 16 类损坏反例，包括统一替换算法、缺计划、改提交／镜像及重新标为新留出；原 v2 制品支持有效输入和 11 类损坏反例的离线检查，不修改原制品。无新真实来源或检测规则调整，结果见[评估报告](../../../HONEYPOT-EVALUATION.md)。

## 历史基础构建与 v2 默认入口

```sh
# 首次构建；固定上游源码，安装各自依赖和 Debian nginx。
bash scripts/acceptance/honeypot-real/build.sh
# 使用已构建的镜像执行评估，结束后清理测试容器和网络。
bash scripts/acceptance/honeypot-real/run.sh
```

要求本地 `jacketser/artex:local`、`golang:1.26-bookworm`、Docker Compose、Python 3、Git 和可用网络。
网络只用于构建依赖；运行阶段只连接新建的内部网络，无宿主机端口、不挂载正式数据和配置。
构建默认使用阿里云 PyPI 镜像，源版本由各项目依赖声明控制；结果记录完整已安装版本与镜像 ID。
QeeqBox 的 Twisted 24.10.0 与 pyOpenSSL 26.4.0 在 TLS Context 重用上不兼容；其独立环境固定 pyOpenSSL 24.3.0 / cryptography 44.0.3，未修改服务响应代码。OpenCanary 使用另一套独立依赖。
源码固定不代表传递依赖永久不变，比较历史结果时应复用对应镜像并核对版本清单。

## 样本与标签

- [OpenCanary](https://github.com/thinkst/opencanary/tree/a81e3992751548cbf4ae49eda5df78353d4c81ea)：固定提交，原装 `nasLogin`，只启用 HTTP，保留默认 Server 字段。`basicLogin` 在固定源码中缺少 `redirect.html`，根路径返回 500，记录为启动样本排除项，不计入检测分母。
- [QeeqBox honeypots](https://github.com/qeeqbox/honeypots/tree/f337a32e3351e2add3a455a3bcaf1f02ded5744b)：固定提交的原装 HTTP、HTTPS 服务；随机选择伪装 Server 字段，自签名证书保持默认。两个服务属于同一家族。
- Debian nginx：原装欢迎页、欢迎页回退、OpenCanary README 静态文档、文档回退。后面三项是配置对照，不代表额外的独立网站。

标签由实际启动的程序、固定源码和配置在检测前确定；不从名称命中或探测结果反推标签。
服务 ID、容器名、已知标签不会传给元数据检测器。行为检测只接收必要的访问来源。
没有为样本临时新增名称、证书或正文规则，也没有改动目标程序响应代码。

## 指标与检查

每个部署重复三次；每次一个单独的元数据 GET，加上生产行为检测至多四次 GET／HEAD。
启动就绪检查只建立 TCP 连接；不跟随跳转、不发送凭据、不放宽 TLS 校验。默认 HTTPS 自签名证书被拒绝应计为无法评估。
元数据由实验采集器提取 HTTP 字段、标题、响应内容和已验证 TLS 信息，调用生产 `DetectWithRules`；
这不是完整的资产发现、落库和页面交互验收。行为路径直接调用生产 `Probe`，保留 DNS 固定、正文上限与错误终止语义。

结果按部署计数，三次测量用于检查稳定性；不能把七个部署重复三次当成 21 个独立样本。
分别报告静态任意命中、静态中／高置信、行为 `suspected`、`needs_review`、`no_signal` 和 `inconclusive`。
无法判断不能计作正确阴性，未发现线索不能判定为正常；静态低置信命中和人工复核提示不是确认蜜罐。
脚本成功只表示测量完整，不表示检测准确率达到某个门槛。

`/tmp/artex-honeypot-real-*` 保存标签与配置哈希、版本、依赖清单、固定规则、原始测量、采集元数据、摘要和目标容器日志。
正文只保留在本地采集文件中，提交的结果摘要包含哈希、有限 HTTP 字段和检测结论；不提交第三方源码／完整页面或测试容器日志。

## v2 调试与留出评估（2026-11-06）

判定冻结提交 `b7877ca`：正文名称与普通行为差异只能提示复核；升级疑似须在两次主页 GET 和 HEAD 中持续命中同一个响应头字段／规则，并伴随行为差异。静态名称规则未改。响应头仍是可伪造自述，不是已验证产品指纹，最高中置信。

预先划分的调试集是历史七个部署；留出集为固定 Heralding `ac12724ab38c4e2fe78f07d1bc35e6e586ba69c0` HTTP、Apache 原装页／Heralding 文档回退／Basic 认证和 Python 静态服务，共五个部署。标签与预期健康状态来自源码和部署配置，未按检测结果选择。Apache 的三个配置不算三个独立软件家族。首次留出测量后不再根据结果修改判定代码；未来调参应将这些已查看样本转为回归集，另选新的留出集。

```sh
bash scripts/acceptance/honeypot-real/build-holdout.sh
bash scripts/acceptance/honeypot-real/run.sh tuning
bash scripts/acceptance/honeypot-real/run.sh holdout
```

两组分别产生摘要，按部署报告四种行为结论及静态命中；不得混合计数来稀释调试误报。运行脚本拒绝尚未提交的检测器修改，记录源码提交、检测器／脚本哈希、镜像 ID、配置和依赖。Heralding 只启用原装 HTTP，不发凭据，关闭上游公共 IP 查询、外部日志和口令破解功能；没有修改响应代码。构建通过依赖镜像源下载，运行仅内部网络。

离线完整性检查（不向目标发请求）：

```sh
python3 scripts/acceptance/honeypot-real/check-summary.py /tmp/某次完整评估目录
```

最初检查正常输入及七类损坏输入，2026-11-07 扩为下述十类；缺失／重复数据、分组错误、未知结论与混入算法版本均拒绝产出新摘要。原结果清单记录测量当时的脚本版本；之后增加的离线检查不改变检测器和测量结果。

## 历史 v2 新应用留出组（2026-11-07）

该组首次测量时为新留出，现已查看，v5 必须作为回归集。以下命令和 `new_holdout` 标签说明仅适用于历史 v2。

[首次检测前提交的约定](HOLDOUT-20261107.md)固定 `b7877ca` 检测器及四个部署：Log4Pot 原装 JSON／Tomcat 页面、httpbin、Datasette。Log4Pot 两个配置属于同一家族；正常侧是两个真实应用。标签从实际程序和配置确定，不按检测结果挑选。之前 `tuning` 和 `holdout` 分组现在都只用于回归，分组 ID 保留用于历史比较；新组在摘要中标为 `new_holdout`，旧两组为 `regression`。

```sh
# 固定源码提交和下载归档 SHA-256，构建隔离镜像。
bash scripts/acceptance/honeypot-real/build-holdout-20261107.sh
# 运行新留出；完成后清理容器与网络。
bash scripts/acceptance/honeypot-real/run.sh holdout-20261107
# 两组旧样本回归（复用已有镜像）。
bash scripts/acceptance/honeypot-real/run.sh tuning
bash scripts/acceptance/honeypot-real/run.sh holdout
```

运行脚本比较检测文件与 `b7877ca`，不只检查工作区是否已提交；不同则拒绝。构建源码通过 GitHub API 归档获取，核对 `sources-20261107.json` 中 SHA-256；依赖通过阿里云 PyPI，记录各应用独立 venv 的完整版本。基础运行镜像和未固定的传递依赖仍可能变化，复验应核对镜像和版本清单。

Log4Pot 使用上游文档支持的无外部依赖模式，只启用本地日志，未启用下载器／云日志；没有修改原装响应或指定带蜜罐名称的响应头。两个正常应用均使用原装路由／模板，Datasette 仅挂载这次生成的三条合成目录记录，不读取正式数据库。检测请求无攻击字符串、认证信息或跳转跟随。浏览器不会打开目标页面，HTML 中的远端脚本／资源不会被加载。

新组额外复制 Log4Pot 的目标请求日志，核对每部署 15 次请求（三个元数据 GET，九个行为 GET，三个行为 HEAD），无 Cookie/Authorization/Proxy-Authorization、无非预期路径／方法或 exploit 事件；只提交计数摘要，不提交原始日志。`behavior_four_requests` 表示发完四请求，`behavior_completed_comparison` 表示得到可分析结果；动态／截断等仍无法判断，不能把两项混同。

汇总完整性检查新增固定标签、观测完整和请求记账验证，共十类损坏反例；失败时删除旧摘要，避免旧结果误充当新结果。旧测量产物和旧报告不重写。首次新组检测后若将其用于调参，就应把它转为回归并另设留出，不能反复称为独立验证。
