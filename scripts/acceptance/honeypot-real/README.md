# 真实程序的蜜罐识别评估

在内部 Docker 网络运行真实开源程序，使用当前 `honeydetect` 的默认规则和 `Probe` 检测。
这是已知部署标签的实验室样本，不是已获授权的公网实测集；没有外部扫描、登录尝试或攻击载荷。
正常服务对照含有刻意选择的信号重叠配置，不能据此估计这些配置在真实网站中的比例。

## 运行

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

检查正常输入及七类损坏输入；缺失／重复数据、分组错误、未知结论与混入算法版本均拒绝产出新摘要。原结果清单记录测量当时的脚本版本；之后增加的离线检查不改变检测器和测量结果。
