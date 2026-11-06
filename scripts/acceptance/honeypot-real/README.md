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
