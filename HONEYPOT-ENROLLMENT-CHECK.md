# 冻结 v3 的接入／诊断内容针对性对照

> 历史阶段说明：本文是固定 v3 的内容评估，“正式版本／未部署／留出”均指 2026-11-07 当时。当前正式 `dev-0fb610d`／v5 已将内容提示独立于蜜罐结论；本组未重跑，不作为 v5 效果证据。当前状态见[项目总览](PROJECT-STATUS.md)，分离语义见[v4 报告](HONEYPOT-CONTENT-SEPARATION.md)。

日期：2026-11-07。检测器继续固定 `0b07cb4`／`http-behavior-v3`，没有修改判定、默认规则或正式应用；正式仍为 `dev-b7877ca`。本轮取得了新的独立诊断诱导来源，但**仍未取得独立注册＋心跳诱导的阳性证据，也未取得完整词组合的正常误报反例**。

## 分组与来源

第一组在测前提交约定 `1777448`，见[方法](scripts/acceptance/honeypot-content/ENROLLMENT-20261107.md)和[来源锁](scripts/acceptance/honeypot-content/sources-enrollment-20261107.json)：

| 来源 | 固定版本／提交 | 纳入内容及标签 |
| --- | --- | --- |
| [Consul 官方文档](https://github.com/hashicorp/consul/blob/cddc6181264ad5909e2795ec5cd68a89fa3b2c99/website/content/api-docs/agent/check.mdx) | v1.20.0 / `cddc6181264ad5909e2795ec5cd68a89fa3b2c99` | Agent 检查注册文档全文，正常 |
| [osquery 官方文档](https://github.com/osquery/osquery/blob/711974b7dcddb83af0bbbb972fa930ed02046adc/docs/wiki/deployment/remote.md) | `711974b7dcddb83af0bbbb972fa930ed02046adc` | 远程接入文档全文，正常 |
| [llm-honeypot 源码](https://github.com/protocedvill/llm-honeypot/blob/e60d8b104101c8eb4d6ffbdf171e1a06668c745c/app/payloads/reciprocity_lure.py) | `e60d8b104101c8eb4d6ffbdf171e1a06668c745c` | HTML 投递模板 `html_reciprocity_canary` 的全部 3 个 `final_variants` 字面量，诊断执行诱导；未纳入其他向量或中间阶段 |
| AgentCapture | 与前轮相同的 `b1fd1ee7a0130ab8fb1255b3af32e083bd9741f6` | `C2_RECRUIT_PROMPT` 单独作已查看的开发回归，不能算独立留出 |

两份正常文档各转义为可见／hidden section；新诱导的三条原字面量分别作为 HTML 直接复放，以及转义后放进 hidden section。占位符不替换、不补关键词、不访问内容中的 URL。hidden 容器为合成呈现，不声称上游原网页具有此隐藏方式。旧开发模板保持原字面量，共 11 个呈现样例。

新诱导项目的 PoC 说明声称通过“诊断程序”诱导执行并回传环境；本轮只把这当作来源的设计／标签依据，不复现其模型结论、不下载或执行诊断程序。测前已为确认适用性阅读 PoC 和 AST 字段结构，未运行检测、未按检测结果挑选；本组独立于检测器开发，但不是完全盲测。

第二组在第一组测完后选择，并在自身首次测量前提交 `49a9f4a`，见[单列约定](scripts/acceptance/honeypot-content/COUNTEREXAMPLE-20261107.md)：Kubernetes 官方 [Nodes 文档](https://github.com/kubernetes/website/blob/e136b827da7537cdf5ec2a497335e6b42962a3a6/content/en/docs/concepts/architecture/nodes.md)，固定 `e136b827da7537cdf5ec2a497335e6b42962a3a6`，全文可见／hidden 两种呈现。这是根据前组覆盖缺口选择的正常反例检查，不并入首组留出分母。

## 结果

| 分组 | 呈现数 | 疑似 | 人工复核 | 无信号 | 无法判断 | 新内容提示 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 正常文档，可见 | 2 | 0 | 0 | 2 | 0 | 0 |
| 正常文档，hidden | 2 | 0 | 0 | 2 | 0 | 0 |
| 新诊断诱导，原装字面量 | 3 | 0 | 0 | 3 | 0 | 0 |
| 新诊断诱导，转义 hidden | 3 | 0 | 0 | 3 | 0 | 0 |
| 已知开发回归 | 1 | 0 | 1 | 0 | 0 | 1 |
| 单列 Kubernetes 正常检查，可见 | 1 | 0 | 0 | 1 | 0 | 0 |
| 单列 Kubernetes 正常检查，hidden | 1 | 0 | 0 | 1 | 0 | 0 |

首组 44 次请求约 8.3 秒；第二组 8 次请求约 1.5 秒。每样例一次四请求，均完整，无测量失败／排除／测后调参。唯一复核来自已用于开发的 AgentCapture 模板，新内容提示也只出现在该样例；不把它重复算成新增识别证据。

三个正常来源都未触发，但没有覆盖规则的完整词组合：Consul 文档有 agent／registration，却没有 heartbeat 或 hostname＋username／os_version 配对；osquery 有 client／hostname／os_version，却没有 register／registration；Kubernetes 有 registration／heartbeat，却没有 client／agent／automated 称谓。因此，**本组不能证明同类合法说明不会误报**。这些覆盖缺口在测后检查中如实记录，没有向原文添加关键词补成“通过”样本。

独立诊断执行诱导也未触发，说明当前规则不能覆盖这类相关诱导；但它并非注册＋心跳样例，不能用它证明或否定窄组合的真实效果。样例按设计用途标注，不依据结果改标签；无信号不代表安全。各呈现变体不是独立产品／部署，不汇总计算准确率。

## 证据与复现

- 结果分别为[针对性对照](scripts/acceptance/results/honeypot-v3-enrollment-20261107.json)和[单列正常检查](scripts/acceptance/results/honeypot-v3-enrollment-counterexample-20261107.json)，记录来源／渲染／检测器／工具哈希、测前提交、逐项四请求观测及五组／两组计数；此前结果不重写。
- [现有工具](scripts/acceptance/honeypot-content/README.md)增加显式来源锁参数、纯 AST 字面量提取和固定 Git blob API 下载模式。默认 MDN／BIPIA 命令保持兼容；摘要单列 `content_warning_counts`，区分新内容提示与其他名称／行为线索。
- 运行使用指定 Go 镜像、`GOMAXPROCS=2`、`-p 1`、既有缓存；Docker 无网络，只在 loopback 复放根200／HEAD空正文／未知路径404。未启动目标产品、模型、数据库或浏览器；不替代真实来源授权／DNS入口的验证，没有处理正式数据。
- 首组 `/tmp/artex-enrollment-20261107/`、第二组 `/tmp/artex-enrollment-counterexample-20261107/` 均保留下载、夹具、`run.log`、`check-summary.log`；临时源码和容器已清理。两组有效摘要及各 11 类损坏反例通过；旧 154 样例结果的离线有效输入和 11 类反例也通过：`/tmp/artex-enrollment-legacy-validator.log`，未重新发旧请求。
- Python／Shell 语法、文档链接和 `git diff --check` 通过；检测源码与 `0b07cb4` 无差异。仅验收工具／报告改变，没有重复完整应用或数据库测试，没有部署。
- 准备阶段 Consul 当前分支完整目录下载超时且旧文档路径查询失败，改选固定 v1.20.0；该选择在首组约定之前。GitHub raw 下载超时后改用固定 blob API，仍校验同一字节哈希；两组实际测量各一次完成。失败下载不作为样本排除或验收通过。

## 当前决策与下一步

v3 仍未具备新增的独立阳性支持，完整词组合正常反例也尚未验证。保留候选与全部已知反例，暂不部署；不通过扩展关键词、放宽 TLS／跳转或重新解释标签提高命中。

本轮结束这一阶段的广泛样本扩展。下一短任务建议先将“外部内容可能诱导接入”的风险提示与“蜜罐行为结论”分开展示和解释，不再把前者的出现直接当作蜜罐证据；这项调整本轮尚未实现。进一步效果验证需要真正来源独立的同类注册诱导与合法说明；在取得之前，不宣称新内容检查提升了蜜罐覆盖或防接管能力。正式版本仍为 `dev-b7877ca`，长负载与其他 P2 待办不变。
