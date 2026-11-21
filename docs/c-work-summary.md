# C 模块工作说明

**负责人** `Crayoncharle`

## 我负责的工作

我实现了密码学公共组件、签名发布和可信知识检索，为网关与执行器提供经过验证的内容、来源和版本。发布范围包括提示词、Agent 配置、策略、工具清单和知识文档。C 的核心实现及负责人登记已通过 [PR #3](https://github.com/Gump111458785/edge-agent-trust/pull/3) 合入 `main`，组合执行器加载 B 审批配置的修复通过 [PR #6](https://github.com/Gump111458785/edge-agent-trust/pull/6) 合入。

## 实现内容

| 交付内容 | 实现方式 | 代码入口 |
| --- | --- | --- |
| 密码学公共组件 | SHA-256 摘要、Ed25519 签名与验签、按键排序的紧凑 UTF-8 JSON 和无填充 Base64URL。以已知测试向量核对摘要、签名和编码。 | [密码学组件](../trusted_release/crypto.py) |
| 签名发布与撤销 | 签名绑定信任域、制品身份、版本、密钥及内容摘要。SQLite 事务保存当前版本和签名撤销状态，拒绝旧版本、同版本冲突及已撤销发布的重放。公钥按发布、撤销权限配置。 | [发布协议](../trusted_release/protocol.py) · [可信状态库](../trusted_release/store.py) |
| 配置使用时核验 | 从同一快照加载策略和工具清单，比对令牌绑定的版本，并按签名 Schema 校验参数。清单覆盖描述、风险、执行目标及服务身份，禁止外部未签名 Schema 依赖。 | [配置核验](../trusted_release/configuration.py) · [载荷验证](../trusted_release/payloads.py) |
| 可信 RAG | BGE-M3 与 Chroma 生成候选，使用时重新计算片段摘要，核对当前签名文档、版本和片段 ID。返回出处取自签名文档，过滤被篡改或冒充来源的片段。 | [检索验证](../trusted_release/rag.py) · [BGE-M3 ONNX](../trusted_release/embedding.py) |
| 服务与组合入口 | CLI 支持初始化、发布导入、撤销和索引；Dify 接口提供独立 Bearer 认证、Top K 和分数阈值。A 的组合入口先检查 C 发布状态，再复用 A 的执行事务，并支持加载 B 的独立审批验证器。 | [CLI](../trusted_release/manage.py) · [检索服务](../trusted_release/dify_api.py) · [组合执行器](../trusted_release/role_a.py) |

### 发布内容如何在使用时验证

1. 发布端用私钥签发内容摘要和版本。部署端从自己的公钥配置验证签名、发布权限和信任域，再通过事务更新可信状态。版本降低、同版本内容冲突或已撤销发布均被拒绝。
2. 检索时，将 Chroma 返回的候选与当前已签名文档逐一比对。通过校验的文本、来源、片段摘要和发布版本才进入返回结果。合法签名的恶意文本仍按内容处理，后续操作继续受授权边界约束。
3. 执行时，C 先验证令牌及当前策略和工具清单，把核验后的版本交给 A。A 重新检查时效、会话、预约、审批及重放，负责业务写入。设置 `ROLE_B_FABRIC_CONFIG` 时，组合入口向 A 提供 B 的独立审批源；来源不可用时拒绝高风险操作。[模块运行说明](../trusted_release/README.md#本地联调) · [接口契约](a-interface-contract.md)

## 评测方法

发布测试覆盖签名和内容篡改、权限与信任域错配、旧签名回滚、撤销后重放、重启、并发及密钥轮换。检索实验使用合成校园规章和固定版本的真实 BGE-M3 模型，核对正常问题的首条命中，并固定同一批候选，对比开启和关闭完整性验证时伪造片段能否进入结果。[发布测试](../trusted_release/tests/test_release.py) · [检索测试](../trusted_release/tests/test_retrieval.py) · [真实模型实验](../trusted_release/model_demo.py)

与 A、D 联调时，分别记录签名发布版本、令牌绑定、拒绝阶段和最终业务状态。策略更新或工具清单撤销后，旧令牌应被拒绝；重新发布更高版本后，正常请求可恢复。业务状态与令牌消费沿用 A 的快照比较，拒绝请求不得新增权限或消费令牌。[交接测试](../trusted_release/tests/test_handoff.py) · [状态评分](../evaluation/state_evaluator.py)

## 已完成的验收

### 2026-11-21：补齐独立发布检查点

基于最新 main `62b3ddc`，本次在独立分支 `feat/c-release-checkpoint` 补齐 C 的运行时独立发布核验：

- `ReleaseSnapshot.load` 在本地验签后查询 B 的 `ReadRelease`，核对完整发布引用和未撤销状态。因此策略/工具清单加载、可信检索、D 的现有工厂和 C 的组合执行器都能启用检查点，不改 A/B/D 的实现。
- 增加部署 `checkpoint` 配置及 `ROLE_C_REQUIRE_CHECKPOINT=1`。必需模式下缺少配置启动失败，配置或网络故障不能降级。旧的本地演示保持兼容，并明确其不能抵抗整个数据库回退。
- 整个本地 SQLite 被有效旧签名快照替换时，独立检查点报 `CHECKPOINT_MISMATCH`。远端撤销或不同发布引用同样拒绝；网络、提交确认、回执、区块或读取耗时异常沿用 `STATE_UNAVAILABLE`。
- 修正 RAG 的依赖故障处理：返回 503，丢弃本次已产生的部分结果。管理员 CLI 增加 `--anchor-config`，先验证本地签名及目标，再提交 B 发布/撤销，失败不报告成功并支持重试。
- 同一检查点实例有界串行提交和验证，避免正常并发响应乱序误报区块回退；管理员锚定与消费读取共用严格回执检查。独立审查提出的这两项问题已复现、加测试并修正，复核未发现新的重要问题。

| 本次实际运行 | 结果与范围 |
| --- | --- |
| A/B/C/D Python 回归 | **277 项通过**，2 个既有第三方弃用警告；相对 215 项基线新增 62 项 C 测试 |
| C 测试 | **120 项通过**；新增检查点 35 项、交接/CLI 25 项、检查点 Demo 2 项 |
| 原 C 快速 Demo | **7/7 通过** |
| 新检查点实验 | **10/10 通过**；真实 C 签名和 SQLite 备份恢复，调用 B 原链码内存桩，不是真实 Fabric 网络 |
| B 原有 Node 链码回归 | **3/3 通过**；B 文件未修改 |

配置、管理命令、错误码、失败重试、具体实验和真实链运行方式见 [C 独立发布检查点接入](c-checkpoint-integration.md)。当前机器没有可用 WSL/Fabric 部署和 B 的真实连接配置；本次没有把内存桩结果说成真实链验收，也未声称补齐真实 Agent 写入编排、用户意图确认、日志自动上链或 PPT 的 600 次消融实验。

### 历史验收记录

| 验收 | 实际结果 |
| --- | --- |
| 主线 A、B、C 自动测试 | **134 项通过**，覆盖密码学组件、发布与检索、组合执行及既有业务回归。2 个依赖弃用警告来自 Starlette 和 Chroma。 |
| C 快速 Demo | **7/7 通过**，覆盖策略篡改、旧签名回滚、合法检索、索引投毒、伪造来源、知识撤销与合法签名的恶意内容。 |
| 真实 BGE-M3 检索 | CPU 生成 1024 维向量，三条中文问题首条均命中预期文档。未验证候选中的伪造片段排第一，可信检索返回 `CHUNK_DIGEST_MISMATCH` 并过滤该片段。 |
| Dify 本地服务 | 独立进程 CLI 导入、持久化 Chroma 索引、服务工厂启动和跨进程撤销通过；撤销后不再返回该发布的片段。 |
| 组合工厂审批配置 | **6 项 HTTP 回归通过**，覆盖双组织批准、单组织不足、撤销、审批源不可用、未配置和启动配置损坏。 |
| C、D、A 定向验收 | **9/9 通过**；叠加 D 分支的独立副本 **215 项测试通过**，A 原有状态评测 **51/51 个组合符合预期**。 |
| C、B 发布检查点接口 | **5/5 通过**，使用真实 C 签名产生的 `ReleaseRef` 和 B 原链码内存桩，覆盖当前版本、旧数据库快照、撤销和回滚。 |

以上运行结果来自 2026-11-19。2026-11-20 核对的 `main` 为 `dbd58e2`，文件树未变化，[main CI](https://github.com/Gump111458785/edge-agent-trust/actions/runs/44446648411) 成功。D 联合副本使用 `0ee65c3`，该网关当时尚未合入主线。C 工厂审批测试使用替身网络读取；本地 Dify 验收覆盖 HTTP 契约。真实 Fabric 的既有结果见 [B 的验收记录](b-fabric-approvals.md)，Dify Cloud 与真实 Agent 的可信检索仍待联合验收。

## 如何复跑

在仓库根目录的 Python 环境中运行以下命令。

```powershell
python -m pip install -r trusted_release/requirements-test.txt
python -B -m pytest -q -p no:cacheprovider business/tests trusted_release/tests role_b/tests
python -B -m trusted_release.demo
python -B -m evaluation.run_benchmark
```

固定模型放在仓库外，准备后运行 `python -B -m trusted_release.model_demo --model-dir ../member-c-assets/bge-m3-onnx`。模型修订和文件摘要、发布公钥配置、CLI 导入、服务环境变量及错误码见 [C 的运行说明](../trusted_release/README.md)。发布私钥留在签名端，消费服务只加载部署方指定的公钥。

## 联调交接

| 对接角色 | 接入点与验收范围 |
| --- | --- |
| A · 独立执行器 | C 提供 `ExecutorReleaseCheck` 和 `ReleaseAwareExecutor`，先校验当前配置，再复用 A 的写入边界。已覆盖版本变化、清单撤销及验证延迟下的时效检查。 |
| B · 联盟链 | C 提供 `ReleaseRef` 及可配置的使用时独立检查点，管理员 CLI 可锚定发布/撤销；组合执行器另支持 `ROLE_B_FABRIC_CONFIG` 审批源。读配置和正式必需模式已接入，真实 Fabric 仍需提供连接配置验收。 |
| D · 授权网关 | C 提供同快照加载的策略、工具清单及版本标识。真实 D 令牌的本地交接通过；待 D 整合 main 后统一部署，记录正常与越权请求的裁决和执行结果。 |
| E · Agent 编排 | C 提供 `POST /retrieval`。E 接入可访问的 HTTPS External Knowledge 服务，配置知识库 ID 和独立 Bearer，保存片段出处、Agent 提案、调用轨迹与业务状态。 |

## 可信假设与限制

- 仅本地模式依赖可信状态库及备份的写保护。配置独立检查点后，每次使用会核对远端当前引用，可发现与之不符的整个旧快照。正式进程设置 `ROLE_C_REQUIRE_CHECKPOINT=1` 防止缺少配置时启动。此保证仍依赖独立网络、组织与部署信任配置完好，进程内区块上界不跨重启保存。
- 发布验证与 A 的业务写入位于不同数据库，管理员本地更新与 B 远端锚定也不原子，存在跨存储撤销窗口；失败要重试，统一部署后仍需测量竞态和并发排队开销。
- 签名证明获准来源与字节完整性。合法签名文本仍可能包含恶意语句，模型是否提出越权调用及执行端是否拦截，需要结合 D 和 A 的端到端实验判断。

## 技术依据

- [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) 与 [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1) 提供 SHA-256、Ed25519 标准及已知测试向量。
- [TUF（CCS 2010）](https://ssl.engineering.nyu.edu/papers/samuel_tuf_ccs_2010.pdf) 和 [TUF 规范](https://theupdateframework.github.io/specification/latest/) 提供签名元数据与回滚威胁模型。本项目借鉴其版本保护思路，采用简化发布协议。
- [PoisonedRAG（USENIX Security 2025）](https://www.usenix.org/conference/usenixsecurity25/presentation/zou-poisonedrag) 的知识投毒威胁模型用于设计候选内容篡改实验。
- [Overcoming the Retrieval Barrier（USENIX Security 2026）](https://www.usenix.org/conference/usenixsecurity26/presentation/chang-hongyan) 用于区分候选检索与后续注入效果。上述论文为调研和实验设计依据，当前记录没有声称复现完整论文实验。
