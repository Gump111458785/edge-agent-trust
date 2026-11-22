# B · Fabric 多组织审批与可验证审计

> 本页保留原分支验收记录。主线已包含 B 源码。集成版本新增 D 启动配置、真实 SQLite 日志导出及锚定、发布检查点和重复耗时采样入口，见[集成验收](integration.md)。

## 本分支的交付

在 `qin` 分支上沿用 A 的操作摘要、`ApprovalSource` 和 SQLite 执行事务，以及 C 的规范化 JSON、Ed25519 和 `ReleaseRef`。D 通过审批引用关联执行令牌。A 配置自己的 Fabric 客户端与审批公钥，从两个组织的节点核对提交结果，独立检查审批与本次操作是否匹配。

复核远端分支时，`main` 已补充 A 的工作总结，D 的网关实现位于 `feat/d-evidence-gateway`。D 使用同一 `ApprovalVerifier` 并支持向 `Gateway` 注入审批源。本次变更留在 `qin`，通过现有接口交接。 [A 的工作总结](https://github.com/Gump111458785/edge-agent-trust/blob/4d6a2eac807ed11b762c15ad91f9832ec490094e/docs/a-work-summary.md) · [D 的接口契约](https://github.com/Gump111458785/edge-agent-trust/blob/0ee65c32241698d515d789f2b28fc5c6ecca7599/docs/d-interface-contract.md)

| 交付 | 代码 |
| --- | --- |
| 组织身份、审批、撤销、发布摘要和审计批次链码 | [ledger.js](../role_b/chaincode/ledger.js) |
| 指定两组织背书、核对两个节点的提交结果 | [gateway.js](../role_b/client/gateway.js) |
| 部门签名和 A 的审批适配器 | [approval.py](../role_b/approval.py) |
| C 的发布摘要登记、日志 Merkle 根计算与核验 | [anchors.py](../role_b/anchors.py) |
| 合成预约、真实测试链对照和 SQLite 状态断言 | [experiment.py](../role_b/tests/experiment.py) |

## 组织身份和操作绑定

- 保卫处 `security` 对应 `Org1MSP`，信息中心 `information_center` 对应 `Org2MSP`。各组织以 CA 签发并带 `role_b=approver` 属性的客户端证书登记一把独立 Ed25519 公钥。链码限制每组织登记一次，拒绝跨组织重复公钥。实验链以单频道固定公钥运行。轮换需要双方共同治理链码或重建实验频道。
- D 用 [A 定义的 operation_digest](a-interface-contract.md#b-的可验证审批与-c-的可信配置) 生成操作摘要，传给两部门核对其对应的预约、参数和操作。摘要就是 `approval_ref`，为 64 位小写十六进制。每部门单独生成签名，再用本组织的审批证书提交。两部门分别签同一摘要，审批时间区间可以不同，执行取较早的截止时间。
- 任一已经批准的部门均可撤销。链码保留原签名、撤销部门和撤销交易 ID，并封存该摘要。A 同时核对引用、操作摘要和两个组织；执行事务开始后再次核对截止时间和新鲜度。
- 链码背书使用 `AND('Org1MSP.peer','Org2MSP.peer')`。查询也提交交易，Fabric 在提交时检查审批键的读取版本。读取后且该笔读交易之前提交的撤销会使过期的读取版本失效。SDK 需收到两端对同一交易、同一块的有效确认，超时、失败或不一致均拒绝。A 用发起查询的时间计算新鲜度，默认上限 15 秒。 [Fabric 交易流程](https://hyperledger-fabric.readthedocs.io/en/release-2.5/txflow.html) · [Fabric Gateway](https://hyperledger-fabric.readthedocs.io/en/release-2.5/gateway.html)

### 审批请求示例

签名载荷为 ASCII 域 `edge-agent-trust:b-approval:v1`、一个 LF、按键排序的紧凑 UTF-8 Claims JSON。签名用无填充 Base64URL 表示。用 [`ApprovalClaims` 和 `sign_approval`](../role_b/approval.py) 生成并序列化外层 `{"claims": ..., "signature": ...}`。下面是 Claims 的结构示例，运行时取当前 Unix 秒和实际操作摘要。

```json
{
  "channel": "roleb",
  "operation_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "organization": "security",
  "issued_at": 1795165200,
  "expires_at": 1795165500
}
```

| 交易 | 参数 | 权限与响应 |
| --- | --- | --- |
| `RegisterApprover` | Ed25519 的 SPKI DER，Base64URL | 本组织审批客户端，返回 `organization` 与 `spki` |
| `Approve` | 序列化的 `SignedApproval` | 本组织审批客户端，返回 `reference`、`approvals`、`revocation` |
| `RevokeApproval` | 审批引用 | 该操作已登记的任一审批组织，返回含撤销的记录 |
| `ReadApproval` | 审批引用 | 频道内获授权客户端，返回记录或 JSON `null` |
| `PublishRelease`、`RevokeRelease` | C 的 `ReleaseRef` JSON，含 `scope`、`kind`、`artifact_id`、`version`、`manifest_sha256` | `Org2MSP` 的 `role_b=publisher`，返回引用和 `revoked` |
| `ReadRelease` | `scope`、`kind`、`artifact_id` | 读取当前版本和撤销状态 |
| `AnchorAudit` | `{"stream":"executor","first_seq":1,"last_seq":3,"root":"<64 位十六进制>"}` | `Org1MSP` 的 `role_b=auditor`，返回批次 |
| `ReadAudit`、`ReadAuditHead` | `stream` 加批次起始序号，或只有 `stream` | 读取某批次或流的锚定尾序号 |

成功的 [SDK 客户端](../role_b/client/gateway.js) 输出 `{"transaction_id":"…","block":"…","value":…}`。链码拒绝码包括 `FORBIDDEN`、`BAD_SIGNATURE`、`APPROVAL_TIME_INVALID`、`APPROVAL_REVOKED`、`RELEASE_ROLLBACK`、`AUDIT_RANGE_INVALID`。A 接口对来源不可用或记录验签失败返回 `503 APPROVAL_UNAVAILABLE`，对摘要不符返回 `403 APPROVAL_MISMATCH`，对缺少一方或已撤销的审批返回 `403 APPROVAL_INSUFFICIENT`。A 也单独报告 `APPROVAL_EXPIRED` 和 `APPROVAL_STALE`。

## A、C、D 的接入步骤

1. 运行测试链脚本生成配置，或参照下例提供受信配置。相对路径以配置文件目录为基准。每个组织需维护自己的证书、公钥和签名私钥。执行器身份使用普通频道客户端，只拥有查询所需权限。只有控制审批、发布或审计的进程持有对应证书和私钥。
2. A 按原[启动说明](../business/README.md)启动执行器，额外为该进程设置 `ROLE_B_FABRIC_CONFIG` 指向读配置的绝对路径。节点客户端需要 Node.js 和 `role_b/client` 的依赖。该接入点用于源码部署，A 的原有公开只读镜像继续服务预约查询。
3. D 在构建 `Gateway` 时传入 `approvals=ApprovalVerifier(source=FabricApprovalSource.from_config(path))`。D 用该验证器检查摘要、部门、撤销状态、新鲜度和有效期。D 签发令牌后，A 会重新读取。两个服务分别维护自己的可信配置。
4. C 先用现有发布流程核验签名和内容，再调用 `publish_release(client, ref)` 登记相同的 `ReleaseRef`。消费端可在 C 的使用时验证之外调用 `release_current(client, ref)` 核对频道上的版本和撤销状态。发布新版本要求版本号严格提高，同版本同摘要可幂等提交。撤销必须精确匹配当前版本和 Manifest 摘要。
5. 日志发送方为每个来源流分配连续 `seq`，从 1 开始。调用 `anchor_audit(client, stream, first_seq, events)` 锚定顺序、范围和根。审计方读取 `audit_head` 确定已锚定尾序号，再对各批次调用 `verify_audit`。对照尾序号可以发现整批丢失。日志本体保存在链下，链上只存流名、范围和根。

```json
{
  "channel": "roleb",
  "chaincode": "roleb",
  "identity": {"msp_id": "Org1MSP", "certificate": "reader.pem", "private_key": "reader.key"},
  "peers": [
    {"msp_id":"Org1MSP","endpoint":"localhost:7051","server_name":"peer0.org1.example.com","tls_root":"org1-ca.pem"},
    {"msp_id":"Org2MSP","endpoint":"localhost:9051","server_name":"peer0.org2.example.com","tls_root":"org2-ca.pem"}
  ],
  "approver_keys": {"security":"security.pub.pem","information_center":"information_center.pub.pem"}
}
```

Merkle 叶是 `SHA-256(0x00 || canonical_json({"stream": ..., "event": ...}))`，内部节点是 `SHA-256(0x01 || left || right)`。奇数节点末尾未配对时直接提升到上一层。批次的每条事件都包含 `seq`。链码拒绝同起点不同根、序号间隙和重叠。

## 复现与对照

本地规则测试在仓库根目录运行。安装 A 的测试依赖后可同时复测已有执行器。

```sh
node --test role_b/tests/ledger.test.js
python -m unittest discover -s role_b/tests -v
```

真实链验收使用 Linux 或已配置 Docker 的 WSL2、Docker Compose、`fabric-samples` 测试网络及 Fabric 和 CA 工具、jq、Node.js 22 和 Python 3.10+。用 Fabric 官方安装方式准备独立样例目录及匹配版本的镜像。部分样例 Compose 文件使用 `:latest` 标签，版本以运行中的节点为准。WSL 下可在 Linux 文件系统中运行源码和依赖，避免挂载盘的进程启动延迟。脚本生成独立测试身份，结果目录 `role-b-results/` 已忽略。重复实验可复用首次生成的配置目录和测试身份。 [Fabric 安装说明](https://hyperledger-fabric.readthedocs.io/en/release-2.5/install.html)

```sh
python -m pip install -r business/requirements-dev.txt
work=$(bash role_b/tests/setup-network.sh /path/to/fabric-samples/test-network)
python -m role_b.tests.experiment "$work"
```

| 用例 | 预期 |
| --- | --- |
| 正常机房预约 | 所选审批门槛满足时，A 写入一条权限和一次令牌消费 |
| 仅保卫处批准 | 单方路径允许。本地多签和 Fabric 路径均拒绝 |
| 修改申请时长后用原审批引用 | 本地多签与 Fabric 路径均报摘要不匹配 |
| 已执行的操作改用新令牌 | A 拒绝再次执行，只保留一次权限写入和一次令牌消费 |
| 撤销后将中心状态恢复到撤销前快照 | 只依赖该中心记录的本地多签路径接受旧签名。Fabric 路径继续按已提交的撤销拒绝 |
| 已锚定日志修改、缺尾或乱序 | 通过批次范围及重算 Merkle 根发现与锚定记录的差异 |

链上实验输出每个用例的结论和执行耗时。每个用例使用独立 SQLite 测试库，同一用例内的重放复用数据库。对照脚本以 A 的合成请求和测试签发器驱动。

### 实测记录

2026-11-18 在 WSL2 运行两组织 Fabric。两个 Peer 为 3.1.5，Orderer 为 2.5.16，CA 为 1.5.22，频道使用应用能力 `V2_5`。链上审批与 SQLite 对照的 11 个用例全部符合预期，C 的发布摘要登记与撤销、生效状态核对，以及审计 Merkle 根核验同时通过。

| 对照 | 实测 |
| --- | --- |
| 正常机房权限 | 本地多签与 Fabric 各写入一条权限和一次令牌消费 |
| 仅保卫处批准 | 单方路径写入一次。本地多签和 Fabric 拒绝，并保持权限及令牌消费无新增 |
| 修改申请时长 | 本地多签和 Fabric 均报 `APPROVAL_MISMATCH` |
| 同一操作更换新令牌 | A 返回 `AUTHORIZATION_REPLAY`，该操作仍只有一条权限和一次令牌消费 |
| 联盟链撤销后恢复中心快照 | 本地多签接受撤销前快照。Fabric 返回 `APPROVAL_INSUFFICIENT`，权限及令牌消费无新增 |
| 发布摘要和审计 | 当前发布摘要可核验，撤销后核验失败。原始日志通过，删掉尾项或改写事件后核验失败 |

正常授权单次样本中，本地多签路径为 3.542 ms，Fabric 路径为 2417.118 ms，包含进程启动、背书、排序及两节点提交确认。样本用于记录该环境的开销，尚无重复测量的延迟分布。首次跨 Windows 挂载盘运行遇到客户端超时，移到 WSL 原生目录后整组通过。测试结果保存在本地 `role-b-results/`。

本分支还运行了 3 项 Node 链码规则测试。Python 回归覆盖 A、B 与 C 的发布及检索核心测试，115 项通过、2 项跳过。A 原有评测的 51 个任务与配置组合全部符合预期。规则测试中的 Fabric 状态使用本地测试替身。

联合冒烟另用远端 D 分支的 `Gateway`、C 本地验签通过的策略与工具清单，以及 A 的 `ReleaseAwareExecutor`。D 和 A 分别用 Org2 与 Org1 的普通频道客户端读取同一审批，D 的 `POST /authorize` 返回 200，A 的执行接口返回 `executed`。保卫处提交撤销后，D 拒绝签发，A 也独立拒绝使用先前签发的令牌。两个接口均返回 `APPROVAL_INSUFFICIENT`。此次联调使用 FastAPI 测试客户端和真实 Fabric，面向 Dify 的统一部署与撤销竞态窗口测量留待全项目验收。 [D 联调基线](https://github.com/Gump111458785/edge-agent-trust/blob/0ee65c32241698d515d789f2b28fc5c6ecca7599/gateway/tests/test_gateway.py)

## 可信假设与限制

- 信任 A 主机、公钥配置及其指向的两个独立组织节点和 Fabric 频道治理。提交确认由配置内通过 TLS 验证身份的节点返回。当前实现使用 Gateway 背书及提交验证。测试网络的单排序节点适用于课程实验。
- Fabric 读交易有效提交后到 A 的 SQLite 写入之间存在撤销竞态。当前以有效读交易的排序位置作为链上判断时点，以 15 秒作为端到端读状态年龄上限。每次高风险检查提交读交易会产生排序与存储开销。
- 本地多签对照信任中心快照，撤销前快照可由中心存储恢复。若给本地对照额外配置独立且持久的防回退记录，需另做对照。审计锚点覆盖截至链上尾序号的日志，后续批次待锚定。

## 技术依据

- Androulaki 等人的 EuroSys 论文描述 Fabric 的执行、排序和验证流程。B 的链码在背书阶段读取审批键，提交阶段由节点核对版本及背书。 [Hyperledger Fabric 论文](https://arxiv.org/abs/1801.10228)
- RFC 9162 的 Merkle 树用不同前缀区分叶和内部节点。B 沿用两个前缀，用流名和带序号的原始事件作为叶输入。 [RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1)
- 测试链使用两组织 CA 和明确的双组织背书策略。客户端通过 Gateway 等待并核对提交状态。 [Fabric 2.5 双组织测试网络](https://hyperledger-fabric.readthedocs.io/en/release-2.5/test_network.html) · [Fabric 频道与背书策略](https://hyperledger-fabric.readthedocs.io/en/release-2.5/create_channel/channel_policies.html) · [Node Gateway 提交状态接口](https://hyperledger.github.io/fabric-gateway/main/api/node/interfaces/SubmittedTransaction.html)
