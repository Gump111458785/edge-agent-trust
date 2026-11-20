# A 与 B/C/D/E 的接口契约

以下为 A 的可运行联调草案 v1。B、C、D 可用同一份请求和验证向量完成对接，随后共同冻结协议与部署信任参数。

## 接口与信任边界

| 服务 | 接口 | 凭据及用途 |
| --- | --- | --- |
| 读业务 | `GET /booking?booking_id=BK-1042`、`GET /access-status?area=visitor_area` | 用户会话 Bearer，仅返回本人信息 |
| 读业务 | `GET /internal/bookings/{booking_id}`、`GET /internal/session` | D 的事实查询 Bearer。会话查询另传 `X-Session-Token`，返回可信访客和会话标识 |
| 执行器 | `POST /internal/executor/access-grants` | D 的执行服务 Bearer 加独立的 `X-Session-Token`，以及由发行方签名的操作令牌 |
| 执行器 | `GET /internal/executor/operations/{operation_id}` | 执行服务 Bearer，按操作 ID 查带时间戳的尝试结果 |
| 执行器的实验入口 | `POST /auth/demo-login` | 仅在显式设置 `ROLE_A_DEMO_CREDENTIALS` 时启用。要求执行服务 Bearer 加匹配访客的实验凭据，签发一小时随机不透明会话 |

公开只读调用与内部调用使用不同凭据。会话、服务凭据和请求令牌不进入执行审计或评测输出。

## D 的令牌与 A 的独立检查

执行请求含 `operation_id`、`action`、`args`、`token`。`args` 精确包含 `booking_id`、`area` 和整数 `valid_minutes`（1 至 120）。区域为 `visitor_area` 或 `server_room`，对应 `grant_access` 或 `grant_restricted_access`。操作风险由 A 根据可信部署规则和参数独立判定。

令牌是 JSON 对象，包含 `claims` 和 `signature`。签名为不带填充的 Base64URL Ed25519 签名字节。

| Claims | 验证含义 |
| --- | --- |
| `version`、`issuer`、`audience`、`key_id` | v1、可信签发者、本执行器与配置的公钥 |
| `token_id`、`operation_id`、`subject` | 唯一令牌、本次操作、可信会话的访客 |
| `action`、`args_hash` | 工具名、规范化 `args` 的小写 SHA-256 十六进制 |
| `issued_at`、`expires_at` | UTC Unix 秒，半开时间范围，签发跨度最多 120 秒 |
| `approval_ref` | 可空。机房动作必须携带适用审批引用 |
| `evidence` | 可空。证据版本必须携带 `session_id`、`booking_id`、`booking_version`、`policy_version`、`tool_manifest_version` |

对严格模式校验后的对象按键名排序，用 UTF-8 JSON、`,` 和 `:` 紧凑分隔符、不转义非 ASCII。Claims 的可选字段缺省值规范化为 `null`。签名载荷为 ASCII `edge-agent-trust:executor-token:v1`、一个 LF 和规范化 Claims。参考实现见 [authorization.py](../business/app/authorization.py)。

在 `BEGIN IMMEDIATE` 内重新检查令牌有效期、会话、预约状态和适用证据版本。一条事务写入 `used_tokens`、`access_grants` 和执行成功记录。`token_id` 和 `operation_id` 均独立限制重复，已成功的操作即使用新令牌也会被拒绝。拒绝记录另写审计事务。合法授权已有有效权限时返回 `ACCESS_ALREADY_GRANTED`，过期权限可经新操作替换。执行器对有效请求返回 `executed` 与 `grant_id`，拒绝返回机器可读 `reason_code`。常见 HTTP 状态为 `401` 凭据缺失、`403` 验证失败、`409` 重放或状态冲突、`422` 格式错误、`503` 审批或存储不可用。

## B 的可验证审批与 C 的可信配置

B 适配器实现 `ApprovalSource.fetch_verified(reference)`，负责从独立可信来源核对组织签名、交易有效提交及撤销状态，并返回 `ApprovalState`。记录包含引用、操作摘要、已验证组织集合、状态、观察时点及有效期。A 自行比对操作摘要、当前所需组织及新鲜度。缺少适配器会默认拒绝高风险操作。实验默认需要 `security` 与 `information_center` 两方，状态最多 15 秒旧，后续由 B/D 协同确定最终组织配置、状态来源和时间参数。

审批操作摘要取规范化 `{"operation_id": ..., "action": ..., "subject": ..., "args_hash": ...}`，加 ASCII `edge-agent-trust:approval-operation:v1` 和 LF 前缀后做 SHA-256。SQLite 提交前再次核对审批有效期及快照新鲜度。Fabric 撤销与 SQLite 提交之间仍有跨系统时间窗口，联调时按这一窗口单列实验。

B 的 Fabric 适配器用操作摘要作为审批引用。A 可通过 `ROLE_B_FABRIC_CONFIG` 启用，详细配置见 [B 的交付与接入说明](b-fabric-approvals.md)。

C 已提供 `load_configuration`，从同一可信状态快照验证策略与工具清单的签名、内容摘要、版本及撤销状态，返回 `VerifiedConfiguration`。`evidence_versions()` 输出 `policy_version` 和 `tool_manifest_version`，格式为 `v<版本>-<64 位发布摘要>`。D 将其绑定到令牌证据，A 的 C 组合入口再从自己的可信状态核对当前版本，并按签名工具清单中的 Schema 校验参数。

A 可设置 `ROLE_C_TRUST_CONFIG`，使用 `trusted_release.role_a:create_app` 工厂启动组合执行器。默认制品 ID 为 `campus-policy` 与 `campus-tools`，可通过 `ROLE_C_POLICY_ID` 和 `ROLE_C_TOOLS_ID` 覆盖。该入口先核验发布，再复用 A 原有令牌、会话、预约、审批和事务检查；同时支持 `ROLE_B_FABRIC_CONFIG` 加载 B 的独立审批源。接口参数与错误码见 [C 的接口契约](c-interface-contract.md)，部署配置与复现见 [C 的运行说明](../trusted_release/README.md#本地联调)，交付和验收见 [C 的工作记录](c-work-summary.md)。

发布版本不匹配、已撤销或参数不符合清单时，组合入口分别返回 `403 TRUST_VERSION_MISMATCH`、`403 TRUST_REVOKED` 或 `403 TRUST_INVALID_TOOL_ARGUMENTS`；可信状态不可用或绑定异常返回 `503 TRUST_STATE_UNAVAILABLE` 或 `503 TRUST_STATE_INVALID`。本地交接测试已覆盖配置更新、撤销后的拒绝及审批适配。版本保护依赖本地可信状态库完整性，独立 Fabric 发布检查点尚未在 C 运行时自动强制使用；发布核验与 A 业务提交之间仍有跨库撤销窗口。

预约的 `version` 由数据库触发器保护，归属、区域、状态或有效期变化会递增。D 的令牌内容只作为待比较的签名断言，A 从自己的会话、预约和部署配置读取当前事实。
