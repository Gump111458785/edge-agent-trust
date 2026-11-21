# C 独立发布检查点：部署与验证

## 本次补齐的 C 工作

此前 C 能验证本地签名、版本和撤销，但整个 SQLite 被旧快照替换时，旧发布仍可能通过本地验证。本次把独立检查点接入实际消费路径：`ReleaseSnapshot.load` 验证本地发布后，通过 B 原有 `FabricClient` 提交 `ReadRelease`，要求远端当前未撤销的完整 `ReleaseRef` 与本地完全相同。

`load_configuration`、`POST /retrieval`、C 的组合执行器和现有 D 工厂都通过这一加载路径生效。无需修改 A/B/D 的业务代码。C 同时补充管理员发布/撤销锚定和可复现实验。B 的链码、身份权限、TLS 和双组织提交确认继续使用 B 的原实现。

## 配置消费服务

复制 [带检查点的信任配置](../trusted_release/examples/trust-checkpoint.json) 到仓库外运行目录，填好 C 的发布/撤销公钥及数据库路径。在现有信任配置顶层增加：

```json
{
  "checkpoint": {
    "provider": "fabric",
    "config": "fabric/reader.json",
    "max_read_seconds": 15
  }
}
```

上面是新增字段片段，不能单独代替完整信任配置。`config` 相对于 C 信任配置所在目录；B 配置内证书、身份和 TLS 文件则按 B 的原规则相对于该连接配置解析。B 的配置需要完整的 `channel`、`chaincode`、`identity`、两组织 `peers`，详见 [B 的部署说明](b-fabric-approvals.md)。使用只具有查询所需权限的 Fabric 身份，不给消费服务发布者身份或 C 的发布私钥。

消费进程设置：

```powershell
$env:ROLE_C_TRUST_CONFIG = "E:/your-runtime/trust.json"
$env:ROLE_C_REQUIRE_CHECKPOINT = "1"
```

第二个变量接受精确字符串 `0` 或 `1`。值为 `1` 时，信任配置缺少 `checkpoint` 就启动失败；配置错字、未知字段、缺失/损坏的连接配置、布尔或越界的读取上限也会失败，不能降级。上限为 1–15 的整数，默认 15，限制一次提交读取从发起到返回的耗时。B 的 Node 客户端另有网络阶段超时。还须安装 B 的 `role_b/client` 依赖及 Node.js。

已有工厂启动方式不变：

```powershell
python -m uvicorn gateway.main:create_app --factory --host 127.0.0.1 --port 8002
python -m uvicorn trusted_release.role_a:create_app --factory --host 127.0.0.1 --port 8001
python -m uvicorn trusted_release.dify_api:create_app --factory --host 127.0.0.1 --port 8003
```

各进程仍须配齐各自原有环境变量；上述三个命令分别启动进程，不是在同一个终端依次等待。三个进程均须读取带检查点的 C 配置，并设置必需模式。`ROLE_B_FABRIC_CONFIG` 仍用于 A 的高风险审批，不能代替此发布检查点配置，也不表示 D 的审批源缺口已经补齐。

旧纯本地实验仍兼容：没有 `checkpoint` 且 `ROLE_C_REQUIRE_CHECKPOINT` 未设置或为 `0` 时，只验证本地数据库。该模式不能抵抗整个可信数据库回滚。直接构造 `ReleaseStore` 的代码应显式传入 `checkpoint=FabricReleaseCheckpoint(...)`；必需环境变量由部署入口 `open_store` 处理，不能约束绕过该入口的代码。

## 管理员发布和撤销

先由 C 的离线私钥持有人生成发布/撤销信封。管理员导入本地并使用 B 的独立发布者连接配置提交锚点：

```powershell
python -B -m trusted_release.manage --config ../c-runtime/trust.json init
python -B -m trusted_release.manage --config ../c-runtime/trust.json publish ../c-runtime/handbook.signed.json ../c-runtime/handbook.json --anchor-config ../b-runtime/publisher.json
python -B -m trusted_release.manage --config ../c-runtime/trust.json index visitor-handbook --index-dir ../c-runtime/chroma --model-dir ../member-c-assets/bge-m3-onnx
python -B -m trusted_release.manage --config ../c-runtime/trust.json revoke ../c-runtime/handbook.revoked.json --anchor-config ../b-runtime/publisher.json
```

`--anchor-config` 相对于命令运行目录，区别于信任配置中的相对路径。它仅用于管理员 CLI，使用 B 允许 `PublishRelease` / `RevokeRelease` 的身份。本地签名、内容或撤销目标验证失败时，不会发起 B 的写入。发布仅在锚定成功后输出原格式的 `ReleaseRef`；故障退出 1，不输出成功引用。

两处存储不是同一事务。本地发布成功而锚定失败时，新版本在受保护消费端不可用；重试同一条发布命令可完成锚定。撤销先落本地，再提交远端，提交失败须重试；已完成远端撤销后，即使恢复旧的本地快照也会被检查点拒绝。**从本地撤销到远端确认期间，以及读取检查点到业务提交之间，仍存在跨存储窗口。** 不把部分提交表述为完整成功，也不声称此改动消除了所有撤销竞态。

## 拒绝行为

| 情形 | C 结果 | 消费端行为 |
| --- | --- | --- |
| 远端当前引用完全一致、未撤销 | 返回已验证发布 | 配置/片段可继续参与原有验证 |
| 远端未登记、旧快照、不同摘要、已撤销 | `CHECKPOINT_MISMATCH` | A/D 返回 403 `TRUST_CHECKPOINT_MISMATCH`；知识候选被过滤 |
| 网络/身份/TLS/提交确认失败、异常回执、超时 | `STATE_UNAVAILABLE` | A/D 返回 503 `TRUST_STATE_UNAVAILABLE`；检索返回 503，丢弃本次部分结果 |
| 进程已经见过更高区块，随后读取返回较低区块 | `STATE_UNAVAILABLE` | 不把较旧读取当作当前状态 |
| 必需模式下缺少检查点配置 | 启动失败 | 不启动纯本地服务 |

没有跨请求的成功缓存。同一检查点实例串行提交及验证，以免正常并发响应乱序被误判为区块回退；等待提交锁最多为 `max_read_seconds`，超时拒绝，随后的一次远端提交也须满足该耗时上限。高并发下可能等待或返回 503，吞吐与延迟需在部署环境另测。区块上界仅保存在每个检查点实例的内存中；重启后仍依赖所配置的 B 网络、组织、身份和提交验证，不能声称有独立于这些信任根的持久区块防回退。管理员锚定同样校验回执结构、交易 ID、区块范围和耗时，不仅检查返回的引用。

## 复现实验和证据范围

```powershell
python -B -m pytest -q -p no:cacheprovider business/tests trusted_release/tests role_b/tests gateway/tests
python -B -m trusted_release.checkpoint_demo
```

第二条使用真实 C 签名/验签、SQLite 文件备份恢复，以及 **B 原链码的内存桩**，不需要 Docker 或 Fabric 网络，也不代表真实链提交。输出明确包含 `backend: b-chaincode-memory` 和 `live_fabric: false`，覆盖正常发布、未锚定更新、新版锚定、整库回滚、独立撤销、新版恢复、检查点不可用、正常检索、撤销后检索和本地内容篡改。回滚用例同时证明旧库本地签名仍有效，但受保护消费端拒绝。

已有双组织网络时，使用独立的读、写配置运行同一实验：

```powershell
python -B -m trusted_release.checkpoint_demo --fabric-reader ../b-runtime/reader.json --fabric-publisher ../b-runtime/publisher.json
```

此模式会在配置所指向的测试链上创建一个唯一 `checkpoint-demo-*` 发布记录，提交更新、撤销和读取；不会修改既有制品。输出 `live_fabric: true`。只有该命令实际成功且保存结果后，才能声称通过了本次真实链发布检查点验收。它不测高风险审批、多组织串通、真实 Agent、日志自动上链或 600 次消融实验。

本机检查发现没有可运行的 WSL Linux/Fabric 部署，当前也没有 B 的真实连接配置。本次已完成可配置实现和原链码内存桩验收；真实链验收仍依赖 B 提供可访问的网络与两份连接配置。C 的签名私钥未写入实验输出。
