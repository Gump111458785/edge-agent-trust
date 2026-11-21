# C 模块接口与运行说明

以下为 C 与 A/B/D/E 的联调契约 v1，基于 main 的接口，并补充 2026-11-21 独立发布检查点配置。工作内容与验收记录见 [C 模块工作说明](c-work-summary.md)。

## 信任边界

C 验证发布来源、内容完整性、当前版本和撤销状态。消费端从部署方指定的配置加载公钥及其发布、撤销权限，发布私钥留在签名端。Agent、检索索引和令牌中的版本字段均不能指定信任根。C 不解释自然语言策略，也不把合法签名等同于内容语义安全。

发布和撤销通过 Python 库或管理员 CLI 导入受保护的 SQLite；面向 E 的 HTTP 服务只提供可信检索。A、D 分别读取自己的信任配置和当前发布状态。C 的检查完成后，业务授权、服务身份和写入仍由对应网关、执行器核验。

| 接收方 | 接口 | 输出与用途 |
| --- | --- | --- |
| 发布管理端 | `sign_release`、`sign_revocation`；`ReleaseStore.publish/revoke` | 生成签名信封，验证后更新发布状态 |
| A、D | `open_store`、`load_configuration` | 当前已验证策略、工具清单及证据版本 |
| A | `ExecutorReleaseCheck`、`ReleaseAwareExecutor` | 执行前核对发布版本与工具参数，复用 A 的业务事务 |
| B | `ReleaseRef` | `(scope, kind, artifact_id, version, manifest_sha256)` 发布锚定引用 |
| E | `POST /retrieval` | Dify External Knowledge 的已验证片段、来源、摘要及版本 |

## 签名发布与撤销格式

信封精确包含 `action`、`payload`、`signature`。`action` 为 `publish` 或 `revoke`；`signature` 为 Ed25519 签名的无填充 Base64URL，共 86 字符。JSON 拒绝重复成员、未知字段和非有限数值。完整结构见 [签名信封 Schema](../trusted_release/schemas/signed-statement.schema.json)。

| Payload 字段 | 类型与含义 |
| --- | --- |
| `scope` | 部署信任域；标识符格式 `[A-Za-z0-9_-]{1,80}` |
| `kind` | `prompt`、`agent_config`、`policy`、`tool_manifest` 或 `knowledge` |
| `artifact_id` | 同域、同类型下的制品 ID，使用上述标识符格式 |
| `version` | JSON 整数，范围 1–2147483647；同一制品更新时严格提高 |
| `key_id` | 部署配置中的公钥 ID，使用上述标识符格式 |
| `digest` | 64 位小写十六进制摘要；发布与撤销的含义如下 |

签名输入是 ASCII `edge-agent-trust:<action>:v1`、一个 LF 和规范化 **payload**。规范化采用按键名排序、紧凑 `,`/`:` 分隔符、不转义非 ASCII 的 UTF-8 JSON。发布的 `digest` 为原始内容字节的 SHA-256；即使 JSON 语义相同，改变原始字节也需重新签名。

`ReleaseRef.manifest_sha256` 是目标 **publish 签名输入**的 SHA-256，区别于内容摘要、信封 JSON 摘要和签名字节摘要。`ref.tag` 为 `v<版本>-<manifest_sha256>`。撤销的 `digest` 必须等于目标发布的 `manifest_sha256`，并精确匹配当前版本。

发布库校验签名、密钥权限和内容后，在 SQLite 事务内更新状态。同一有效发布可幂等重试；旧版本报 `ROLLBACK`，同版本冲突报 `VERSION_CONFLICT`，已撤销发布不能重放恢复。恢复服务需要发布更高版本。[协议实现](../trusted_release/protocol.py) · [状态实现](../trusted_release/store.py)

## Python 发布接口

| 调用 | 返回或约束 |
| --- | --- |
| `ReleaseStore.initialize(path, scope, keys)` | 管理员初始化数据库，返回 `ReleaseStore` |
| `open_store(config_path, initialize=False)` | 按部署公钥配置打开状态；消费端默认不创建数据库 |
| `sign_release(key, *, scope, kind, artifact_id, version, content, key_id)` | 返回 `SignedStatement`；`content` 为 bytes |
| `sign_revocation(key, ref, *, key_id)` | 返回针对该 `ReleaseRef` 的撤销信封 |
| `store.publish(signed, content)` | 返回 `ReleaseRef`；不会信任未经验证的输入引用 |
| `store.revoke(signed)` | 成功返回 `None`；同一有效撤销可重试 |
| `store.load(kind, artifact_id, expected_version=None)` | 返回 `VerifiedRelease(ref, content)`；检查当前签名、摘要、撤销及可选版本 |
| `store.verify(kind, artifact_id, content, expected_version=None)` | 另外比对外部内容字节，成功返回 `ReleaseRef` |

表中的 `expected_version` 是仅限关键字的参数，值为 `ref.tag`。库级拒绝抛出 `TrustError`，调用方读取 `.code`，它本身不是 HTTP 响应。

以下示例在临时目录生成独立实验密钥，验证发布、读取和撤销；不保留密钥或修改业务数据：

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trusted_release.protocol import TrustError, sign_release, sign_revocation
from trusted_release.store import ReleaseStore, TrustedKey

with TemporaryDirectory(prefix="c-interface-") as temporary:
    key = Ed25519PrivateKey.generate()
    kinds = frozenset({"prompt"})
    store = ReleaseStore.initialize(Path(temporary) / "releases.sqlite", "campus", {
        "publisher-c": TrustedKey(key.public_key(), publish=kinds, revoke=kinds),
    })
    content = "预约事实只来自业务服务。".encode("utf-8")
    signed = sign_release(key, scope="campus", kind="prompt", artifact_id="system",
                          version=1, content=content, key_id="publisher-c")
    ref = store.publish(signed, content)
    assert store.load("prompt", "system", expected_version=ref.tag).content == content
    store.revoke(sign_revocation(key, ref, key_id="publisher-c"))
    try:
        store.load("prompt", "system")
    except TrustError as error:
        assert error.code == "REVOKED"
    else:
        raise AssertionError("Revoked release was accepted")
```

## A、D 的可信配置交接

`load_configuration(store, *, policy_id, tool_manifest_id, policy_version=None, tool_manifest_version=None)` 从同一读快照加载两份制品并返回 `VerifiedConfiguration`。默认校园制品 ID 由服务入口约定为 `campus-policy` 和 `campus-tools`。

| 返回对象的方法 | 结果 |
| --- | --- |
| `config.evidence_versions()` | `{"policy_version": policy.ref.tag, "tool_manifest_version": tools.ref.tag}`，供 D 绑定到令牌 |
| `config.tool(tool_id)` | 返回已验签工具条目的副本；不存在时报 `UNKNOWN_TOOL` |
| `config.validate_arguments(tool_id, arguments)` | 按已签名 JSON Schema 校验 dict，成功返回 `None`；失败报 `INVALID_TOOL_ARGUMENTS` |

工具清单顶层为 `{"tools": [...]}`；每项精确包含 `tool_id`、`description`、`argument_schema`、`risk_level`、`execution_target` 和 `service_identity`。风险为 `read`、`normal` 或 `high`，目标为 HTTP/HTTPS URL。参数 Schema 须为 object 且自包含，可用本地片段引用，禁止外部 `$ref`/`$dynamicRef`。完整约束见 [工具清单 Schema](../trusted_release/schemas/tool-manifest.schema.json)。

D 读取 `config.tool(...)`，核对目标、服务身份及风险，并解析已签名策略；其严格 JSON v1 策略格式见 [D 的策略内容约定](d-interface-contract.md#c-的策略内容约定)。策略正文的 `version: 1` 是格式号，C 信封的 `version` 是发布修订号，两者分别管理。

A 使用 `ExecutorReleaseCheck(store, policy_id, tool_manifest_id)` 和 `ReleaseAwareExecutor(..., release_check=check)`，在使用时比对令牌中的版本并核验工具参数，再复用 A 的时效、会话、预约、审批及写入事务。组合入口的默认 `ROLE_A_PROFILE` 为 `evidence`；`token` 模式也检查当前发布，但令牌可不含证据版本。[组合实现](../trusted_release/role_a.py) · [A 的执行契约](a-interface-contract.md)

## E 的 POST /retrieval

请求头：

```http
Authorization: Bearer <ROLE_C_DIFY_KEY>
Content-Type: application/json
```

请求示例：

```json
{
  "knowledge_id": "campus",
  "query": "访客应该从哪个门进入？",
  "retrieval_setting": {"top_k": 3, "score_threshold": 0.0}
}
```

| 参数 | 约束 |
| --- | --- |
| `knowledge_id` | 等于部署的 `scope`，标识符长度 1–80 |
| `query` | 去除首尾空白后 1–2048 字符 |
| `retrieval_setting.top_k` | 整数，1–100 |
| `retrieval_setting.score_threshold` | 数值，0–1；不接受字符串或非有限数值 |
| `metadata_condition` | 可省略或为 null；非空 `conditions` 返回 `METADATA_FILTER_UNSUPPORTED` |

未知字段和类型错误返回 `422`。每次最多查询 `max(20, top_k * 4)` 个候选，过滤后最多返回 top_k 项，可能少于请求数量。分数为余弦集合的 `1 - distance`，截断到 0–1，分数本身不代表可信度。

成功响应结构如下，摘要和版本位置为示意占位符，实际返回完整值：

```json
{
  "records": [{
    "content": "访客请从东门登记进入。",
    "score": 0.87,
    "title": "campus-handbook",
    "metadata": {
      "scope": "campus",
      "artifact_id": "visitor-handbook",
      "release_version": "v1-<64位发布摘要>",
      "chunk_id": "entrance",
      "chunk_sha256": "<64位片段SHA-256>"
    }
  }]
}
```

知识发布内容为 `{"source":"campus-handbook","chunks":[{"chunk_id":"entrance","text":"访客请从东门登记进入。"}]}`，顶层和片段均不接受额外字段，片段 ID 不可重复，详见 [知识文档 Schema](../trusted_release/schemas/knowledge.schema.json)。响应的 title 来自签名文档 source，metadata 和文本来自已验证发布。伪造、篡改、旧版和已撤销候选被过滤；无可用命中时返回 `200 {"records": []}`。所有该接口的应用级响应带 `Cache-Control: no-store`。

| HTTP | error_code | error_msg |
| --- | --- | --- |
| 401 | 1001 | `BEARER_REQUIRED`：未提供 Bearer |
| 401 | 1002 | `AUTHORIZATION_FAILED`：Bearer 不匹配 |
| 404 | 2001 | `KNOWLEDGE_NOT_FOUND`：知识库域不符 |
| 422 | 2002 | `INVALID_REQUEST` 或 `METADATA_FILTER_UNSUPPORTED` |
| 503 | 2003 | 状态或检索依赖错误，如 `STATE_UNAVAILABLE`、`INDEX_UNAVAILABLE` |

失败响应为 `{"error_code": 1002, "error_msg": "AUTHORIZATION_FAILED"}`。认证先于请求体校验；候选级失败只被过滤并记录原因，不将未验证内容作为降级结果返回。[HTTP 实现](../trusted_release/dify_api.py)

## 拒绝码与 B 的发布引用

| TrustError.code | 含义 |
| --- | --- |
| `INVALID_STATEMENT` / `INVALID_CONTENT` | 信封或结构化载荷无效 |
| `SCOPE_MISMATCH` / `UNAUTHORIZED_KEY` / `BAD_SIGNATURE` | 域、公钥权限或签名不符 |
| `DIGEST_MISMATCH` / `CHUNK_DIGEST_MISMATCH` | 内容或候选片段摘要不符 |
| `ROLLBACK` / `VERSION_CONFLICT` / `VERSION_MISMATCH` | 旧发布、同版本冲突或使用时版本不符 |
| `CHECKPOINT_MISMATCH` | 独立检查点未登记、已撤销或与本地完整发布引用不符 |
| `REVOKED` / `UNKNOWN_RELEASE` / `UNKNOWN_TOOL` / `UNKNOWN_CHUNK` | 撤销或目标不存在 |
| `INVALID_TOOL_ARGUMENTS` / `INVALID_QUERY` / `INVALID_CANDIDATE` | 参数、查询或候选格式不符 |
| `STATE_UNAVAILABLE` / `STATE_INVALID` / `INDEX_UNAVAILABLE` | 状态不可用、绑定异常或索引依赖不可用 |

A 的 `ExecutorReleaseCheck` 将库拒绝映射为 `reason_code="TRUST_" + code`：`STATE_UNAVAILABLE`、`STATE_INVALID` 为 HTTP 503，其余为 403。格式沿用 A 的执行拒绝响应，不能与 Dify 的 error_code/error_msg 混用。

B 接收 `dataclasses.asdict(ref)`，包含 scope、kind、artifact_id、version、manifest_sha256。C 先验证发布，再由获准操作者调用 B 的 `publish_release(client, ref)` 或 `revoke_release(client, ref)`。`release_current(client, ref)` 为 True 时表示链上当前引用完全一致且未撤销；不可用时拒绝相关受保护操作，不能当作核验成功。[B 的接口和权限](b-fabric-approvals.md)

上述 B 适配函数属于 B。C 信任配置可增加 `checkpoint={"provider":"fabric","config":"fabric/reader.json","max_read_seconds":15}`；启用后每次 `ReleaseSnapshot.load` 通过 B 的 `FabricClient` 提交 `ReadRelease`，严格核对完整引用、未撤销状态与提交回执。`config` 相对于 C 信任配置；1–15 秒整数限制单次读取耗时，默认 15。`ROLE_C_REQUIRE_CHECKPOINT=1` 要求配置存在；无效配置或异常依赖不降级。纯本地模式保持兼容，但不能声称有此保护。

`ROLE_B_FABRIC_CONFIG` 在 C 组合入口仍只启用高风险审批源，不能代替发布检查点配置。独立状态读取失败映射为已有 `STATE_UNAVAILABLE`；A/D 为 503，检索为 503 并清空本次部分结果。合法格式但不匹配的候选在检索中被过滤。详见 [部署、管理员锚定和可复现实验](c-checkpoint-integration.md)。

## 本地运行与配置

安装 `trusted_release/requirements-service.txt`。信任配置的 database 和 public_key 路径相对于配置文件目录，示例为：

```json
{
  "scope": "campus",
  "database": "releases.sqlite",
  "keys": {
    "publisher-c": {
      "public_key": "publisher-c.pem",
      "publish": ["policy", "tool_manifest", "knowledge"],
      "revoke": ["policy", "tool_manifest", "knowledge"]
    }
  }
}
```

示例允许同一实验密钥发布和撤销；部署可按 [运行指南](../trusted_release/README.md#本地联调) 分设密钥权限。管理员先初始化状态、导入离线签名，再建立知识索引：

```powershell
python -B -m trusted_release.manage --config ../c-runtime/trust.json init
python -B -m trusted_release.manage --config ../c-runtime/trust.json publish ../c-runtime/handbook.signed.json ../c-runtime/handbook.json
python -B -m trusted_release.manage --config ../c-runtime/trust.json index visitor-handbook --index-dir ../c-runtime/chroma --model-dir ../member-c-assets/bge-m3-onnx
```

CLI 的 publish 成功输出 ReleaseRef JSON，index 输出 ref.tag，init/revoke 成功无输出；操作成功退出 0，捕获的信任、文件或值错误打印到 stderr 并退出 1，命令用法错误由 argparse 处理。撤销实验使用 `python -B -m trusted_release.manage --config ../c-runtime/trust.json revoke ../c-runtime/handbook.revoked.json`。

`publish` 和 `revoke` 新增可选 `--anchor-config <B发布者连接配置>`，相对于命令工作目录。C 验证签名及内容/目标并更新本地状态后，再提交 B 发布/撤销交易；锚定失败退出 1，发布不输出成功引用，可幂等重试。该身份不交给消费服务。两处存储不原子提交，不能把本地成功、远端失败表述为整体完成。

| 环境变量 | 用途 / 默认值 |
| --- | --- |
| `ROLE_C_TRUST_CONFIG` | 必填；上述信任配置路径 |
| `ROLE_C_REQUIRE_CHECKPOINT` | 消费进程正式部署设 `1`；缺少检查点配置则启动失败。仅接受 `0`/`1`，默认 `0` 兼容本地实验 |
| `ROLE_C_POLICY_ID` / `ROLE_C_TOOLS_ID` | A/D 使用，默认 `campus-policy` / `campus-tools` |
| `ROLE_C_BGE_MODEL_DIR` | 检索必填；固定 BGE-M3 ONNX 及 tokenizer 目录 |
| `ROLE_C_INDEX_PATH` | 检索必填；已建立的持久化 Chroma 索引 |
| `ROLE_C_DIFY_KEY` | 检索必填；至少 24 个 ASCII 字符且无空白的独立 Bearer |
| `ROLE_B_FABRIC_CONFIG` | 组合执行器可选；B 的独立审批读配置 |

检索服务用 `python -m uvicorn trusted_release.dify_api:create_app --factory --host 127.0.0.1 --port 8003` 启动。Dify Cloud 配置可访问的 HTTPS 服务基址，knowledge_id 填 scope；Dify 拼接 `/retrieval`。A 组合执行器用 `python -m uvicorn trusted_release.role_a:create_app --factory --host 127.0.0.1 --port 8001` 启动，还需 [A 的原有环境变量](../business/README.md)。

消费端不持有发布私钥。更新嵌入式 Chroma 时先停止检索服务，再索引并重启；公钥配置改变后也需重启相关消费服务。B 的公钥等启动配置损坏会启动失败，节点连接、TLS 或客户端故障在高风险请求时拒绝。

## 验收与适用范围

在仓库根目录安装测试依赖后运行 `python -B -m pytest -q -p no:cacheprovider trusted_release/tests` 和 `python -B -m trusted_release.demo`。端到端本地运行参考 [D 的接口文档](d-interface-contract.md#本地运行)，在签发后更新策略或撤销清单，核对 A 的 `TRUST_VERSION_MISMATCH` / `TRUST_REVOKED` 和未新增权限、未消费令牌的状态。

未启用检查点时，防回滚依赖本地可信数据库及备份未被替换。启用后，每次使用还核对独立当前状态，可发现与该状态不符的旧快照；仍依赖所配 Fabric 网络及信任根完好。区块单调上界只保存在检查点实例内存中；发布读取与业务事务、管理员本地写入与远端锚定之间仍有跨存储窗口。合法签名的恶意文本可能通过完整性校验。Dify Cloud、真实 Fabric 和完整攻防实验的验收范围见 [C 工作记录](c-work-summary.md)。
