# C · 密码学与可信发布

本模块签名发布 Agent 配置、提示词、策略、工具清单和知识文档。A 与 D 在使用时读取当前可信版本，E 接入检索时应只将已验证片段交给 Agent。五人分工和完整的攻防实验见 [项目总览](../README.md)。

## 本地复现

在仓库根目录使用 Python 3.12 或 3.13 的独立环境运行。自动化测试和快速攻击演示使用真实 Chroma 和固定向量。真实 BGE-M3 的小规模对照使用下方固定的 INT8 ONNX 权重。

```powershell
python -m pip install -r trusted_release/requirements-test.txt
python -B -m pytest -q -p no:cacheprovider business/tests trusted_release/tests
python -B -m trusted_release.demo
```

演示输出 JSON 记录，包括预期结果、实际拒绝码、耗时及检索片段的出处。例如，修改策略文件得到 `DIGEST_MISMATCH`，重放旧签名发布得到 `ROLLBACK`，向索引写入篡改文本得到 `CHUNK_DIGEST_MISMATCH`。合法签名的注入文本会作为有出处的引用返回。演示记录的是 C 的检索和发布判定。Agent 是否提出越权调用、执行器是否改变业务状态由端到端实验测量。

## 签名、发布与撤销

[签名信封 Schema](schemas/signed-statement.schema.json) 的载荷包含 `scope`、`kind`、`artifact_id`、单调递增的整数 `version`、`key_id` 和 `digest`。`kind` 可为 `agent_config`、`prompt`、`tool_manifest`、`policy` 或 `knowledge`。

| 动作 | 签名输入 | `digest` 含义 |
| --- | --- | --- |
| `publish` | ASCII `edge-agent-trust:publish:v1`、一个 LF、规范化载荷 | 原始发布内容字节的 SHA-256 |
| `revoke` | ASCII `edge-agent-trust:revoke:v1`、一个 LF、规范化载荷 | 目标发布签名输入的 SHA-256，等于 `ref.manifest_sha256` |

规范化载荷是按键名排序、使用紧凑分隔符、保留非 ASCII 字符的 UTF-8 JSON。签名编码为无填充的 Base64URL，摘要为小写十六进制。信封解析拒绝重复成员和未知字段，版本使用 1 到 2147483647 的 JSON 整数。校验者从部署配置取得可信公钥，以及每把公钥可发布或撤销的制品类型。

```python
from pathlib import Path

from trusted_release.protocol import SignedStatement, sign_release, sign_revocation
from trusted_release.store import ReleaseStore, TrustedKey

# publisher_key and revoker_key are Ed25519 private keys held by their respective operators.
keys = {
    "publisher-c": TrustedKey(publisher_key.public_key(), publish=frozenset({"prompt"})),
    "revoker-c": TrustedKey(revoker_key.public_key(), revoke=frozenset({"prompt"})),
}
store = ReleaseStore.initialize(Path("releases.sqlite"), "campus-demo", keys)
content = "访客预约信息仅来自业务服务。".encode("utf-8")
statement = sign_release(
    publisher_key, scope="campus-demo", kind="prompt", artifact_id="system",
    version=1, content=content, key_id="publisher-c",
)
ref = store.publish(SignedStatement.from_json(statement.to_json()), content)
assert store.load("prompt", "system", expected_version=ref.tag).content == content
store.revoke(sign_revocation(revoker_key, ref, key_id="revoker-c"))
```

`initialize` 用于管理员初次配置。消费端用 `ReleaseStore(path, scope, keys)` 打开同一份受保护状态，只需读取公钥和数据库。发布、更新与撤销各在 SQLite 写事务中完成。同一有效发布可重试，同版本换内容会冲突，撤销后只有更高版本可恢复发布。网关和执行器可用 `load` 取得已验证的原始字节，或用 `verify` 校验运行前读取的外部文件字节。策略交由 D 的策略解析器解释。

## A、D 与 E 接口

工具清单遵循 [工具清单 Schema](schemas/tool-manifest.schema.json)。发布签名覆盖工具标识、描述、参数 JSON Schema、风险级别、执行目标及服务身份。参数 Schema 须自包含，允许本地片段引用。`validate_arguments` 使用关闭外部解析的验证器。网关还需核对业务策略和下游身份。执行器按它的可信规则独立验证请求。

```python
from trusted_release.configuration import load_configuration

# D reads the current pair and uses its versions in the signed token's evidence.
config = load_configuration(store, policy_id="campus-policy", tool_manifest_id="campus-tools")
tool = config.tool("grant_access")
config.validate_arguments("grant_access", proposed_args)
versions = config.evidence_versions()  # {"policy_version": "...", "tool_manifest_version": "..."}

# The opt-in A adapter makes the independent comparison while handling the operation.
load_configuration(
    store, policy_id="campus-policy", tool_manifest_id="campus-tools",
    policy_version=claims.evidence.policy_version,
    tool_manifest_version=claims.evidence.tool_manifest_version,
)
```

这两个标识形如 `v2-<64 位发布摘要>`，长度不超过 A 约定的 80 字符。策略和清单从同一读快照加载。A 应在授权决策时读取，跨进程撤销与业务提交之间的时间窗口由联调实验记录。B 可用 `(scope, kind, artifact_id, version, manifest_sha256)` 登记发布摘要。

知识内容使用 [知识文档 Schema](schemas/knowledge.schema.json)。示例请求文档为 `{"source":"handbook","chunks":[{"chunk_id":"entrance","text":"请前往东门。"}]}`。发布将文档来源、片段 ID 和文本一起绑定。联调入口和真实模型实验使用固定版本的 BGE-M3 INT8 ONNX 导出。模型及 Chroma 索引保存在工作树之外。 [BAAI/BGE-M3 模型说明](https://huggingface.co/BAAI/bge-m3) · [ONNX 导出](https://huggingface.co/Xenova/bge-m3/tree/4de13258303883538bd53b696b452bf8099f0858) · [Chroma 查询说明](https://docs.trychroma.com/docs/querying-collections/query-and-get)

```python
from pathlib import Path
from trusted_release.embedding import open_onnx_index
from trusted_release.rag import retrieve

index = open_onnx_index(Path("../campus-index"), Path("../member-c-assets/bge-m3-onnx"))
index.add_release(store.load("knowledge", "visitor-handbook"))
result = retrieve(index, store, "访客入口在哪？", limit=3, candidate_limit=20)
for hit in result.hits:
    print(hit.text, hit.source, hit.chunk_id, hit.ref.tag, hit.chunk_sha256)
```

只有 `hits` 进入 Agent 上下文。每项含签名文档出处、`ref`、片段 ID、文本及 SHA-256。调用方可把 `rejections` 的候选名次与错误码写入实验日志。同一文档应按当前发布顺序更新索引。`add_release` 写入新片段后清理旧版本，清理失败时可重试。索引可影响排序和可用性，只有当前签名文档支持的片段能作为证据返回。

## 本地联调

生产与实验配置都从部署方指定的 JSON 读取受信任的 Ed25519 **公钥**。下方示例的数据库和公钥路径相对于配置文件目录。操作方通过前文的签名函数生成信封，私钥留在签名端。

```json
{
  "scope": "campus",
  "database": "releases.sqlite",
  "keys": {
    "publisher-c": {
      "public_key": "publisher-c.pem",
      "publish": ["agent_config", "prompt", "policy", "tool_manifest", "knowledge"],
      "revoke": []
    },
    "revoker-c": {
      "public_key": "revoker-c.pem",
      "publish": [],
      "revoke": ["agent_config", "prompt", "policy", "tool_manifest", "knowledge"]
    }
  }
}
```

将已签名内容导入并索引。撤销操作接收独立签名的撤销信封。

```powershell
python -m pip install -r trusted_release/requirements-service.txt
python -B -m trusted_release.manage --config ../c-runtime/trust.json init
python -B -m trusted_release.manage --config ../c-runtime/trust.json publish ../c-runtime/handbook.signed.json ../c-runtime/handbook.json
python -B -m trusted_release.manage --config ../c-runtime/trust.json index visitor-handbook --index-dir ../c-runtime/chroma --model-dir ../member-c-assets/bge-m3-onnx
python -B -m trusted_release.manage --config ../c-runtime/trust.json revoke ../c-runtime/handbook.revoked.json
```

最后一条用于撤销实验。在正常检索或启动服务前先保留当前文档。为 A 联调发布策略 `campus-policy` 与工具清单 `campus-tools`，或分别设置 `ROLE_C_POLICY_ID` 与 `ROLE_C_TOOLS_ID`。配齐 [A 执行器原有变量](../business/README.md) 后设置 `ROLE_C_TRUST_CONFIG`，用以下可选入口运行。C 先验证令牌签名和当前发布，然后把该请求所用的可信版本交给 A 的原有执行器。A 独立重验令牌、时效、身份、预约及多方审批，并提交业务事务。C 拒绝码带 `TRUST_` 前缀。D 负责解释策略和裁决。

```powershell
python -m uvicorn trusted_release.role_a:create_app --factory --host 127.0.0.1 --port 8001
```

此入口读取与 A 相同的可选变量 `ROLE_B_FABRIC_CONFIG`，其值为 B 的 Fabric 读配置文件绝对路径。配置文件内的部门公钥、证书和 TLS 路径按 [B 的接入说明](../docs/b-fabric-approvals.md) 设置，Node.js 客户端依赖也须安装。配置存在时，C 的组合入口向 A 传入独立的 `ApprovalVerifier`，高风险执行重新核对 B 的部门签名和当前审批状态。部门公钥等启动加载配置无效时启动失败；节点连接、身份、TLS 或客户端问题在高风险请求时返回 `APPROVAL_UNAVAILABLE`；未设置此变量时高风险操作也返回 `APPROVAL_UNAVAILABLE`。程序化部署也可向 `ReleaseAwareExecutor` 提供 A 的 `ApprovalVerifier`。C 读取当前发布与 A 提交权限库之间存在跨库窗口，需按组内接口契约在联调中测量。

对 Dify，配置 `ROLE_C_TRUST_CONFIG`、`ROLE_C_BGE_MODEL_DIR`、`ROLE_C_INDEX_PATH` 和长度至少 24 字符的独立 Bearer 密钥 `ROLE_C_DIFY_KEY`。软件将信任域 `scope` 作为 External Knowledge ID。用以下命令可在本机启动外部知识库服务。

```powershell
python -m uvicorn trusted_release.dify_api:create_app --factory --host 127.0.0.1 --port 8003
```

向 `POST /retrieval` 发送 Bearer 密钥及 `{"knowledge_id":"campus","query":"访客入口在哪？","retrieval_setting":{"top_k":3,"score_threshold":0.0}}`。响应示例为 `{"records":[{"content":"请前往东门。","score":0.87,"title":"handbook","metadata":{"artifact_id":"visitor-handbook","chunk_id":"entrance","release_version":"v1-…","chunk_sha256":"…","scope":"campus"}}]}`。分数来自 Chroma 余弦相似度，来源和片段摘要来自已验证发布。当前接口支持单个信任域、Top K 和分数阈值。实际使用元数据筛选会返回 `422`。未授权返回 `401`，错误知识库 ID 返回 `404`，无法使用底层状态或索引时返回 `503`。

Dify Cloud 对接时需要能从云端访问的测试 HTTPS 地址。外部知识库配置填服务地址，Dify 自行拼接 `/retrieval`。本地 HTTP 契约测试覆盖成功检索、篡改过滤、撤销、认证和故障。Dify Cloud 的应用配置和真实模型工具调用仍需 E 联合验收。 [Dify 外部知识库 API](https://docs.dify.ai/en/cloud/use-dify/knowledge/external-knowledge-api)

更新嵌入式 Chroma 时，先停止检索服务，再运行 `manage index`，然后重启服务读取新索引。SQLite 中已提交的撤销在下一次读取快照时生效。变更信任公钥后需重启检索服务和 A 的组合入口，以加载新的公钥配置。

## 独立发布检查点

要发现**整个本地数据库被旧快照替换**，使用 [带检查点的信任配置](examples/trust-checkpoint.json)，并为所有消费进程设置 `ROLE_C_REQUIRE_CHECKPOINT=1`。配置中的 `checkpoint` 指定 B 的只读 Fabric 连接配置；每次发布加载均在本地验签后提交 `ReadRelease`，比对完整引用与撤销状态。配置存在时始终强制校验，不缓存跨请求的成功结果，不在网络错误时退回仅本地校验。

远端不一致报 `CHECKPOINT_MISMATCH`；读取或提交确认不可用报 `STATE_UNAVAILABLE`。A/D 延续原错误映射拒绝请求；检索在依赖不可用时返回 503，并丢弃部分结果。管理员 `manage publish/revoke` 可通过显式 `--anchor-config` 使用独立发布身份锚定已经验证的发布/撤销。部署步骤、失败重试和跨存储窗口见 [C 检查点接入说明](../docs/c-checkpoint-integration.md)。

```powershell
python -B -m trusted_release.checkpoint_demo
```

该命令运行真实 C 签名及 B 原链码的**内存桩**，验证整库回滚、独立撤销与恢复等 10 个场景；输出 `live_fabric: false`，不是实际 Fabric 证据。有真实测试链时可提供 `--fabric-reader` 和 `--fabric-publisher` 运行同一实验。C 专属 CI 安装 Node.js 22 并运行此实验。原纯本地示例继续兼容，但不具备独立检查点保护。

## 真实 BGE-M3 对照实验

下载固定修订的 INT8 ONNX 模型和分词器到仓库外的资产目录。测试运行器会核对两份文件的 SHA-256。

```powershell
hf download Xenova/bge-m3 tokenizer.json onnx/model_int8.onnx --revision 4de13258303883538bd53b696b452bf8099f0858 --local-dir ../member-c-assets/bge-m3-onnx
python -B -m trusted_release.model_demo --model-dir ../member-c-assets/bge-m3-onnx
```

2026-11-16 的本地运行使用 CPU 和 1024 维向量，三条中文问题的 Top-1 均命中预期文档。固定同一批 Chroma 候选后，未核验的 Top-1 为攻击者写入的伪造片段，可信检索以 `CHUNK_DIGEST_MISMATCH` 拒绝该片段。Dify 协议的本地请求在撤销前收到合法规章，撤销后返回的记录不含该规章。运行器固定三个合成问题并输出实测结果。该实验没有调用云端大模型。

## 拒绝码与信任边界

| 错误码 | 条件 |
| --- | --- |
| `INVALID_STATEMENT` / `INVALID_CONTENT` | 信封、结构化工具或知识载荷无效 |
| `SCOPE_MISMATCH` / `UNAUTHORIZED_KEY` / `BAD_SIGNATURE` | 部署域、密钥授权或签名校验失败 |
| `DIGEST_MISMATCH` / `CHUNK_DIGEST_MISMATCH` | 制品字节或候选片段与签名内容不符 |
| `ROLLBACK` / `VERSION_CONFLICT` / `VERSION_MISMATCH` | 旧发布、同版本分叉或运行时版本已更改 |
| `CHECKPOINT_MISMATCH` | 本地发布与独立当前引用或撤销状态不一致 |
| `REVOKED` / `UNKNOWN_RELEASE` / `UNKNOWN_TOOL` / `UNKNOWN_CHUNK` | 当前制品已撤销或指定身份不存在 |
| `INVALID_QUERY` / `INVALID_CANDIDATE` | 查询参数或索引记录格式错误 |
| `INVALID_TOOL_ARGUMENTS` | 工具调用参数违反已验证的 Schema |
| `STATE_INVALID` / `STATE_UNAVAILABLE` / `INDEX_UNAVAILABLE` | 无法验证状态绑定或访问依赖 |

SQLite 保存已见最高版本和当前撤销状态。部署须控制数据库及其备份的写权限，按可信状态恢复。启用上述独立检查点后，可发现与远端当前引用不符的旧快照；没有配置时仅有本地保护。该保证依赖独立网络及其信任配置完好，并保留跨存储读取/提交窗口。发布信任根和签名密钥均由部署配置。常规轮换可先发布新版再移除旧公钥。紧急轮换可先移除失陷公钥，使相应旧版立即无法加载，再用新公钥对应的私钥签发高于已见版本的发布。

模块使用标准 SHA-256 和 Ed25519，并验证已知测试向量。单调版本检查参考 TUF 的回滚威胁模型，本模块只使用本文规定的信封和部署状态。 [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) · [RFC 8032 的 Ed25519 向量](https://www.rfc-editor.org/rfc/rfc8032#section-7.1) · [TUF 规范](https://theupdateframework.github.io/specification/latest/)

知识投毒用例借鉴 Zou 等人的 *PoisonedRAG*（USENIX Security 2025）的威胁模型。C 的真实模型对照固定同一份候选序列，记录受篡改片段能否通过验证。Chang 等人的 *Overcoming the Retrieval Barrier*（USENIX Security 2026）把检索与后续注入效果作为不同环节。端到端联调应分别记录候选检索、可信校验、Agent 行为和业务写入。 [PoisonedRAG](https://www.usenix.org/conference/usenixsecurity25/presentation/zou-poisonedrag) · [Overcoming the Retrieval Barrier](https://www.usenix.org/conference/usenixsecurity26/presentation/chang-hongyan)
