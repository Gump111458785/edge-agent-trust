# D 模块工作说明

日期：2026-11-18。开发分支：`feat/d-evidence-gateway`。
本次工作由 Codex 根据 D 的职责实现，代码位于当前项目的 `gateway/`，未修改 A、C 的现有实现。

## 本次实现

D 负责将 Agent 的不可信操作提案转换为证据绑定的执行授权。当前支持 A 已实现的两个写操作：
`grant_access` 和 `grant_restricted_access`，不将 README 中尚未实现的其他业务工具声明为已交付。

| 文件 | 工作内容 |
| --- | --- |
| `gateway/service.py` | 严格提案模型、A 事实查询客户端、预约与身份核验、C 发布配置校验、确定性策略、审批检查、签名令牌、SQLite 决策日志 |
| `gateway/main.py` | FastAPI `/authorize` 接口、服务认证、会话头、环境配置、固定服务地址及 HTTP 客户端生命周期 |
| `gateway/setup_demo.py` | 创建全新本地演示目录，生成 D 密钥、C 公钥及签名策略/工具发布库，不覆盖已有密钥 |
| `gateway/requirements*.txt` | 运行与测试依赖，沿用 A 的固定版本及 C 的依赖范围 |
| `gateway/tests/test_core.py` | 不依赖 socket 的 D–C–A 核心集成与攻击测试，实际调用 A 的执行器并检查 SQLite 状态 |
| `gateway/tests/test_gateway.py` | HTTP 接口、认证、严格参数、跨会话、审批、C 配置更新、令牌过期及重放测试 |
| `.github/workflows/member-d.yml` | Python 3.12 下安装声明依赖，运行 A/D/C 发布校验测试及原有状态评测 |
| `docs/d-interface-contract.md` | 请求/响应、错误码、策略格式、部署变量和完整本地运行步骤 |
| `README.md`、`.gitignore` | 增加 D 入口、更新 D 工作状态，忽略演示密钥及运行数据目录 |

## 授权过程

1. 校验调用服务凭据和请求结构，拒绝模型指定身份、证据、令牌、目标地址或跳过审批标志。
2. 使用独立事实查询凭据访问 A，确认真实用户会话、预约归属、预约状态、区域、时间窗口和授权时长。
3. 使用 C 的 `load_configuration` 校验签名发布物、当前版本和撤销状态；按签名工具 Schema 验证参数，并比对固定执行地址、服务身份和风险级别。
4. 执行签名策略中的动作、区域和时长规则。缺失规则默认拒绝；不解释自然语言中的“允许执行”指令。
5. 机房授权复用 A 的 `ApprovalVerifier`，核对操作摘要、组织集合、批准状态、有效期及新鲜度。默认无真实审批源时拒绝。
6. 复用 A 的规范化 JSON、参数摘要和签名域，签发 Ed25519 令牌。绑定操作 ID、工具动作、参数、可信用户、会话 ID、预约 ID/版本及 C 的策略/工具版本。
7. 默认令牌 60 秒、最多 120 秒，并受会话、预约及审批到期时间约束。先持久化决策日志，成功后才向调用方返回令牌。
8. 可信编排服务把 D 响应原样交给 A。A 独立复验签名、会话、当前业务证据、C 配置和高风险审批，并在 SQLite 事务中处理一次性消费。

D 不持有业务数据库写权限，不把“签发成功”等同于“执行成功”。
短期令牌的随机 ID 与稳定操作 ID 配合 A 的唯一性约束，阻止同一令牌以及同一操作换令牌后的重复成功写入。

## 已完成验证与环境限制

本机使用 Python 3.11 及离线缓存安装包验证。由于网络/代理限制，项目固定版本依赖未能在线安装，
本次实际版本为 FastAPI 0.141.1、Pydantic 2.13.5、cryptography 50.0.1、httpx 0.28.1、
pytest 8.4.2、jsonschema 4.26.0、referencing 0.37.0。
未为适应缓存而放宽项目已有依赖要求。

已执行以下不依赖 socket 的测试：

```powershell
.\.venv\test311\Scripts\python.exe -B -m pytest -q -p no:cacheprovider `
  gateway/tests/test_core.py trusted_release/tests/test_release.py gateway/tests/test_gateway.py `
  -k 'not test_gateway or deployment_urls or demo_setup'
```

结果：**57 通过，47 未选择**。其中 D 核心集成 29 项、D 独立配置/演示测试 5 项、C 发布校验回归 23 项。
有 1 个新版 Starlette 关于测试客户端使用 httpx 的弃用警告。
核心集成验证了真实 D 令牌可以被 A 验证并提交数据库，以及以下情况不能产生未授权写入：

- 跨用户预约、撤销/失效/未来预约、错误区域和过长授权。
- 已签名但目标地址、服务身份、风险级别或参数 Schema 不符合部署要求的工具。
- 撤销的清单、内容摘要被篡改、无效策略和缺失策略规则。
- 参数篡改、会话替换、签发后预约版本变化、令牌过期。
- 重放同一令牌、同一操作重新签发新令牌、高风险审批签发后撤销。
- 事实源超时、重定向、响应结构不可信，以及审计写入失败。

Python 编译检查和 `git diff --check` 已通过；本地演示初始化已实际运行成功。
HTTP 测试文件已成功收集 52 项，其中上述 5 项无需 socket 的测试已运行。
其余 47 项 HTTP/fixture 测试以及 A 的完整回归、原有状态评测**尚未完成**：
Windows 受限环境中的 `TestClient` 在 `asyncio → socket.socketpair → accept` 创建本地 socket 时阻塞，
诊断后已停止相关进程。没有将其记为通过，也未更改执行器或测试代码以绕过环境限制。

CI 已配置但尚未推送运行。可在正常网络与本地 socket 可用的环境中执行：

```powershell
python -m pip install -r gateway/requirements-dev.txt
python -B -m pytest -q -p no:cacheprovider business/tests gateway/tests trusted_release/tests/test_release.py
python -B -m evaluation.run_benchmark
```

## 尚需协作的部分

- **B：**提供真实 Fabric `ApprovalSource.fetch_verified`，分别注入 D 和 A；接入日志 Merkle 锚定。当前审批成功测试使用明确的模拟来源，不代表 Fabric 联调完成。
- **C：**确认 D 文档定义的 JSON v1 策略内容，使用真实发布流程签发；部署时向 A、D 配置相同的发布信任根与 artifact ID。
- **A/E：**通过可信入口传递真实会话，由编排服务串联授权与执行，完成 Dify 实际调用。D 本次只提供授权接口，没有自动代理执行请求。
- **实验：**补充真实 LLM、提示注入及自然语言越权任务的实验记录。当前结果属于结构化攻击与执行边界验证，不是模型攻击成功率统计。

交付分支为 `feat/d-evidence-gateway`。后续通过 Pull Request 审查并合入 `main`；本次未合并主分支。
