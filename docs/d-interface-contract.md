# D 模块接口与运行说明

## 信任边界

D 把 Agent 提案转换为 A 能独立验证的执行请求，不直接写业务数据库。
用户身份只从 A 的 `/internal/session` 获取；预约只从 A 的内部预约接口获取。
请求体禁止指定 subject、证据、风险级别、执行地址、令牌和绕过审批标志。
`X-Session-Token` 必须由可信登录入口传递，不能由模型根据自然语言生成。
部署时仅让可信编排服务持有 D 服务凭据；模型不应接触服务凭据或签名私钥。

## POST /authorize

请求头：

```http
Authorization: Bearer <ROLE_D_SERVICE_KEY>
X-Session-Token: <A 签发的不透明用户会话令牌>
Content-Type: application/json
```

请求示例：

```json
{
  "operation_id": "d-demo-001",
  "action": "grant_access",
  "args": {"booking_id": "BK-1042", "area": "visitor_area", "valid_minutes": 15},
  "approval_ref": null
}
```

省略 `operation_id` 时 D 生成 UUID；高风险审批应先确定该 ID，再以相同 ID 请求授权。
成功响应为完整的 A `ExecuteRequest`：`operation_id`、`action`、`args`、`token`。
令牌包含可信 subject、参数摘要、随机 token_id、签发和过期时间，以及会话、预约版本、C 策略与工具清单版本。
签名直接复用 A 的规范化函数、域分离和 Ed25519 协议，不另定义协议。
默认寿命 60 秒，上限 120 秒，同时不超过会话、预约和已验证审批的有效期。
响应包含 `Cache-Control: no-store`。

可信编排服务将成功响应原样 POST 到 A 的 `/internal/executor/access-grants`，使用
`ROLE_A_EXECUTOR_KEY` 作为 Bearer，并传递同一个 `X-Session-Token`。
D 的授权成功仅表示可以尝试执行；业务是否修改以 A 的响应和数据库状态为准。
相同 operation_id 可申请多个短期令牌，但 A 只允许一次成功提交；D 不宣称已经消费令牌。

| HTTP | 常见 reason_code | 含义 |
| --- | --- | --- |
| 401 | SERVICE_AUTH_REQUIRED / SESSION_REQUIRED | 服务凭据或用户会话无效 |
| 403 | BOOKING_NOT_FOUND / BOOKING_INACTIVE / AREA_NOT_ALLOWED | 预约归属、状态或区域不符合 |
| 403 | GRANT_OUTSIDE_BOOKING / POLICY_DENIED | 时长超出预约或签名策略 |
| 403 | ACTION_AREA_MISMATCH / TOOL_TARGET_MISMATCH / TOOL_RISK_MISMATCH | 动作、执行目标或风险级别不一致 |
| 403 | TRUST_* | C 的发布物、版本、签名或工具参数校验失败 |
| 403 | APPROVAL_REQUIRED / APPROVAL_MISMATCH / APPROVAL_INSUFFICIENT / APPROVAL_EXPIRED | 审批缺失或不符合 |
| 422 | INVALID_REQUEST | 未知字段、未知动作或严格类型校验失败 |
| 503 | FACTS_UNAVAILABLE / POLICY_INVALID / AUDIT_UNAVAILABLE | 事实源、策略格式或审计存储故障 |
| 503 | APPROVAL_UNAVAILABLE / APPROVAL_STALE | 审批来源不可用或状态过旧 |

失败响应格式为 `{"status":"rejected","reason_code":"..."}`。
请求格式及服务认证失败由 HTTP 层拒绝；进入授权流程的决策记录在 D 的 SQLite 日志中。
日志仅包含操作 ID、动作、参数摘要、结果、原因、令牌 ID、证据版本和时间，不含会话令牌、服务密钥、签名或私钥。
持久化授权日志失败时不向调用方返回令牌。日志尚未接入 B 的 Merkle 锚定，不能声称具备链上防篡改能力。

## C 的策略内容约定

C 已提供签名校验、撤销检查、版本防回滚、工具 Schema 校验，但不解释 policy 内容。
D 定义以下严格 JSON v1 格式，需由 C 的发布方签名发布为 `policy`：

```json
{
  "version": 1,
  "rules": {
    "grant_access": {"area": "visitor_area", "max_valid_minutes": 60},
    "grant_restricted_access": {"area": "server_room", "max_valid_minutes": 30}
  }
}
```

缺失规则默认拒绝。未知字段、自由文本策略或格式错误不会被解释为放行。
工具清单继续使用 C 现有 Schema。普通授权要求 `normal`，机房授权要求 `high`；
目标 URL 必须与部署配置完全相同，服务身份必须等于令牌 audience。
说明文本中的指令不参与授权判断。

## 本地运行

从仓库根目录执行（Python 3.10+，CI 使用 3.12）：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r gateway/requirements.txt
python -m gateway.setup_demo
python -m business.app.setup_demo --session-for V001
```

保存最后输出的 `session_token`。初始化脚本只生成合成场景的 D 私钥、公钥、C 公钥、
签名发布库和信任配置；不会覆盖已有目录。C 的演示发布私钥不保留。
运行数据在 `gateway/data/`，被 Git 忽略。

以下环境变量需在三个服务的终端中设置为相同值；三个服务使用不同端口。
服务密钥请自行生成至少 24 字符的随机字符串，不要写入 Git。

```powershell
$env:ROLE_A_FACTS_KEY = '<随机事实查询服务密钥>'
$env:ROLE_A_EXECUTOR_KEY = '<另一个随机执行服务密钥>'
$env:ROLE_D_SERVICE_KEY = '<另一个随机网关服务密钥>'
$env:ROLE_D_PRIVATE_KEY = 'gateway/data/demo/d-private.pem'
$env:ROLE_A_D_PUBLIC_KEY = 'gateway/data/demo/d-public.pem'
$env:ROLE_C_TRUST_CONFIG = 'gateway/data/demo/trust.json'
$env:ROLE_A_PROFILE = 'evidence'
```

分别启动：

```powershell
# 终端 1：A 的可信事实接口
python -m uvicorn business.app.main:create_business_app --factory --host 127.0.0.1 --port 8000
# 终端 2：A 在执行时复查 C 发布物的独立执行器
python -m uvicorn trusted_release.role_a:create_app --factory --host 127.0.0.1 --port 8001
# 终端 3：D 授权服务
python -m uvicorn gateway.main:create_app --factory --host 127.0.0.1 --port 8002
```

在另一个配置了相同服务密钥的终端发起完整授权与执行：

```powershell
$sessionToken = '<前面 A 输出的 session_token>'
$proposal = @{
  operation_id = [guid]::NewGuid().ToString('N')
  action = 'grant_access'
  args = @{ booking_id = 'BK-1042'; area = 'visitor_area'; valid_minutes = 15 }
} | ConvertTo-Json -Depth 8
$authorized = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8002/authorize' `
  -Headers @{ Authorization = "Bearer $env:ROLE_D_SERVICE_KEY"; 'X-Session-Token' = $sessionToken } `
  -ContentType 'application/json' -Body $proposal
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8001/internal/executor/access-grants' `
  -Headers @{ Authorization = "Bearer $env:ROLE_A_EXECUTOR_KEY"; 'X-Session-Token' = $sessionToken } `
  -ContentType 'application/json' -Body ($authorized | ConvertTo-Json -Depth 12)
```

执行需在令牌过期前完成。重发同一执行请求应收到 A 的 `AUTHORIZATION_REPLAY`；
若预约已有有效授权，新操作可能收到 `ACCESS_ALREADY_GRANTED`。
上述为本机合成数据联调，未调用真实门禁、Dify 或 Fabric。

## 配置与后续接入

| 环境变量 | 默认值 / 用途 |
| --- | --- |
| ROLE_D_FACTS_URL | `http://127.0.0.1:8000`，事实源 origin |
| ROLE_D_EXECUTOR_URL | `http://127.0.0.1:8001`，固定执行目标 origin |
| ROLE_D_PRIVATE_KEY | 必填，Ed25519 PEM 私钥 |
| ROLE_D_SERVICE_KEY | 必填，至少 24 字符 |
| ROLE_A_FACTS_KEY | 必填，访问 A 内部事实接口 |
| ROLE_C_TRUST_CONFIG | 必填，C 的公钥及数据库配置 |
| ROLE_D_AUDIT_DB | `gateway/data/decisions.sqlite3` |
| ROLE_D_TOKEN_TTL | `60`，范围 1–120 秒 |
| ROLE_A_ISSUER / ROLE_A_AUDIENCE / ROLE_A_KEY_ID | `role-d` / `role-a-executor` / `role-d-v1`，与 A 一致 |
| ROLE_C_POLICY_ID / ROLE_C_TOOLS_ID | `campus-policy` / `campus-tools` |

远端事实源和执行器要求 HTTPS，本机允许 HTTP。事实查询禁用重定向和环境代理，并设置 5 秒超时。
默认应用不装配 B 的真实审批来源，因此高风险请求会拒绝。
接入时向 `Gateway` 和 A 的执行器分别注入 `ApprovalVerifier(source=...)`；
来源必须实现 A 的 `ApprovalSource.fetch_verified`，独立验证组织签名、有效提交及当前撤销状态。
默认组织为 `security` 和 `information_center`，状态新鲜度上限 15 秒。
不接受请求体中的审批签名或“已审批”布尔值作为替代。

尚需 B 的 Fabric 适配、Dify 可信会话传播与编排、日志锚定，以及真实模型注入攻击评测。
当前结构化攻击测试验证执行边界，不代表已测量模型抵抗提示注入的能力。
