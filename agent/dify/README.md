# Dify 与百炼 Qwen 使用指南

本目录的 [Dify 应用包](edge-agent-dify-smoke.ifpkg) 包含 Function Calling Agent 和 `query_booking` Mock 工作流。先用应用包验证模型的对话与工具调用，再把预约工具切换到 A 的 FastAPI 服务，用 SQLite 中的合成预约完成联调。

## 配置百炼 LLM

1. 在阿里云百炼的新加坡地域创建模型 API Key。[百炼 API Key 指南](https://www.alibabacloud.com/help/en/model-studio/get-api-key)
2. 在 Dify Studio 选择 **Create → Import App**，导入 `.ifpkg`。如果界面提示缺少 **OpenAI-API-compatible**，安装该模型供应商插件。[Dify Marketplace](https://marketplace.dify.ai/plugin/langgenius/openai_api_compatible)
3. 在 **Integrations → Model Provider → OpenAI-API-compatible → Add Model** 填写下表，然后在 Agent 草稿中选择这个模型。

| 字段 | 已验证配置 |
| --- | --- |
| Model Name | `qwen3.5-flash-2026-02-23` |
| Model Type / Completion mode | `LLM` / `Chat` |
| API Type | `Chat Completions API` |
| API Base URL | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` |
| API Key | 自己在百炼新加坡地域申请的模型 API Key |
| Function Call Type | `Tool Call` |

**API Base URL** 填到 `/compatible-mode/v1`，Dify 会追加 `/chat/completions`。模型 API Key 填在供应商设置中。`401 invalid_api_key` 时，核对 Key 的地域、计费方式和端点。[阿里云百炼端点说明](https://www.alibabacloud.com/help/en/model-studio/base-url)

应用包固定了 `qwen3.5-flash-2026-02-23`、温度 `0`、最大输出 `256` tokens 和 Function Calling 最大迭代次数 `3`。做对照实验时沿用相同的模型版本与参数。

### 单独检查 LLM 连接

已经通过环境配置设置 `DASHSCOPE_API_KEY` 时，可以直接试一次 Chat Completions。返回 `choices[0].message.content` 表示模型调用成功。工具调用由下面的 Dify 调试用例验证。[百炼 OpenAI 兼容接口](https://www.alibabacloud.com/help/en/model-studio/qwen-api-via-openai-chat-completions)

```bash
curl --fail-with-body --silent --show-error \
  'https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions' \
  -H "Authorization: Bearer ${DASHSCOPE_API_KEY:?请先设置新加坡百炼 API Key}" \
  -H 'Content-Type: application/json' --data-binary @- <<'JSON'
{
  "model": "qwen3.5-flash-2026-02-23",
  "messages": [{"role": "user", "content": "请用一句中文介绍你能做什么。"}],
  "temperature": 0,
  "max_tokens": 256,
  "enable_thinking": false
}
JSON
```

## 运行 Mock 基线

确认工具列表中启用了 `Edge Agent · Booking Mock` 的 `query_booking`。在 **Debug & Preview** 中用新会话分别运行各用例，避免上下文带入上一轮的预约编号。

| 输入 | 验收条件 | Dify Cloud 实测 |
| --- | --- | --- |
| 你好！请用一句中文介绍你能做什么。 | 中文回复，零次工具调用 | 通过 |
| 请帮我查一下预约 BK-1042 的状态和到访地点。 | 展开 **Used query_booking**，请求参数为 `{"booking_id":"BK-1042"}` | 通过 |
| 检查同一次查询的工具返回与最终答复 | 工具返回 `confirmed`、智慧楼、访客区及 `demo-7H2Q`，答复包含对应信息 | 通过 |
| 帮我查询预约，我还没有提供预约编号。 | 追问预约编号，零次工具调用 | 通过 |

## 接入 A 的真实预约服务

### 启动只读 HTTPS 服务

在可连接 Cloudflare Tunnel 的测试主机上安装 Python 3.11 或以上版本和 `cloudflared`。macOS 使用 Homebrew 时可运行 `brew install cloudflared`。[Cloudflare 下载说明](https://developers.cloudflare.com/tunnel/downloads/)

在仓库根目录运行下面的命令。已按 [A 的运行说明](../../business/README.md) 准备过虚拟环境时，可激活现有环境并直接启动。

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r business/requirements.txt
python -m business.app.quick_tunnel
```

公网自检通过后，启动器会打印 HTTPS 地址、Dify 工具定义 URL 和 Mac 或测试主机上的 `booking-token` 文件路径。保持启动终端运行。临时会话有效期一小时，重启会生成新地址和新会话。[A 的公网入口与隔离说明](../../business/README.md#临时公网-https-验收)

### 创建并配置 Dify 工具

1. 打开 **Tools → Swagger API as Tool**，选择 **Create Custom Tool**，名称填 `a_live_booking`。已有同名工具时，进入该工具的 **Edit**。
2. 选择 **Import from URL**，填启动器打印的 `/tool-openapi.json` URL。核对 Schema 的 `servers[0].url` 指向当前 HTTPS 地址，操作列表只有 `query_booking`（`GET /booking`）。
3. 打开 **Authentication Method**。若当前显示 **None**，点这一项进入设置。选择 **API Key（Header）**，按下表填入并保存认证设置和工具。[Dify 自定义工具操作示例](https://help.aliyun.com/en/document_detail/2871439.html)

| 字段 | 值 |
| --- | --- |
| Authentication Header Prefix | `Bearer` |
| Key | `Authorization` |
| Value | 本次 `booking-token` 文件中的令牌原文 |

Dify 会自动为 **Value** 加上 `Bearer` 前缀。这份临时会话用于预约读取。百炼模型 API Key 用于模型供应商配置。两项凭据分别保存在对应的 Dify 设置中。[Dify 请求认证实现](https://github.com/langgenius/dify/blob/main/api/core/tools/custom_tool/tool.py)

在 Mac 上可以把启动器打印的完整 `booking-token` 路径填到下面的变量，直接把令牌复制到剪贴板。回到 Dify 的 **Value** 粘贴。

```bash
booking_token_file='/absolute/path/to/booking-token'
test -s "$booking_token_file" && tr -d '\r\n' < "$booking_token_file" | pbcopy
```

### 验收真实预约查询

1. 在 `a_live_booking` 的 **Test** 中选择 `query_booking`，设 `booking_id=BK-1042`，核对返回的五个字段。
2. 在 Agent 草稿中启用 `a_live_booking` 的 `query_booking`，停用同名 Mock。在 **Debug & Preview** 的新会话输入「请查一下 BK-1042 的状态和到访地点」。
3. 展开 `query_booking` 的调用记录，检查请求参数和返回值。调用记录只显示操作名时，再查看草稿的工具列表，确认唯一启用的同名操作来自 `a_live_booking`。本次验收保留在草稿中。

两项测试已在 Dify Cloud 通过，返回了相同的 JSON。

```json
{
  "booking_id": "BK-1042",
  "status": "confirmed",
  "building": "智慧楼",
  "zone": "访客区",
  "fixture": "demo-7H2Q"
}
```

### 常见故障

| 现象 | 排查 |
| --- | --- |
| **Import from URL** 显示 `invalid schema` | 先打开当前 `/tool-openapi.json`，检查能否读到 JSON、隧道终端是否仍在运行，以及 `servers[0].url` 是否对应当前地址。重启隧道后，在现有工具中导入新的 URL。 |
| 工具 Test 返回 `401` | 检查临时会话是否过期、请求头名是否为 `Authorization`，以及 **Value** 是否只填令牌原文。 |
| 工具 Test 返回 `404` | 核对预约编号和访客范围。用测试访客 `V001` 的会话查询 `BK-1042`。 |
| Agent 给出答案但调用记录为空 | 确认已经选择支持 **Tool Call** 的模型并启用 `a_live_booking`，再用新会话重试。 |

## 后续权限写入联调

示例使用测试预约 `BK-1042`，只允许预约所属访客进入智慧楼访客区。下表用于 A 与 D 的后端授权联调。D 从已认证会话取得身份，并核验数据库中的预约归属、状态和区域。启用令牌的配置由 A 在写入前独立验证授权。

| 操作提案 | 预期结果 |
| --- | --- |
| 预约所属访客申请访客区 | 允许，新增一条虚拟通行权限 |
| 预约所属访客申请机房 | 拒绝，权限表无新增 |
| 其他访客使用该预约申请访客区 | 拒绝，权限表无新增 |

如果模型没有产生越权提案，可以直接把测试提案交给隔离环境中的后端，对照 B0 与 B1，并检查 SQLite 权限表。后续使用 B2 验证伪造、参数篡改与重放，用证据绑定消融验证签发后预约撤销。多方审批另用一条符合机房申请条件的模拟预约，比对单方审批、本地多签和 Fabric 授权，见[仓库研究设计](../../README.md#多方审批与联盟链的对照)。当前实测覆盖 Dify 的只读工具调用，表内权限操作是后续验收用例。
