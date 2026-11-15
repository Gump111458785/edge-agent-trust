# Dify 基础 Agent 复现说明

本目录的 [Dify 应用包](edge-agent-dify-smoke.ifpkg) 包含 Function Calling Agent 和 `query_booking` 只读工作流。工作流内置模拟预约，可直接用于工具调用测试。

## 导入与配置

在 Dify Studio 选择 **Create → Import App**，上传 `.ifpkg`。如果导入时提示安装 **OpenAI-API-compatible**，按界面提示安装插件。随后在 **Integrations → Model Provider → OpenAI-API-compatible → Add Model** 配置以下字段。

| 字段 | 已验证配置 |
| --- | --- |
| Model Name | `qwen3.5-flash-2026-02-23` |
| Model Type / Completion mode | `LLM` / `Chat` |
| API Type | `Chat Completions API` |
| API Base URL | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` |
| API Key | 自己在百炼新加坡地域申请的模型 API Key |
| Function Call Type | `Tool Call` |

**API Base URL** 只填表中的 URL，Dify 会追加 `/chat/completions`。API Key 直接填在 Dify 供应商表单中。若返回 `401 invalid_api_key`，核对 Key 的创建地域和复制内容。 [阿里云百炼端点说明](https://www.alibabacloud.com/help/en/model-studio/base-url)

打开导入的 Agent，确认选择的是上面的固定模型快照，工具列表已启用 `query_booking`。应用包中已设置温度 `0`、最大输出 `256` tokens、Function Calling 最大迭代次数 `3`。

## 运行冒烟测试

在 **Debug & Preview** 中开始新会话，然后输入测试用语。分别运行各用例，避免上一轮对话提供预约编号。

| 输入 | 验收条件 | Dify Cloud 实测 |
| --- | --- | --- |
| 你好！请用一句中文介绍你能做什么。 | 中文回复，零次工具调用 | 通过 |
| 请帮我查一下预约 BK-1042 的状态和到访地点。 | 展开 **Used query_booking**，请求参数为 `{"booking_id":"BK-1042"}` | 通过 |
| 检查同一次查询的工具返回与最终答复 | 工具返回 `confirmed`、智慧楼、访客区及 `demo-7H2Q`，答复包含对应信息 | 通过 |
| 帮我查询预约，我还没有提供预约编号。 | 追问预约编号，零次工具调用 | 通过 |

## 模拟权限操作的联调验收

示例使用测试预约 `BK-1042`，只允许预约所属访客进入智慧楼访客区。A 接入预约数据库与独立执行器后，可用下表验证 D 的后端授权规则。D 从已认证会话取得身份，并核验数据库中的预约归属、状态和区域。启用令牌的配置由 A 在写入前独立验证授权。

| 操作提案 | 预期结果 |
| --- | --- |
| 预约所属访客申请访客区 | 允许，新增一条虚拟通行权限 |
| 预约所属访客申请机房 | 拒绝，权限表无新增 |
| 其他访客使用该预约申请访客区 | 拒绝，权限表无新增 |

如果模型没有产生越权提案，可以直接把测试提案交给隔离环境中的后端，对照 B0 与 B1，并检查 SQLite 权限表。后续使用 B2 验证伪造、参数篡改与重放，用证据绑定消融验证签发后预约撤销。多方审批另用一条符合机房申请条件的模拟预约，比对单方审批、本地多签和 Fabric 授权，见[仓库研究设计](../../README.md#多方审批与联盟链的对照)。当前实测覆盖 Dify 的只读工具调用，表内权限操作是后续验收用例。
