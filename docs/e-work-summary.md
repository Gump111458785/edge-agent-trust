# E · Agent 编排与汇报

Dify Cloud 与百炼的预约查询已用 BK-1042 验收。现有应用包包含只读 Mock，真实查询工具的设置见 [Dify 指南](../agent/dify/README.md)。写流程新增独立的 [Agent 网关](../agent/edge.py)。

| 环节 | 交付与证据 |
| --- | --- |
| 模型工具 | Dify 导入网关的 /tool-openapi.json 后只可提交待确认申请。返回操作编号和确认链接，不返回会话或执行凭据 |
| 访客确认 | 浏览器显示预约、区域、时长。访客用本次会话确认之后，网关才调用 D 和 A |
| 执行结果 | A 事务内核对同一会话及操作摘要。重复确认可读取之前的成功结果，SQLite 仍只有一次写入 |
| 本地验收 | [HTTP 集成测试](../agent/test_edge.py) 串联真实应用代码，检查提案、确认、执行和 SQLite 终态 |
| 云端验收 | 新写流程与可信检索的 Dify Cloud 调用仍需部署环境验证。已有云端只读联调不受影响 |

写路径启动及演示步骤见 [统一部署](integration.md)。汇报数据见 [边界实验结果](../evaluation/results/boundary-v2-summary.json)。
