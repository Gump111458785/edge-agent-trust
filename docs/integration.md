# 统一部署与验收

本演示仅操作合成预约和虚拟权限。部署入口分为事实查询、执行器、授权网关与对外的 Agent 工具。前三个进程监听私网或回环地址。访客浏览器访问 HTTPS 的 Agent 工具入口。各进程凭据由部署方独立管理。

## 启动

在 Python 3.11 以上环境安装 `gateway/requirements-dev.txt`。按照 [D 的部署说明](d-interface-contract.md#本地运行) 初始化 A 的 SQLite 和 C、D 的演示密钥。已有 SQLite 用相同的 `business.app.setup_demo --db` 命令升到 schema v2。

执行器必须设置 `ROLE_A_REQUIRE_CONFIRMATION=1`，使用 `trusted_release.role_a:create_app`。低风险演示使用 V001 的会话，高风险演示使用 V003 和 BK-1044。默认演示启动使用以下四个入口：

| 端口 | Uvicorn factory |
| --- | --- |
| 8000 | `business.app.main:create_business_app` |
| 8001 | `trusted_release.role_a:create_app` |
| 8002 | `gateway.main:create_app` |
| 8003 | `agent.edge:create_app` |

前三个入口使用 D 文档中的环境变量。E 额外需要以下配置：

| 配置 | 用途 |
| --- | --- |
| `ROLE_E_PUBLIC_URL` | E 对外的 HTTPS origin。回环本地实验可填 http://127.0.0.1:8003 |
| `ROLE_E_TOOL_KEY` | 独立的 Dify 工具 Bearer |
| `ROLE_E_PROPOSAL_KEY` | E 保管的提案签名密钥 |
| `ROLE_E_DEMO_SESSION` | 当前演示的单一访客会话。保存在服务端，不加入 Agent 上下文 |
| `ROLE_E_GATEWAY_URL` | 默认 http://127.0.0.1:8002 |

使用 `uvicorn <factory> --factory --host 127.0.0.1 --port <port> --no-access-log`。反向代理也应禁用确认链接的访问日志。仅将 E 与另行部署的 C 检索接口公开给演示环境。服务凭据、访客会话和签名密钥均使用不同的值。演示跨会话时应使用分别配置的工具实例。这是单访客演示绑定，生产应用需通过已认证的入口动态绑定会话。

## Dify 和 SQLite 验收

1. 在测试草稿中导入 E 的 `/tool-openapi.json`。设 Dify 工具的认证为独立 E Bearer，并启用 `prepare_access_request`。设置模型只在用户明确提出申请时调用此工具。把返回的确认链接呈现给用户。
2. 保留预约查询工具。C 的部署按 [外部知识库说明](../trusted_release/README.md) 配置，检索 API 使用单独 Bearer。导入后查看一次规章检索记录和返回出处。
3. 对 V001 开通 15 分钟访客区。提案提交后核对权限表无新增。新开页面核对区域与时长，使用本次访客会话确认，然后核对 `access_grants` 和 `used_tokens` 各新增一条，`execution_records` 与 D 决策日志共享操作编号。
4. 重新提交同一确认，应返回原执行结果且权限不重复写入。仅查询时保持权限库不变。已有 [本地 HTTP 验收测试](../agent/test_edge.py) 覆盖这条确认链路。

## Fabric 审批、发布与审计

D 设 `ROLE_D_FABRIC_CONFIG`，A 设 `ROLE_B_FABRIC_CONFIG`。为 A、D 配置独立的 Fabric 读取身份。沿用 [B 的测试网络和审批格式](b-fabric-approvals.md)，用 E 生成的操作摘要办理保卫处与信息中心审批。双部门批准后确认应成功。另开一条机房申请，在用户确认前撤销审批，D 应拒签。用相同测试网在 A 侧复验已签发授权的撤销状态。

C 的检索入口、D 网关和组合执行器共用信任配置中的 `checkpoint` 字段。正式部署设置 `ROLE_C_REQUIRE_CHECKPOINT=1`，缺少配置时启动失败。发布和撤销通过 `trusted_release.manage` 的 `--anchor-config` 提交。完整配置、命令和部分提交后的重试方式见 [C 的检查点部署说明](c-checkpoint-integration.md)。发布引用不一致时消费端拒绝使用，检查点读取与业务提交之间仍有撤销时间窗口。

用专用审计身份运行下列命令。定时轮询重启后以链上已提交尾序号恢复。每次校验已锚定批次并补交新事件。使用与数据库实例对应的唯一流名。对照验收时可用只读身份和 `--verify-only`。

```bash
python -m role_b.runtime --fabric auditor.json audit executor campus.sqlite3 demo-a --interval 30
python -m role_b.runtime --fabric auditor.json audit gateway decisions.sqlite3 demo-d --interval 30
```

已锚定批次由链上顺序、范围和根共同核验。新日志在下一次提交前仍属于未锚定尾部。审批在 Fabric 读结果之后、SQLite 提交之前发生撤销时，跨系统事务窗口仍存在。当前以有效读交易的排序位置判定状态，以 A 的 15 秒新鲜度检查限制老状态，不能将链上撤销和 SQLite 写入宣称为同一事务。
