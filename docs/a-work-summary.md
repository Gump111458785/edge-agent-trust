# A 模块工作说明

> 组合执行器已支持按配置强制检查访客确认，确认绑定会话与操作摘要。校验位于原有 SQLite 事务中。720 次边界实验与确认路径的测试见[集成验收](integration.md)。

**负责人** `Gump111458785`

## 我负责的工作

我实现了校园虚拟通行的预约服务、权限数据库和独立执行器，并负责核对业务状态是否按授权发生变化。场景使用合成访客、预约和虚拟权限。A 的业务代码已合入 `main`，Dify Cloud 的只读预约查询已验收。[A 模块实现 PR](https://github.com/Gump111458785/edge-agent-trust/pull/1)

## 实现内容

| 交付内容 | 实现方式 | 代码入口 |
| --- | --- | --- |
| 预约与权限数据 | SQLite 保存访客、预约、会话、通行权限、令牌消费和执行记录。预约的归属、区域、状态或有效期变更后自动更新版本。 | [数据库迁移](../business/migrations/001_initial.sql) |
| 业务读取 API | 检查临时会话后按访客范围查询预约与权限状态。为网关提供独立凭据保护的内部预约和会话查询。 | [FastAPI 服务](../business/app/main.py) |
| 独立执行器 | 验证服务凭据、访客会话和 Ed25519 执行令牌。核对令牌绑定的操作、参数摘要与适用的证据版本，并根据区域检查所需审批。 | [验签与审批](../business/app/authorization.py) · [执行器](../business/app/executor.py) |
| Dify HTTPS 入口 | 公网进程只开放 `GET /booking` 和 `GET /tool-openapi.json`。启动器用独立的测试 SQLite 生成一小时会话，并自检正常查询、缺少会话、跨访客查询和内部路由隔离。 | [公网应用](../business/app/public_booking.py) · [隧道启动器](../business/app/quick_tunnel.py) |

### 执行器如何决定能否写库

1. 检查内部服务凭据和 Ed25519 签名，核对签发方、受众、有效期、操作 ID 和规范化参数摘要。
2. 根据操作和区域判断审批要求。机房授权需要与操作摘要匹配的有效审批，审批来源不可用时拒绝写入。
3. 在 SQLite 的 `BEGIN IMMEDIATE` 事务内复核时效，检查访客会话、预约归属、区域和有效期，并根据令牌 ID 与操作 ID 拦截重放。证据绑定配置还会检查会话标识、预约版本、策略版本和工具清单版本。令牌消费、虚拟权限变更和成功审计在同一事务中提交，写入故障时共同回滚。拒绝审计单独记录。[A 与其他角色的接口契约](a-interface-contract.md)

## 评测方法

评测借鉴 τ-bench 的数据库终态比较。每个用例从相同版本的种子数据建立独立 SQLite，记录执行前后的快照，并按预期结果检查权限、令牌消费、执行记录以及其他访客数据。判定时同时核对返回结果与数据库状态。[τ-bench 论文](https://arxiv.org/abs/2406.12045) · [状态评分实现](../evaluation/state_evaluator.py)

本地评测包含 16 个校园任务和 51 个任务与配置组合。B0、B1 走离线实验路径，签名令牌组走 A 执行接口。涉及审批的当前用例使用合成审批状态。运行结果分别记录预期是否符合和是否产生越权写入。B0 有 3 个用例实际发生越权写入，符合该对照组的实验预期。[校园用例](../evaluation/tasks/campus-v1.json) · [评测运行器](../evaluation/run_benchmark.py)

## 已完成的验收

| 验收 | 实际结果 |
| --- | --- |
| A 模块自动测试 | **72 项通过**，覆盖预约读取、服务权限、伪造与篡改拒绝、证据绑定、防重放和状态评分。 |
| 状态评测 | **51/51 个组合符合预期**。并发重放用例中，同一份合法授权提交 20 次，只有 1 次成功写入。故障注入用例确认权限写入失败时令牌消费一并回滚。 |
| Dify Cloud 工具 Test | `a_live_booking` 的 `query_booking` 查询 `BK-1042`，返回 `confirmed`、智慧楼、访客区和测试标识 `demo-7H2Q`。 |
| Dify Agent 草稿调试 | 调用记录中的 `booking_id=BK-1042`，五个返回字段与工具 Test 一致。草稿工具列表确认同名操作来自 `a_live_booking`。 |

测试期的真实预约查询读取 SQLite 中的合成业务数据。云端记录覆盖工具 Test 和 Agent 草稿中的只读调用。A 的授权写入由本地执行器测试和状态评测覆盖。[A 的运行说明](../business/README.md) · [Dify 云端验收记录](../agent/dify/README.md#验收真实预约查询)

## 如何复跑

在仓库根目录使用 Python 3.11 或以上版本运行以下命令。

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r business/requirements-dev.txt
python -m pytest -q business/tests
python -m evaluation.run_benchmark
```

评测产物默认写入 `role-a-results/results.json`。在具备 `cloudflared` 和外网连接的测试机上，运行 `python -m business.app.quick_tunnel` 可以生成新的工具定义 URL 和 `booking-token` 文件。Dify 的模型与工具配置见[Dify 与百炼使用指南](../agent/dify/README.md)。

## 联调交接

| 对接角色 | 接入点与验收范围 |
| --- | --- |
| B · 联盟链 | A 已提供 `ApprovalSource.fetch_verified` 适配接口。接入 Fabric 后，用机房授权用例核对双部门审批、撤销及过期状态，最后查看 SQLite 是否符合预期。 |
| C · 可信发布 | C 已提供可选的组合执行器入口，先核验可信发布，再交给 A 检查令牌与业务状态。本地组合测试覆盖配置撤销和时效检查。[组合入口说明](../trusted_release/README.md#本地联调) · [交接测试](../trusted_release/tests/test_handoff.py) |
| D · 授权网关 | A 已提供内部事实查询、验签和写入接口。真实网关接入后，使用 D 签发的令牌复跑合法写入、参数篡改、跨会话和并发重放用例。 |
| E · Agent 编排 | E 已与 A 验收只读预约。继续联调时，在 Agent 草稿中核对工具提供方和调用记录，并与 A 的执行审计和数据库快照对应。 |
