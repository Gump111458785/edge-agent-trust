# A · 有状态业务环境与独立执行器

业务读取和执行器可作为两个 FastAPI 服务运行。读服务以 SQLite 只读模式打开数据库。执行器验证独立服务凭据、用户会话和 Ed25519 授权，在原子事务中消费令牌、写入虚拟权限并记录执行结果。权限数据、预约与身份均为模拟数据。

## 运行测试与评测

在仓库根目录使用 Python 3.11 或以上版本。

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r business/requirements-dev.txt
python -m pytest -q
python -m evaluation.run_benchmark
```

结果默认写入 `role-a-results/results.json`。每个用例使用新建的临时 SQLite 和固定逻辑时钟。结果包含用例及种子版本、操作提案、逐次决策、耗时、前后快照及越权写入标记。`verification_passed` 表示结果符合该实验配置的预期，B0 的故意越权写入也可能符合预期。`unauthorized_write` 单独记录越权状态变化。`model` 和 `agent_proposal` 为 `null` 表示本轮由结构化客户端重放提案。

```bash
python -m evaluation.run_benchmark --config B2 --config Ours --task T08 --task T09
```

- B0/B1 使用仅存在于离线运行器的实验路径和独立临时数据库。B1 的业务判断由测试替身提供。
- B2、B2+Evidence、B2+Chain 与 Ours 通过 A 的 HTTP 执行接口验签并检查状态。签发密钥由测试运行器临时生成，审批替身返回预核验的合成状态。两种审批配置用相同替身验证执行契约，真实 Fabric 的增量和开销待测。
- B2 与证据绑定版本都会拒绝已撤销的预约。T13 改变预约版本并保留业务资格，用于观察证据绑定对旧授权的独立影响。
- 状态评分借鉴 τ-bench 的初始环境重置及最终状态比较。这里用校园模拟任务验证 SQLite、令牌消费和意外的旁路状态变化。作者的 Retail/Airline 模型成绩仍未复现。[原论文](https://arxiv.org/abs/2406.12045) · [作者评分器](https://github.com/sierra-research/tau-bench/blob/main/tau_bench/envs/base.py)

## 本机运行预约工具

```bash
export ROLE_A_DB="$(mktemp -d)/campus.sqlite3"
export ROLE_A_FACTS_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
ROLE_A_DEMO_SESSION_JSON="$(python -m business.app.setup_demo --session-for V001)"
export ROLE_A_SESSION_TOKEN="$(printf '%s' "$ROLE_A_DEMO_SESSION_JSON" | python -c 'import json,sys; print(json.load(sys.stdin)["session_token"])')"
unset ROLE_A_DEMO_SESSION_JSON
uvicorn business.app.main:create_business_app --factory --host 127.0.0.1 --port 8000 &
ROLE_A_READ_PID=$!
```

服务启动后检查真实预约与面向 Dify 的 OpenAPI。

```bash
curl --fail -H "Authorization: Bearer $ROLE_A_SESSION_TOKEN" \
  'http://127.0.0.1:8000/booking?booking_id=BK-1042'
curl --fail http://127.0.0.1:8000/tool-openapi.json
kill "$ROLE_A_READ_PID"
```

预约查询返回已确认、智慧楼、访客区以及 `demo-7H2Q`。种子中另有过期 `BK-1043`、具备机房申请资格的 `BK-1044` 和已撤销的 `BK-1045`。读工具用测试会话限制访问范围，D 的事实查询用独立服务凭据。

## 执行器联调

在同一参数环境启动第二个进程。`ROLE_A_D_PUBLIC_KEY` 指向 D 的 PEM 格式 Ed25519 公钥。`ROLE_A_EXECUTOR_KEY` 采用独立的随机服务凭据。

```bash
export ROLE_A_D_PUBLIC_KEY=/absolute/path/to/issuer-public.pem
export ROLE_A_EXECUTOR_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uvicorn business.app.main:create_executor_app --factory --host 127.0.0.1 --port 8001
```

启动配置仅加载公钥。默认要求证据绑定，使用 `ROLE_A_PROFILE=token` 可为 B2 单独运行一个实例。默认审批来源为空，高风险请求会拒绝。具备真实审批适配器时，由组合入口将其注入 `Executor` 的 `ApprovalVerifier`。本地测试签发与审批替身的入口是 `evaluation/fixtures.py`，可通过上面的评测命令运行。[版本化接口契约](../docs/a-interface-contract.md)

## 与 E 联调

`GET /tool-openapi.json` 只发布 `query_booking` 的定义。E 有可达 HTTPS 入口后，将 `ROLE_A_TOOL_BASE_URL` 设置为该入口。反向代理只路由只读 `/booking` 及按需提供的 Schema。Dify 工具凭据填合成访客临时会话。每个真实访客的身份传播由 D 的可信会话链路完成。执行器保持内部监听。当前仓库里的 Dify 应用仍用原预约 Mock，云端换接取决于可达入口和 E 的配置。

Docker 可在仓库根目录用 `docker build -f business/Dockerfile -t edge-agent-trust-a .` 构建。两个服务用独立账户和进程启动。把数据库目录对读服务设为只读，对执行器设为可写，只向相应进程分发服务凭据和验签材料。SQLite 的写隔离依赖文件系统权限及部署身份。`mode=ro` 同时约束读取代码路径。默认容器命令启动读服务，执行器容器重载为 `uvicorn business.app.main:create_executor_app --factory --host 0.0.0.0 --port 8001` 后应留在内部网络。
