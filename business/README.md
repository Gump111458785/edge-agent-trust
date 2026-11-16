# A · 有状态业务环境与独立执行器

业务读取和执行器可作为两个 FastAPI 服务运行。读服务以 SQLite 只读模式打开数据库。执行器验证独立服务凭据、用户会话和 Ed25519 授权，在原子事务中消费令牌、写入虚拟权限并记录执行结果。权限数据、预约与身份均为模拟数据。

本机测试已验证合法授权写入、直连拒绝、参数篡改与并发重放。Dify Cloud 的工具 Test 和 Agent 草稿已通过 `a_live_booking` 查询 `BK-1042`。[Dify 联调记录与复现步骤](../agent/dify/README.md#验收真实预约查询)

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
- 状态评分借鉴 τ-bench 的初始环境重置和最终状态比较。每个用例以同一版种子数据创建独立数据库，按预期核对权限、令牌消费与执行审计，同时检查其他访客、预约与会话的状态。当前复跑范围为本项目的校园任务。[原论文](https://arxiv.org/abs/2406.12045) · [作者评分器](https://github.com/sierra-research/tau-bench/blob/main/tau_bench/envs/base.py) · [本项目评分器](../evaluation/state_evaluator.py)

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

### 临时公网 HTTPS 验收

在可运行 Cloudflare Tunnel 的测试主机上安装 Python 依赖和 `cloudflared`。macOS 可用 `brew install cloudflared`。从仓库根目录启动。

```bash
python -m business.app.quick_tunnel
```

启动器创建单独的合成 SQLite 和访客 `V001` 的一小时会话。它通过公网 HTTPS 验证正常查询、缺少会话、跨访客查询和内部路由隔离后，打印本次 HTTPS 地址、工具定义 URL 和临时 Bearer 会话文件路径。Dify 自定义工具导入打印的 `/tool-openapi.json`，把 `booking-token` 文件中的会话填入 Bearer 凭据，在调试预览中查询 `BK-1042`。

保持启动终端运行。`Ctrl+C` 关闭本次入口并清理临时数据库和会话。重启会分配新地址和会话。若主机已有 Cloudflare 默认隧道配置或无法连接 Cloudflare，使用一台能运行 Quick Tunnel 的测试主机。[Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)

### 自有 HTTPS 入口

将 `ROLE_A_TOOL_BASE_URL` 设置为可达的 HTTPS 入口。`GET /tool-openapi.json` 发布 `query_booking` 的定义，反向代理只路由 `/booking` 和所需的 Schema。Dify 工具凭据填合成访客临时会话。真实访客身份传播由 D 的可信会话链路负责，执行器保持内部监听。仓库的 Dify 应用包用于复现 Mock 基线，Cloud 草稿可按[真实预约联调步骤](../agent/dify/README.md#接入-a-的真实预约服务)配置 `a_live_booking`。

可将反向代理的上游设为 `uvicorn business.app.public_booking:create_public_booking_app --factory --host 127.0.0.1 --port 8000`。该进程只注册预约查询和工具定义。内部事实服务和执行器使用各自的内部端口与配置。

Docker 可在仓库根目录用 `docker build -f business/Dockerfile -t edge-agent-trust-a .` 构建。两个服务用独立账户和进程启动。把数据库目录对读服务设为只读，对执行器设为可写，只向相应进程分发服务凭据和验签材料。SQLite 的写隔离依赖文件系统权限及部署身份。`mode=ro` 同时约束读取代码路径。默认容器命令启动读服务，执行器容器重载为 `uvicorn business.app.main:create_executor_app --factory --host 0.0.0.0 --port 8001` 后应留在内部网络。
