# 运维手册

[English](../operations.md) · **简体中文**

运行方式、演示流程、真实模型模式、故障处置手册与数据留存。按已实现的代码编写。

## 1. 运行

需要 Python 3.12+（本机在 3.13 上验证）。`LLM_MODE=mock` 是默认值，全程零网络调用。

```text
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
LLM_MODE=mock DEMO_MODE=1 PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

浏览器打开 http://127.0.0.1:8000。Windows PowerShell 下先设置变量：
`$env:LLM_MODE = "mock"; $env:DEMO_MODE = "1"; $env:PYTHONPATH = "src"`。

或者一条命令搞定——自动选择空闲端口、打开浏览器，并且在端口被占用或数据目录不可写时给出可操作的提示而不是堆栈跟踪：

```text
LLM_MODE=mock DEMO_MODE=1 python3 run.py
```

uvicorn 命令里有两个细节是刻意的。**用 `python -m uvicorn` 而不是 `uvicorn` 控制台脚本**：那个包装器在安装时硬编码了解释器的绝对路径，因此项目目录一被移动或重命名就会失败，报出一个指向读者从未见过的路径的 `bad interpreter` 错误。**`DEMO_MODE=1` 跳过登录**，因为身份本应来自会话，而走完四个工作区就得登录四次。

推荐使用虚拟环境，因为 Homebrew 或系统 Python 通常受外部管理（PEP 668），会拒绝直接 `pip install`。`PYTHONPATH=src` 无论可编辑安装是否生效都能工作。

## 2. 按真实部署方式运行

去掉 `DEMO_MODE`，就必须使用真实会话：

```text
LLM_MODE=mock PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

首次启动会生成初始 `admin` 密码并**仅在控制台打印一次**。它从不写入日志或磁盘，并且必须先修改才能做其他任何事。修改密码会终止该账号的所有会话（包括当前这个），因为轮换密码通常正是因为发生了泄露。

如果该账号从未登录过，后续启动会重新签发并再次打印该密码。**已经登录过**的账号则保留其凭据：从未使用的账号没有需要保护的历史，而静默地给一个正在使用的身份换钥匙，那是入侵手段而不是恢复手段。

已使用过的账号丢了密码怎么办？把 `data/users.json` 移走再重启，系统会重新配置一个账号。该文件持有 scrypt 密码哈希与活跃会话令牌，因此被 gitignore——提交一份凭据库，等于把它分享给每一个克隆仓库的人。

**范围直说。** 这是一个最小化的本地会话存储，不是企业级 SSO：没有身份提供方、没有第二因子、没有用户管理。它的存在是为了让信任边界落在正确的位置，并留出一个可由 OIDC 集成替换的接缝。

## 3. 六场景演示

场景按钮位于折叠的 **示例与教学 / Examples and training** 抽屉中，在工作流**下方**——编辑器上方摆六个示例按钮会让日常工具看起来像个演示品，而代表的真实工作顺序是：来源 → 上下文 → 叙述 → 提交。当 `DEMO_MODE=0` 时该抽屉完全隐藏。

| # | 场景 | 内容 | 预期结果 |
| --- | --- | --- | --- |
| 1 | `normal` | 符合说明书的高血压用药指导 | `allow`（S3） |
| 2 | `ae` | 潜在不良事件（皮疹） | `human_review`（S1）→ PV + 医学 |
| 3 | `pii` | 个人标识符（身份证号） | `blocked`（S1）→ 安全；数值已打码 |
| 4 | `off_label` | 超适应症剂量 / 适应症（糖尿病，100mg） | `human_review`（S1）→ 合规 + 医学 |
| 5 | `redline` | 严重不良事件（昏迷，危及生命） | `human_review`（S0）→ PV + 医学 |
| 6 | `injection` | 提示词注入（忽略所有规则…） | `blocked`（S0）→ 安全 |

每个用例都可以打开 **trace** 查看审计时间线（`case_received → … → decision → workflow.complete`）与模型路由版本。**代码控制、永不失效开放**的行为正是在这里可见。

场景文本在任何界面语言下都保持中文，并且有测试强制这一点。风险检测匹配中文关键词，证据语料仅有 `zh-CN`/`zh-HK`，因此翻译请求体会静默地让 AE、红线和注入检测失效，并返回空证据集。

## 4. 四个工作区

| 工作区 | 面向 | 展示内容 |
| --- | --- | --- |
| 代表 | 业务代表 | 提交、预检提示、脱敏结果、自己的 trace |
| 审核 | 医学 / PV / 合规 / 法务 | 证据、finding、决定表单、电子签名 |
| 模型策略 | 架构师（起草/测试）、管理员（发布/回滚） | Profile、路由、版本、历史 |
| 质量与审计 | QA、审计、法规 | ALCOA+ 态势、接口治理登记册、审计轨迹 |

基于角色的可见性由 `GET /api/permissions` 对照服务端权限矩阵解析得出。**隐藏是易用性辅助，不是控制措施**——每条受保护路由都独立复核权限，并且有测试验证：`architect` 强行调用发布接口依然收到 `403`。

### 演示角色

当 `DEMO_MODE=1` 时，角色选择器会设置 `x-demo-role`，并标注为 *仅演示模式 / demo mode only*。关闭该标志后选择器隐藏，且该请求头会被 `401` 拒绝。这个门控封堵了一个真实漏洞：该请求头此前允许调用方自行声明角色，因此改一个 header 就足以发布模型策略或读取审计轨迹。`GET /health/ready` 会报告 `demo_mode`，因此当前姿态永远不需要靠猜。

| 角色 | 可以做什么 | 可达工作区 |
| --- | --- | --- |
| `field_rep` | 提交；读取自己的结果与 trace | 代表 |
| `reviewer` | 读取证据、记录签署决定 | + 审核 |
| `auditor` | 审计导出、验证态势 | + 质量与审计 |
| `architect` | 查看/起草/测试模型策略（**不可**发布） | + 模型策略 |

更完整的药企角色矩阵保留在服务端——`msl`、`pv_reviewer`、`qppv`、`medical_reviewer`、`mlr_reviewer`、`compliance_admin`、`qa`、`regulatory_affairs`——并且有测试锁定"收窄选择器并未削减该模型"。值得注意的职责分离：只有 `qppv` 可以放行 ICSR 提交（PV 审核人可以评估信号但不能提交）；`qa` 与 `auditor` 可读审计轨迹，但既没有 `review_case` 也没有 `config_publish`，因为**质量监督不等于运营权力**。`GET /api/permissions` 还会返回 `sop_refs`，把每个动作映射到管辖它的 SOP，因此权限读起来是一项受控程序，而不是一个裸的能力名。

要跑通完整的发布/回滚闭环，请以 `x-demo-role: compliance_admin` 调用 API。以 `architect` 身份点击发布会返回 `403`——这正是要点。

## 5. 模型策略：起草、测试、发布、回滚

1. **查看** —— 已发布版本、脱敏后的 Profile（凭据引用显示为 `****`）、路由、历史、注册表审计事件。
2. **起草** —— 编辑 Profile 的超时、token 预算、区域、启用状态，或路由的主/回退 Profile、能力、数据分级与 `requires_human_on_failure`（`PUT /api/config/models`）。服务端会校验草稿：适配器是否获批、无明文密钥、无字面量 endpoint、能力/区域/数据分级是否兼容。
3. **测试** —— `POST /api/config/models/test` 执行一次合成连通性检查，报告供应商、模型、路由与时延，或错误类别。mock 模式下这一步从不离开本机。
4. **发布** —— `POST /api/config/publish`。草稿成为新的不可变版本 `v{n}`。需要管理员角色。
5. **回滚** —— `POST /api/config/rollback` 恢复上一个稳定版本。每次发布与回滚都被审计。

运行时快照持久化到 `data/runtime_config.json`，因此已发布状态可在重启后存活。

## 6. 真实模型模式

`LLM_MODE=live` 会把语义检查路由到真实的 OpenAI 兼容 chat-completions 供应商。其余一切不变：同一个策略引擎做决定、写入同样的审计事件、适用同样的失效安全规则。

```text
COMPLIANCE_GUARD_LLM_BASE_URL=https://<provider-host> \
COMPLIANCE_GUARD_LLM_API_KEY=<your-key> \
LLM_MODE=live PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --port 8000
```

密钥也可以放在被 gitignore 的 `config/secrets/llm.local.json`（`{"base_url": "...", "api_key": "..."}`）；环境变量优先于文件。该密钥从不写入快照、API 响应、审计事件或日志。Endpoint 文件不得包含任何密钥，加载器会在发现时拒绝它们。

页头徽标会从 **离线演示模式 / Offline demo mode** 变为 **已接入真实大模型 / Live model connected**。若已开启 live 模式但供应商不可用，徽标显示 **大模型未就绪 / Model not ready**，且 `/health` 报告 `model_service.ready: false`；在该状态下不会放行任何高风险内容。

**真实模型模式下依然成立的保证**，由测试而非约定强制：

- 模型只提议候选。它无法设置决定、严重度、批准状态、路由或工具权限。
- 标识符在请求离开进程**之前**已被打码；模型看到的是形如 `[HCP_TKN_…]` 的 token，永远不是真实姓名。
- 每一种供应商故障（超时、4xx/5xx、截断、非 JSON、缺失凭据）都会变成失效安全的错误类别，因此**故障降级为人工审核，永远不可能看起来像批准**。
- 对于由服务端自行判定的条件（证据缺失、上下文缺失、权限失败、证据冲突），模型给出的候选会记入审计轨迹但绝不被提升为 finding，因此模型的文字无法移动决定。

无需新增依赖；适配器使用早已锁定版本的 `httpx`。

## 7. 故障处置手册

| 情况 | 会发生什么 | 该怎么做 |
| --- | --- | --- |
| **模型超时** | `error_category=timeout` → `MANUAL_DEGRADED`、`human_review` S1，派发审核任务 | 检查 `/health` 与 trace；确认是哪条路由超时；转人工审核 |
| **Schema 失败** | 模型输出非法 → `MANUAL_DEGRADED` 并派发审核任务（若某路由关闭了 `requires_human_on_failure`，则为 `FAILED_SAFE` → `REFUSED`） | 视为数据质量事件；检查输出 Schema 与对应 Profile；重跑黄金集 |
| **检索缺口** | 无证据 → `needs_info`（CN-012，S2）；矛盾 → `human_review`（CN-010，S1） | 补充证据或消解冲突；案例保持在队列中 |
| **提示词注入** | 在模型调用前被标记；CN-005、S0、`blocked`、路由至安全。工具/路由篡改被记录，绝不执行 | 上报安全；不要原样重试该内容 |
| **权限拒绝** | `403` 并返回 `{"error":{"code":"forbidden"}}`；已审计 | 修正角色；绝不绕过拒绝 |
| **重复事件** | 按 `(tenant_id, event_id)` 去重；重复请求返回原结果，不重复产生副作用 | 确认 `created_case_count` 为 1；若副作用重复则检查 DLQ |
| **事件处理失败** | 瞬时 → DLQ `next_action=retry`，最多 `max_attempts`（3）次，之后转 `manual_review`；永久 → 立即 `manual_review` | 读取 DLQ、重放可重试项、把 `manual_review` 当作事件处理 |
| **错误发布** | —— | 以 `compliance_admin` 回滚；确认版本已回退且快照已持久化 |
| **不安全错误** | 任何未捕获异常 → `REFUSED` + `FAILED_SAFE`，派发人工审核。HTTP 响应体从不回显异常或请求内容 | 依据 trace 复现、修复、重跑测试套件 |
| **审计链断裂** | `GET /api/audit-trail/verify` 返回 `ok: false` 与 `first_broken_seq` | 这是数据完整性事件，不是 bug。动手之前先保全文件，然后查清谁有写权限。哈希链只能说明"有改动"，不能说明"改了什么" |
| **服务拒绝启动** | 启动抛出 `ConfigurationError` 并指明文件名 | 修那个文件。过期策略包被拒绝是刻意设计 |
| **ready 为假、live 为真** | `/health/ready` 列出失败的依赖 | 进程活着但无法正确应答。**不要重启**——重启一个健康的进程不会修好一个坏文件 |

### 两个指向"反方向"的告警

| 信号 | 位置 | 为什么重要 |
| --- | --- | --- |
| **推翻率低于 2%** | `GET /api/metrics` → `oversight.status: warning` | 需要调查审核是否已流于形式。这个告警刻意**朝下**报警：一个从不表示异议的审核人，在记录上与一个完美无瑕的系统长得一模一样 |
| **放弃率高于 20%** | `GET /api/metrics` → `usability.status: warning` | 代表在看到提示后清空了编辑器。既没有拦截也没有 finding，因此这种失败在安全指标里完全隐形。要**并排**着看：检出数下降同时放弃率上升，意味着规则变紧了，而不是风险消失了 |

申诉若长期维持高改判率（`GET /api/appeals` → `summary.overturn_rate`），说明要修的是规则，不是队列。逐案吸收同一个误报，只会把成因留在原地。

## 8. 分级健康检查

| 端点 | 回答什么 |
| --- | --- |
| `GET /health/live` | 进程是否存活？不触碰任何依赖，因此一次短暂的文件读取失败不会触发重启循环 |
| `GET /health/ready` | 能否正确应答、基于哪些版本、遵循何种留存策略、处于何种姿态 |
| `GET /health` | 保留给既有调用方与界面模式徽标 |

配置在**启动时**校验，非法配置会拒绝启动并在消息中给出文件名。此前一个格式错误的策略包只会在第一个需要它的请求上暴露——也就是说，第一个发现它的人是**用户**，而且是在写到一半的时候。

## 9. 数据留存

在 `runtime_config.retention_policy()` 中声明，并由 `/health/ready` 报告。**`已强制执行` 这一列要先读**：一个无人实现的留存期，在存储无限增长的同时读起来却像一项控制措施，因此这两种状态被分开报告而不是含糊带过。

| 存储 | 留存期 | 已强制执行 | 理由 |
| --- | --- | --- | --- |
| 审计账本 | 永不自动删除 | 无清理任务 | 必须不短于它所描述的记录。清理任务会摧毁那条"让删除可被发现"的哈希链 |
| 反馈候选 | 永不自动删除 | 无清理任务 | 已确认的候选会成为回归用例 |
| 通知 | 90 天 | 是，读取时清理 | **未读**通知永不清理：让作者尚未看到的结果静默过期，等于把它悄悄丢掉 |
| 已解决申诉 | 90 天 | 是，同一清理 | **待处理**申诉永不过期；让未完成的工作过期，等于用疏忽把它关掉 |
| 预检日志 | 7 天 | 尚未实现 | 仅时延遥测；没有任何决定依赖它 |
| 草稿 | 7 天，浏览器本地 | 是，在浏览器中过期 | 从不上传；服务端从不持有 |

清理在读取时机会性执行，而不是靠定时器：这是一个没有调度器的单本地进程，而当清理本身很廉价时，专门起一个只负责删记录的后台线程并不划算。

## 10. 运行时产物（全部 gitignore）

- `data/audit/` —— 仅追加、哈希链式 JSONL 账本
- `data/runtime_config.json` —— 已发布模型策略的持久化快照
- `data/users.json` —— 本地账号与会话令牌
- `data/golden_set/candidates.jsonl` —— 待第二人确认后才可进入黄金集的误分类报告
- `artifacts/` —— 评估器报告
