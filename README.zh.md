# Compliance AI Guard

[English](README.md) · **简体中文**

一个可独立部署的医疗内容与 AI 对话合规网关。它检查人工提交的文本，约束并
检查模型生成，在内容发布前拦截不安全结果。独立模式不需要特定供应商 SDK、
外部数据库、消息队列、身份提供商或在线模型。

模型只负责提出候选发现或起草回复。处置、严重度、复核路由和发布权限由确定性
策略引擎决定。检查失败或降级永远不会变成放行。

```text
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
LLM_MODE=mock DEMO_MODE=1 PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --port 8000
```

打开 <http://127.0.0.1:8000>。`LLM_MODE=mock` 是默认模式，全程不发网络请求。
也可以运行 `LLM_MODE=mock DEMO_MODE=1 python3 run.py`，由程序选择空闲端口并
打开浏览器。

**范围说明。** 这是一个用于探索受监管环境中 AI 权限控制的可运行 MVP。它对
GxP/CSV、药物警戒、医学法务审查或法规验证**不作任何声称**，也没有接入任何
在线客户系统。仓库内全部数据均为合成数据。不良事件分诊、上报时限、Part 11
风格签名表现形式和 ALCOA+ 视图展示了这些控制措施的形态，不代表经过验证的
实现。本文档不构成法规建议。

## 两个检查入口

| 入口 | API | 用途 |
| --- | --- | --- |
| 内容检查 | `POST /api/checks` | 在保存、发送或发布任意医疗及推广文本前完成检查 |
| AI 对话防护 | `POST /api/conversations/guard-input` | 在创建生成会话前检查不可信输入 |

`POST /api/checks/precheck` 提供编辑过程中的确定性快速预检。它不创建案例，
不保存提交文本，也不会调用模型。

## AI 三个阶段

阶段代码依次为 `input` → `generation` → `output`。

1. **输入** — 网关检查用户消息、脱敏标识符，并在任何模型调用前拦截提示注入
   或其他禁止请求。安全输入会建立短期、绑定用户的对话会话。
2. **生成** — 只能使用服务端保存的已检查输入。模型收到有边界的上下文和适用
   规则约束，返回完整缓冲的候选回复。
3. **输出** — 候选回复在发布前经过同一策略路径。不安全结果会被撤销，且不会
   回显模型正文。输出检查异常时返回 `failed_safe`。

会话不能换入检查后修改的提示词，不能被其他用户或租户复用，不能超过 15 分钟，
也不能在规则版本变化后继续使用。浏览器不能决定发布权限。

## 四种处置

每个结果使用四个公共处置值：

- `allow` — 当前规则未发现需要阻止的问题；这不代表法律或监管批准。
- `needs_info` — 缺少完成判断所需的上下文或证据。
- `human_review` — 需要专业人员评估。
- `blocked` — 禁止生成或发布。

每个 finding 都带有 S0 至 S3 严重度、规则版本、易懂解释、可选的 Unicode
字符片段、允许动作和所需复核角色。`refused` 保留为不安全请求的内部终态。
S0 与 S1 不允许自我批准。

## 七个工作区

| 工作区 | 用途 |
| --- | --- |
| `overview` | 业务上下文、近期活动和两个主要检查入口 |
| `content_check` | 提交任意文本，查看处置、片段、finding 和版本 |
| `conversation_guard` | 检查输入、建立服务端会话，仅展示通过输出检查的回复 |
| `reviews` | 证据、复核决定与签名表现形式 |
| `rules` | 当前规则、版本历史、测试、批量评估、差异、发布和回滚 |
| `quality_audit` | 审计链完整性、监督指标、回归候选、连接器与审计事件 |
| `settings` | 模型档案、任务路由、草稿校验、测试、发布和回滚 |

工作区可见性来自服务端权限矩阵。隐藏控件只是界面辅助，所有受保护 API 都会
独立检查权限。

## 控制措施

**模型提议，服务端决定。** 模型输出不能设置处置、严重度、批准状态、路由或
工具权限。候选声明会与服务端推导的事实和已发布规则版本核对。

**标识符在外部模型调用前脱敏。** 打码只替换识别出的实体片段。实体消解先于
打码，使同一个人获得同一个稳定 token。打码过度被单独测试，因为它可能在安全
规则读到文本前删除不良事件词汇。

**证据按版本封闭检索。** 缺少证据转为 `needs_info` 或人工复核，永远不会变成
放行。过期或跨版本证据会被拒绝。

**审计载荷不保存正文。** 仅追加哈希链记录主体、时间、规则与内容版本、处置、
规则引用和安全摘要。`GET /api/audit-trail/verify` 会报告第一个不可验证位置。

**失败不等于放行。** 模型超时、输出格式异常、脱敏失败、权限拒绝或审计写入
失败会进入 `MANUAL_DEGRADED`、`FAILED_RETRYABLE` 或 `FAILED_SAFE`。案例不能
从失败状态到达 `ALLOWED`。

**连接器是可选的契约。** 内容源、安全接收和复核导出采用供应商中立的 JSON
契约，支持版本检查、幂等和死信处理。缺少连接器不会阻断检查、规则生命周期、
人工复核或审计。

## 验证

```text
python -m pytest -q
python tests/evaluation/run_eval.py --mode mock --output artifacts/eval-report.json
```

发布报告覆盖 44 条合成黄金用例、12 条打码与实体消解用例、危险放行、证据约束、
审计完备性、打码召回、源保真度、复核权限、时延、术语覆盖以及超适应症精确率
与召回率。`release_gate` 必须为 `pass`。

最终测试数量与评测结果记录在 [验证文档](docs/zh/validation.md)。

## 真实模型模式

```text
COMPLIANCE_GUARD_LLM_BASE_URL=https://<provider-host> \
COMPLIANCE_GUARD_LLM_API_KEY=<your-key> \
LLM_MODE=live PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --port 8000
```

通过已配置的档案接入任何 OpenAI 兼容 chat-completions 供应商。密钥可以放在
被 gitignore 的 `config/secrets/llm.local.json`。档案发布带版本，重新指向档案
不会改写历史案例的含义。生成始终经过服务端，模型输出完整缓冲，供应商失败时
不会放行未经检查的文本。

## 文档

| 文档 | English | 内容 |
| --- | --- | --- |
| [产品手册](docs/zh/product-guide.md) | [Product guide](docs/product-guide.md) | 面向用户与部署者的定位、安装、功能说明、API、架构图、安全边界与限制 |
| [架构设计](docs/zh/architecture.md) | [architecture](docs/architecture.md) | 共享控制面、请求路径、AI 三阶段、策略规则、数据模型、失败状态 |
| [运维手册](docs/zh/operations.md) | [operations](docs/operations.md) | 安装、七工作区、规则与模型生命周期、真实模式、故障处置、留存 |
| [安全与风险](docs/zh/security-and-risk.md) | [security-and-risk](docs/security-and-risk.md) | 信任边界、风险登记册、打码、注入防御、审计隐私、范围边界 |
| [验证](docs/zh/validation.md) | [validation](docs/validation.md) | 测试分层、黄金集、发布门禁、评测结果、变更控制 |
| [集成契约](docs/zh/integration-contracts.md) | [integration-contracts](docs/integration-contracts.md) | 可选内容源、安全接收与复核导出契约 |
| [决策记录 0001](docs/zh/decisions/0001-workflow-first-controlled-agent.md) | [decisions/0001](docs/decisions/0001-workflow-first-controlled-agent.md) | 工作流优先的受控 Agent 决策 |

## 技术栈

Python 3.12+、FastAPI、Pydantic v2、uvicorn 与 `httpx`。界面使用零构建步骤的
原生 JavaScript。独立模式使用本地 JSON 与 JSONL 存储。
