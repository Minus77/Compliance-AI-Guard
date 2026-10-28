# 运维手册

[English](../operations.md) · **简体中文**

运行服务、操作七个工作区、管理规则与模型路由、处理故障并留存证据。本手册
描述当前已经实现的服务。

## 1. 本地运行

需要 Python 3.12+（本机在 3.13 上验证）。`LLM_MODE=mock` 是默认值，全程零网络
调用。

```text
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
LLM_MODE=mock DEMO_MODE=1 PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

浏览器打开 <http://127.0.0.1:8000>。Windows PowerShell 下先设置变量：
`$env:LLM_MODE = "mock"; $env:DEMO_MODE = "1"; $env:PYTHONPATH = "src"`。

也可以用一条命令启动，由程序选择空闲端口并打开浏览器：

```text
LLM_MODE=mock DEMO_MODE=1 python3 run.py
```

使用 `python -m uvicorn`，可以避开安装时写入绝对解释器路径的控制台脚本；目录
移动后，该脚本可能失效。`PYTHONPATH=src` 同时适用于可编辑安装和直接运行源码。
使用虚拟环境可以避开系统 Python 的外部管理限制。

## 2. 身份与部署模式

`DEMO_MODE=1` 跳过登录，为本地演示提供四个角色：

| 演示角色 | 用途 |
| --- | --- |
| `author` | 提交内容、检查 AI 输入并查看自己的结果 |
| `reviewer` | 打开复核任务并记录专业决定 |
| `auditor` | 查看审计证据、质量态势与连接器 |
| `architect` | 查看和起草模型配置，不能发布 |

服务端权限矩阵支持复核路由所需的更广专业角色。演示角色来自请求头，不构成
身份认证。除非处在受信任的本地演示环境，否则应使用真实会话。

去掉 `DEMO_MODE` 后使用会话运行：

```text
LLM_MODE=mock PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

首次启动会生成初始 `admin` 密码并仅在控制台打印一次。它不会以明文写入审计
账本或持久化文件。必须先修改该密码才能正常使用；修改密码会终止该账号的所有
会话，包括当前会话。

从未使用过的账号丢失初始密码时，重启会重新签发。已经使用过的账号需要恢复时，
把 `data/users.json` 移走并重启。该文件包含 scrypt 密码哈希与活跃会话令牌，
已经被 gitignore。

本地身份存储不提供身份提供方、第二因子或用户管理，设计上留作企业身份集成的
替换接缝。

## 3. 七个工作区

| 工作区 | 用途 |
| --- | --- |
| `overview` | 当前上下文、近期活动和两个检查入口 |
| `content_check` | 提交任意文本，查看处置、片段、finding 与版本 |
| `conversation_guard` | 检查输入、建立会话、生成，并仅显示已放行输出 |
| `reviews` | 复核任务、证据、决定与签名表现形式 |
| `rules` | 规则版本、测试、批量评估、差异、发布与回滚 |
| `quality_audit` | 审计链校验、监督指标、回归候选、连接器与事件 |
| `settings` | 模型档案、任务路由、校验、测试、发布与回滚 |

工作区可见性来自服务端返回的能力矩阵。隐藏控件用于改善导航；每个受保护端点
都会独立检查操作者和权限。

## 4. 检查操作

### 内容检查

`POST /api/checks/precheck` 是编辑期间的确定性快速检查。它不创建案例、不保存
提交文本，也不调用模型。空 finding 列表表示当前规则通过；它不构成法规批准。

`POST /api/checks` 保存版本化检查。它先完成实体消解，只打码识别出的片段，检索
可用证据，在配置允许时调用有界模型抽取，再把候选字段送入确定性策略引擎。
响应包含处置、严重度、finding、原文片段、策略版本、内容版本、安全文本，以及
是否调用了模型。

检查绑定精确提交版本。客户端修改文本后必须重新检查，不能复用旧结果。

### AI 对话防护

受保护链路分为三个阶段：

1. **输入** — `POST /api/conversations/guard-input` 在模型调用前检查用户消息。
   输入被阻断时不创建会话，也不调用模型。
2. **生成** — `POST /api/conversations/{conversation_id}/generate` 校验操作者、
   租户、已检查提示词哈希、规则版本与会话有效期。模型只接收服务端保存的安全
   输入和有边界的约束。
3. **输出** — 完整候选回复先经过共享策略路径，再决定是否显示。被阻断或检查
   失败的结果会撤回，不返回模型正文。

安全输入建立 15 分钟的服务端会话，并绑定操作者、租户、原文哈希和规则版本。
提示词变化返回 `conversation_prompt_mismatch`；规则版本变化返回
`conversation_requires_recheck`；会话过期或关闭返回 `conversation_expired`。

`GET /api/audit-trail/verify` 校验只追加哈希链，正常运行时返回 `ok: true`。
如果返回失败位置，应先调查，再允许新的发布。

## 5. 六场景演示

**示例与教学**抽屉中的用例覆盖六个场景：

| # | 场景 | 示例风险 | 预期处理 |
| --- | --- | --- | --- |
| 1 | `normal` | 与已批准产品信息一致的表述 | 当前证据支持时 `allow` |
| 2 | `ae` | 皮疹等潜在不良事件 | `human_review`，转安全与医学复核 |
| 3 | `pii` | 联系信息或身份信息 | 按严重度复核或阻断；模型访问前打码 |
| 4 | `off_label` | 未批准适应症或剂量 | `human_review`，转合规与医学复核 |
| 5 | `redline` | 严重不良事件或商业利益输送 | 立即阻断或专业升级 |
| 6 | `injection` | 指令覆盖或伪造权限 | `blocked`；记录尝试，绝不执行 |

这些示例全部为合成内容。`DEMO_MODE=0` 会隐藏教学抽屉，避免与生产内容混淆。

## 6. 规则生命周期

规则包一经发布即不可变。生命周期如下：

1. 从当前规则包开始，记录规则版本和策略版本。
2. 按租户、市场、语言、产品、治疗领域、内容类型和入口（`content`、`input`
   或 `output`）起草作用域。
3. 增加确定性条件、严重度、处置、允许动作、所需复核角色、整改方向和证据
   要求。
4. 通过 `POST /api/rules/test` 测试代表性正例、反例、重叠与片段位置。
5. 通过 `POST /api/rules/evaluate` 运行批量或黄金集回归。
6. 发布前检查 `GET /api/rules/diff`。
7. 通过 `POST /api/rules/publish` 发布，或通过 `POST /api/rules/rollback`
   恢复不可变的历史版本。

规则版本变化不会改写历史检查。基于旧版本完成的 AI 会话需要重新检查。发布与
回滚需要获授权的管理员；架构权限只能起草和查看。

## 7. 模型档案与任务路由

模型配置分为档案和任务路由：

- 档案声明能力、区域、数据类别限制、超时、凭据引用和上游模型标识。
- 路由为具体任务选择档案，包括文本抽取、受控回复生成和多模态输入。
- 凭据放在环境变量或被 gitignore 的本地密钥文件中。持久化配置和审计事件只
  保留引用与打码值。
- 草稿校验拒绝明文密钥、字面量 endpoint、不完整能力声明，以及不兼容的区域或
  数据类别组合。
- `GET/PUT /api/config/models` 查看和起草配置。
- `POST /api/config/models/test` 校验候选路由。
- `POST /api/config/publish` 创建版本快照。
- `POST /api/config/rollback` 恢复上一个稳定快照。

架构角色可以起草、测试和查看，发布与回滚需要管理员。每次发布或回滚都会写入
审计事件。

## 8. 真实模型模式

Mock 模式适用于开发、自动测试和演示。真实模式通过已发布档案接入 OpenAI
兼容 chat-completions 供应商：

```text
COMPLIANCE_GUARD_LLM_BASE_URL=https://<provider-host> \
COMPLIANCE_GUARD_LLM_API_KEY=<your-key> \
LLM_MODE=live PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

供应商地址与密钥不得写入提交文件。供应商只会收到有边界且已打码的请求。模型
输出始终是候选，不能设置发布权限。对话输出完整缓冲并检查通过后才会显示。

## 9. 故障处置

| 情况 | 预期状态 | 运维动作 |
| --- | --- | --- |
| 供应商超时或候选格式异常 | `MANUAL_DEGRADED` | 保持发布暂停；只在当前策略和档案下重试 |
| 瞬时依赖失败 | `FAILED_RETRYABLE` | 有界重试后移交人工 |
| 无法安全处理的条件 | `FAILED_SAFE` | 不发布，保留安全错误并升级 |
| 打码组件失败 | 失败或保持 | 不把原文送给模型 |
| 审计写入失败 | 发布失败 | 恢复审计后再重试发布 |
| 规则版本不可用或已变化 | 拒绝或保持 | 按当前已发布版本重新检查 |
| 会话过期 | `conversation_expired` | 重跑输入检查；不要延长旧批准 |

`MANUAL_DEGRADED`、`FAILED_RETRYABLE` 与 `FAILED_SAFE` 都不会转为
`ALLOWED`。发布需要成功的输出检查与审计事件。

有两个健康信号可能朝反方向变化。推翻率上升可能说明审核人不再信任规则；
复核完成率下降可能说明队列正在阻塞工作。应结合案例证据检查两者，而不是单独
优化某一个数字。

## 10. 健康检查与留存

`GET /health/live` 验证进程存活，`GET /health/ready` 检查启动依赖，
`GET /health` 提供运维使用的分级健康视图。

审计事件记录标识、操作者、时间、版本、处置、规则引用、安全哈希和失败类别。
默认不记录原文、敏感实体映射、令牌映射、系统提示或完整模型输出。审计内容访问
和发布动作分别授权。

独立模式状态保存在 `data/` 下的本地 JSON 与 JSONL 中。应按部署留存政策限制
文件访问并备份，绝不能提交到仓库。`artifacts/` 保存生成的报告，也已被
gitignore。
