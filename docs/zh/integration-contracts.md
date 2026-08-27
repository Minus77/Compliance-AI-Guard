# 集成契约

[English](../integration-contracts.md) · **简体中文**

本系统与药企部署所涉外部系统之间的适配器边界：CRM / 拜访记录来源、已批准内容库，以及安全（PV）系统。

**按设计仅为契约实现。** 不涉及任何真实系统、许可证、凭据或网络调用。每个适配器都从内存存储返回 `mock://` 回执，契约测试通过 monkeypatch socket 层断言不存在网络访问。这里演练的是真实集成所需的那组**不变量**——从源系统回读、版本拒绝、审批门控写入、幂等——从而让日后接入真实系统成为一次**替换**，而不是一次重新设计。

实现位于 `src/compliance_guard/integrations/`：`event_bus.py`、`veeva_adapter.py`、`pv_adapter.py`、`crm_adapter.py`、`source_registry.py`。

## 1. 映射关系

| 关注点 | 生产系统 | 契约实现 | 不变量 |
| --- | --- | --- | --- |
| 业务叙述来源 | CRM 拜访记录 | `CrmAdapter` / `VeevaAdapter`（`get_current_record`、`normalize_event`） | 按当前版本回读；绝不信任事件载荷 |
| 已批准内容、声明、说明书版本 | 内容库（推广 / 医学沟通） | `SourceStoreMixin` 版本门控 + `ContentDraft` 写回 | 只有已批准且为当前版本的内容才可作为证据 |
| 变更投递 | Vault API / 事件框架 | `EventBus.receive_event` | 事件仅为通知；详情一律回读 |
| 权限边界 | 文档级原子安全 | 角色门控的 `validate_approval_token`、`ALLOWED_WRITE_ROLES` | 在调用方授权范围内运行，绝不提权 |
| 执行边界 | 受限的 Agent 执行 | 仅审批门控写入 | 不存在通用管理工具 |
| 安全下游 | Vault Safety / PV | `PvAdapter.submit_safety_case` + 审核路由 | 绝不自动提交；由人授权 |
| 可靠投递 | 队列 + DLQ | `EventBus` 去重、`DeadLetterRecord`、`replay_dlq` | 幂等；可重试与需人工分类 |

## 2. 为什么事件载荷从不具备权威性

投递是一条轻量通知，只携带事件 id 与记录引用。内容一律来自 `get_current_record(record_id, version)`。

载荷可能过期、被截断，或在传输中被改动。**按 id 回读**才能保证检查作用于记录当前真正的内容。传入比当前版本更旧的版本会被 `409 stale_source_version` 拒绝，而不是被静默接受；界面会显示**已从源系统回读**徽标，让来源可见而非靠假设。

连接器由 `GET /api/sources` 枚举，因此新增一个只需在 `source_registry.py` 追加一个条目——界面与 API 无需任何其他改动即可识别。每个连接器都报告 `mode: "mock"`，因此界面永远不可能暗示存在真实租户。

## 3. 幂等、重试与死信队列

| 关注点 | 语义 |
| --- | --- |
| 去重键 | `(tenant_id, event_id)`；重复请求返回原结果，不重复施加任何副作用 |
| 案例创建 | 确定性 `CASE-<sha256(tenant:event)[:12]>`；同一键绝不产生多于一个案例 |
| 审核任务 | 每个 `(tenant_id, event_id)` 最多一个 |
| 可重试失败 | → DLQ，`next_action="retry"`，计数至 `max_attempts`（默认 3），随后转为 `manual_review` |
| 不可重试失败 | Schema、权限或显式不可重试 → DLQ，立即 `manual_review` |
| 重放 | `replay_dlq` 重跑可重试项；已处理过的键会被清理且不再施加副作用 |
| 写入 | 按 `(tenant_id, idempotency_key)` 键控；重复写入返回原回执 |

系统假定投递为至少一次（at-least-once），因此**恰好一次的效果**是适配器的职责，而不是消息中间件的职责。

## 4. 审批门控写入

对任何外部边界的每一次写入，都同时要求三项：

1. **短时效审批令牌**，在签发时即绑定角色、用途、源版本、租户与可选记录 id，并带绝对过期时间（默认 300 秒）。每次使用都会重新校验存在性、过期时间、允许角色、批准用途与源版本一致性。
2. **幂等键** —— 重复写入返回原回执，绝不产生第二次副作用。
3. **源版本一致** —— 草稿版本必须等于源系统当前的权威版本。

不存在任何无需有效令牌与幂等键即可写入、删除或改变状态的方法。拒绝会抛出 `ApprovalDeniedError`（一种 `PermissionError`）并被审计；它们绝不会被降级为静默跳过。

**安全路径被刻意收窄。** 潜在不良事件路由至 PV **人工审核**。`submit_safety_case` 是唯一的 PV 写入路径，它要求 `purpose="safety_submission"`，并且只有 `qppv` 持有放行它的权限。**一个能够自动提交法规上报的 Agent，会是这里最不能出错的一件事。**

## 5. 已实现的接口

```python
# event_bus.py
receive_event(envelope) -> NormalizedEvent                    # 抛出 SchemaError
EventBus(max_attempts=3, *, handler, ledger, now)
EventBus.receive_event(envelope) -> NormalizedEvent            # 去重 -> 处理 -> DLQ
EventBus.created_case_count(event_id, tenant_id=None) -> int   # 同一键绝不 > 1
EventBus.read_dlq() -> list[DeadLetterRecord]
EventBus.replay_dlq(record_id=None) -> list[NormalizedEvent]

# veeva_adapter.py
get_current_record(record_id, version=None) -> SourceRecord    # SourceNotFoundError | StaleVersionError
normalize_event(event) -> SourceRecord
handle_event(normalized) -> str
create_review_task_in_vault(task, approval_token, idempotency_key=None) -> ExternalTaskRef
write_draft_after_approval(draft, approval_token, idempotency_key) -> WriteResult
issue_approval_token(*, role, purpose, source_version, tenant_id, record_id=None, ttl_seconds=300) -> ApprovalToken
validate_approval_token(token, *, now, source_version=None) -> ApprovalToken

# pv_adapter.py
submit_safety_case(draft, approval_token, idempotency_key) -> PvCaseRecord

# crm_adapter.py
normalize_event(event) -> SourceRecord                         # 只读
```

错误分类体系：`EventProcessingError` → `RetryableProcessingError` / `NonRetryableProcessingError`；`SchemaError` 是不可重试的规范化失败；`StaleVersionError` 与 `ApprovalDeniedError(PermissionError)` 分别守卫版本边界与权限边界。

记录的审计事件（不含原始 PII，不含密钥）：`event_received`、`event_duplicate`、`event_processed`、`event_dead_lettered`、`dlq_replay`、`source_read`、`source_read_miss`、`source_version_rejected`、`approval_token_issued`（仅摘要）、`vault_review_task_created`、`vault_review_task_denied`、`vault_draft_write`、`vault_draft_write_denied`、`pv_case_submitted`、`pv_case_denied`。

## 6. 任何真实集成的待解问题

以下问题无法从本侧回答，而每一个都会改变设计：

1. 涉及哪些环境、版本与许可证？
2. 哪个 API 投递变更事件并允许回读，速率限制如何？
3. 服务将以何种权限授权运行，作用于何种对象范围？
4. 它在内容库平台内部执行，还是作为外部服务运行？
5. 哪个拜访记录对象与字段承载业务叙述？是否包含附件？
6. 哪些内容类型与批准状态属于可采证据，版本与生效日期如何建模？
7. 安全信号到达安全数据库的合规路径是什么，由谁授权，事前需要哪些证据？
8. 存在何种投递保证，谁负责 DLQ 监控与重放？
9. 数据驻留、跨境传输与 PHI 处理的审批。
10. 适用何种验证范围，生产启用前需要哪些证据？
