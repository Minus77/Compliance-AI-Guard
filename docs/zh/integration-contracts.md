# 集成契约

[English](../integration-contracts.md) · **简体中文**

集成边界由三个小型、供应商无关的连接器契约组成：内容源、安全信号接入和审核导出。参考实现全部在内存中运行，不发起网络调用。部署时可以用适配器接入组织自己的记录系统、安全系统和审核归档系统。

这些契约覆盖读取、幂等、版本校验、可重试失败和运维可见的健康状态。它们不声称某个外部产品已经可用、经过验证或完成配置。

## 1. 连接器注册表

每个连接器都提供 `ConnectorInfo` 描述，包括类型、名称、能力、允许动作、数据类别、启用状态和 `mode: "mock"`。可以通过以下接口查看：

```text
GET /api/connectors
```

内容源连接器及其记录可以通过以下接口查看：

```text
GET /api/sources
GET /api/sources/{connector_id}/records/{record_id}?version={version}
```

第二个接口会回读权威记录。连接器或记录不存在时返回有明确含义的错误；版本不是当前版本时返回 HTTP `409` 和 `stale_source_version`。

## 2. 内容源

```python
class ContentSource(Protocol):
    def fetch(self, record_id: str, version: str | None = None) -> ContentEnvelope: ...
```

`ContentEnvelope` 包含记录 id、版本、权威正文、`ContentType`、租户、市场、产品和更新时间。带版本读取时只接受当前版本。

事件载荷只是通知，不是事实来源。即使投递中包含正文，服务端也必须按 id 回读记录。这样，过期、截断或被篡改的投递内容不会成为合规决定的依据。

## 3. 安全信号接入

```python
class SafetyIntake(Protocol):
    def submit(self, event: SafetyCandidate, idempotency_key: str) -> SafetyReceipt: ...
```

安全信号接入会先在本地点保留候选信号，再尝试下游投递。临时失败会抛出 `SafetyIntakeError`，候选仍保留在待处理集合中。首次成功后再用同一个幂等键提交，会返回原回执。

该契约只支持经人工授权的释放，不替用户做安全决定，也不会自动提交法规报告。

## 4. 审核导出

```python
class ReviewExport(Protocol):
    def export(
        self, request: ReviewExportRequest, idempotency_key: str
    ) -> ExportReceipt: ...
```

审核导出默认关闭。关闭状态下调用会抛出 `ReviewExportDisabledError`。明确启用后，使用相同幂等键重复调用会返回原回执，不会产生第二次导出。

## 5. 事件投递

`EventBus.receive_event` 接受 `ExternalEvent` 或映射，并规范化为 `NormalizedEvent`。重复投递按 `(tenant_id, event_id)` 去重，不会重复创建案例或审核任务。

| 失败类型 | 处理方式 |
| --- | --- |
| Schema 错误 | 进入不可重试死信队列，`next_action="manual_review"` |
| 权限错误 | 进入不可重试死信队列，`next_action="manual_review"` |
| 临时处理错误 | 进入可重试死信队列，达到 `max_attempts`（默认 3）后转 `manual_review` |
| 重复投递 | 返回首次规范化结果，不重复施加副作用 |
| 死信重放 | 以幂等方式重跑可重试记录；成功的记录离开队列 |

接入审计账本后，事件接收、重复检测、处理、死信和重放都会留下记录，但不包含原始正文。

## 6. 集成检查清单

启用真实连接器之前，需要明确：

1. 每个权威内容源的记录 id 与版本模型。
2. 哪些内容类型和批准状态可以作为证据。
3. 每次读取的租户、市场、数据驻留和数据类别约束。
4. 安全信号接入与审核导出的授权路径。
5. 幂等键的有效期和重复投递行为。
6. 重试上限、死信负责人、监控和重放授权。
7. 用真实连接器替换 mock 实现并验证部署路径所需的证据。
