# Integration Contracts

**English** · [简体中文](zh/integration-contracts.md)

The integration boundary uses three small, vendor-neutral connector contracts:
content source, safety intake, and review export. The reference implementations
are in memory and make no network calls. A deployment can replace them with
adapters for its own record system, safety system, and review archive.

The contracts cover reads, idempotency, version checks, retryable failure and
operator-visible health. They do not claim that a particular external product is
available, validated, or configured.

## 1. Connector registry

Every connector exposes a `ConnectorInfo` descriptor. It reports its kind, label,
capabilities, permitted actions, data classes, enabled state, and `mode: "mock"`.
The descriptor is available through:

```text
GET /api/connectors
```

Content-source connectors and their records are listed through:

```text
GET /api/sources
GET /api/sources/{connector_id}/records/{record_id}?version={version}
```

The second endpoint re-reads the authoritative record. A missing connector or
record returns a typed error; a version that is not current returns HTTP `409`
with `stale_source_version`.

## 2. Content source

```python
class ContentSource(Protocol):
    def fetch(self, record_id: str, version: str | None = None) -> ContentEnvelope: ...
```

`ContentEnvelope` carries the record id, version, authoritative text,
`ContentType`, tenant, market, product and update time. Only a current version is
accepted for a version-checked read.

An event payload is a notification, not the source of truth. Even if delivery
contains text, the server must re-read the record by id. This prevents stale,
truncated, or altered delivery data from becoming the basis of a compliance
decision.

## 3. Safety intake

```python
class SafetyIntake(Protocol):
    def submit(self, event: SafetyCandidate, idempotency_key: str) -> SafetyReceipt: ...
```

Safety intake stores a candidate locally before attempting downstream delivery. A
transient failure raises `SafetyIntakeError` and leaves the candidate in the pending
set. Retrying with the same idempotency key returns the original receipt after the
first successful submission.

The contract supports human-authorized release. It does not make a safety decision
or automatically file a regulatory report.

## 4. Review export

```python
class ReviewExport(Protocol):
    def export(
        self, request: ReviewExportRequest, idempotency_key: str
    ) -> ExportReceipt: ...
```

Review export is disabled by default. Attempting an export while disabled raises
`ReviewExportDisabledError`. Once explicitly enabled, repeated calls with the same
idempotency key return the original receipt and create no second export.

## 5. Event delivery

`EventBus.receive_event` accepts an `ExternalEvent` or a mapping and normalizes it
to a `NormalizedEvent`. Duplicate deliveries are keyed by
`(tenant_id, event_id)` and do not create another case or review task.

| Failure | Handling |
| --- | --- |
| Schema error | Non-retryable dead letter, `next_action="manual_review"` |
| Permission error | Non-retryable dead letter, `next_action="manual_review"` |
| Transient processing error | Retryable dead letter until `max_attempts` (default 3), then `manual_review` |
| Duplicate delivery | Return the first normalized result without replaying side effects |
| DLQ replay | Re-run retryable records idempotently; successful records leave the queue |

When an audit ledger is attached, event receipt, duplicate detection, processing,
dead-lettering and replay are recorded without raw content.

## 6. Integration checklist

Before enabling a live connector, define:

1. The record id and version model for every authoritative content source.
2. Which content types and approval states are admissible evidence.
3. Tenant, market, residency, and data-class constraints for every read.
4. The authorization path for safety intake and review export.
5. The idempotency key lifetime and duplicate-delivery behavior.
6. Retry limits, DLQ ownership, monitoring, and replay authorization.
7. The evidence required to replace each mock connector and validate the deployed
   path.
