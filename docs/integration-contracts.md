# Integration Contracts

**English** · [简体中文](zh/integration-contracts.md)

The adapter boundary between this system and the external systems a pharma
deployment would involve: a CRM/call-report source, an approved-content vault, and
a safety (PV) system.

**Contract-only, by design.** No live system, license, credential, or network call
is involved. Every adapter returns `mock://` receipts from an in-memory store, and
contract tests assert the absence of network access by monkeypatching the socket
layer. What is exercised here is the set of *invariants* a live integration needs —
re-read from source, version rejection, approval-gated writes, idempotency — so
that wiring a real system in later is a substitution rather than a redesign.

Implemented in `src/compliance_guard/integrations/`: `event_bus.py`,
`veeva_adapter.py`, `pv_adapter.py`, `crm_adapter.py`, `source_registry.py`.

## 1. Mapping

| Concern | Production system | Contract implementation | Invariant |
| --- | --- | --- | --- |
| Business narrative source | CRM call report | `CrmAdapter` / `VeevaAdapter` (`get_current_record`, `normalize_event`) | Re-read at current version; never trust the event payload |
| Approved content, claims, label versions | Content vault (promotional / medical comms) | `SourceStoreMixin` version gating + `ContentDraft` write-back | Only approved, current-version content is admissible evidence |
| Change delivery | Vault API / event framework | `EventBus.receive_event` | Event is a notification only; details are re-read |
| Permission boundary | Document-level atomic security | Role-gated `validate_approval_token`, `ALLOWED_WRITE_ROLES` | Operates within the caller's grants, never elevated |
| Execution boundary | Scoped agent execution | Approval-gated writes only | No generic admin tool exists |
| Safety downstream | Vault Safety / PV | `PvAdapter.submit_safety_case` + review routing | Never auto-submitted; a human authorizes |
| Reliable delivery | Queue + DLQ | `EventBus` dedup, `DeadLetterRecord`, `replay_dlq` | Idempotent; retryable vs manual-review classified |

## 2. Why the event payload is never authoritative

Delivery is a lightweight notification carrying an event id and a record
reference. Content always comes from `get_current_record(record_id, version)`.

A payload can be stale, truncated, or edited in transit. Re-reading by id is what
makes the check apply to what the record actually says now. Passing a version older
than the current one is rejected with `409 stale_source_version` rather than
silently accepted, and the UI shows a *re-read from source of record* badge so the
provenance is visible rather than assumed.

Connectors are enumerated from `GET /api/sources`, so adding one means appending an
entry to `source_registry.py` — the UI and API pick it up with no other change.
Every connector reports `mode: "mock"`, so the UI can never imply a live tenant.

## 3. Idempotency, retry, DLQ

| Concern | Semantics |
| --- | --- |
| Dedup key | `(tenant_id, event_id)`; duplicates return the original result and re-apply nothing |
| Case creation | Deterministic `CASE-<sha256(tenant:event)[:12]>`; never more than one case per key |
| Review tasks | At most one per `(tenant_id, event_id)` |
| Retryable failure | → DLQ, `next_action="retry"`, attempts counted to `max_attempts` (default 3), then flips to `manual_review` |
| Non-retryable failure | Schema, permission, or explicit non-retryable → DLQ, `manual_review` immediately |
| Replay | `replay_dlq` re-runs retryables; already-processed keys clear without re-applying side effects |
| Writes | Keyed by `(tenant_id, idempotency_key)`; repeats return the original receipt |

At-least-once delivery is assumed, so exactly-once *effect* is the adapter's job,
not the broker's.

## 4. Approval-gated writes

Every write to any external boundary requires all three:

1. **A short-lived approval token**, bound at issuance to role, purpose, source
   version, tenant, and optional record id, with an absolute expiry (default 300 s).
   Validation re-checks presence, expiry, allowed role, approved purpose, and
   source-version agreement on every use.
2. **An idempotency key** — repeated writes return the original receipt, never a
   second side effect.
3. **Source-version agreement** — the draft version must equal the authoritative
   current version.

There is no method that writes, deletes, or changes state without a validated token
and an idempotency key. Denials raise `ApprovalDeniedError` (a `PermissionError`)
and are audited; they are never downgraded to a silent skip.

**The safety path is deliberately narrow.** A potential AE routes to PV *human
review*. `submit_safety_case` is the only PV write path, it requires
`purpose="safety_submission"`, and only `qppv` holds the permission to release it.
An agent that could auto-file a regulatory submission would be the single most
consequential thing to get wrong.

## 5. Interfaces as implemented

```python
# event_bus.py
receive_event(envelope) -> NormalizedEvent                    # raises SchemaError
EventBus(max_attempts=3, *, handler, ledger, now)
EventBus.receive_event(envelope) -> NormalizedEvent            # dedup -> process -> DLQ
EventBus.created_case_count(event_id, tenant_id=None) -> int   # never > 1 per key
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
normalize_event(event) -> SourceRecord                         # read-only
```

Error taxonomy: `EventProcessingError` → `RetryableProcessingError` /
`NonRetryableProcessingError`; `SchemaError` is a non-retryable normalization
failure; `StaleVersionError` and `ApprovalDeniedError(PermissionError)` guard the
version and permission boundaries.

Audit events recorded, carrying no raw PII and no secrets: `event_received`,
`event_duplicate`, `event_processed`, `event_dead_lettered`, `dlq_replay`,
`source_read`, `source_read_miss`, `source_version_rejected`,
`approval_token_issued` (digest only), `vault_review_task_created`,
`vault_review_task_denied`, `vault_draft_write`, `vault_draft_write_denied`,
`pv_case_submitted`, `pv_case_denied`.

## 6. Open questions for any real integration

Unanswerable from this side, and each one changes the design:

1. Which environments, versions, and licenses are in scope?
2. Which API delivers change events and permits re-reads, under what rate limits?
3. Which permission grants will the service run under, and at what object scope?
4. Does it execute inside the vault platform or as an external service?
5. Which call-report object and fields carry the narrative? Attachments?
6. Which content types and approval states are admissible evidence, and how are
   versions and effective dates modelled?
7. What is the sanctioned path for a safety signal to reach the safety system, who
   authorizes it, and what evidence is required first?
8. What delivery guarantees exist, and who owns DLQ monitoring and replay?
9. Data residency, cross-border transfer, and PHI handling approvals.
10. Which validation scope applies, and what evidence is required before
    production enablement?
