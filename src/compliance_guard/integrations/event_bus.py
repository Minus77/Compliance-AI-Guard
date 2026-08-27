"""Idempotent integration event bus with a dead-letter queue.

The event bus sits at the external integration boundary. External systems
deliver a lightweight change notification (``ExternalEvent``) that carries only
an event id and a record reference - never authoritative content. The envelope
is normalized into a :class:`NormalizedEvent` via ``receive_event``, and
:class:`EventBus.receive_event` applies a single idempotent processing pass.

Idempotency: an in-memory processed-event index keyed by ``(tenant_id,
event_id)`` records the first successful normalization case. Duplicate events
return the original normalized case and never re-apply side effects (case
creation or review-task creation).

Failures: non-retryable schema or permission errors are routed to the dead
letter queue (DLQ) with ``next_action="manual_review"``. Retryable errors are
also placed on the DLQ but carry an ``attempt_count`` and
``next_action="retry"`` until attempts are exhausted, after which the next
action becomes ``manual_review``. ``replay_dlq`` re-runs dead-lettered events;
a successful replay applies side effects exactly once.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any, Callable

from pydantic import Field, ValidationError, field_validator

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import AuditEvent, DomainModel, ReviewTask

_REVIEW_EVENT_TYPES = frozenset({"adverse_event", "safety_signal", "call_report"})
_REVIEW_ROLE_BY_TYPE = {
    "adverse_event": Role.PHARMACOVIGILANCE,
    "safety_signal": Role.PV_REVIEWER,
    "call_report": Role.COMPLIANCE,
}

EventHandler = Callable[[Any], str | None]


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _deterministic_case_id(tenant_id: str, event_id: str) -> str:
    return f"CASE-{_digest(f'{tenant_id}:{event_id}')[:12]}"


def _best_effort(data: dict[str, Any], key: str) -> Any:
    return data.get(key)


class EventProcessingError(Exception):
    """Base class for processing failures routed by the event bus."""

    retryable: bool = False


class RetryableProcessingError(EventProcessingError):
    """A transient failure that may succeed when retried (provider, timeout)."""

    retryable = True


class NonRetryableProcessingError(EventProcessingError):
    """A permanent failure that must not be retried automatically."""

    retryable = False


class SchemaError(NonRetryableProcessingError):
    """Event envelope failed normalization; carries best-effort routing keys."""

    def __init__(
        self,
        message: str = "event schema validation failed",
        *,
        event_id: str | None = None,
        tenant_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.event_id = event_id
        self.tenant_id = tenant_id


class ExternalEvent(DomainModel):
    """Lightweight external change notification; payload is never authoritative."""

    event_id: str = Field(min_length=1, strict=True)
    tenant_id: str = Field(min_length=1, strict=True)
    record_id: str = ""
    version: str = ""
    event_type: str = ""
    source: str = ""
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, Any] = Field(default_factory=dict)

    _normalize_received_at = field_validator("received_at")(_utc)


class NormalizedEvent(DomainModel):
    """Canonical event after normalization; details are re-read, not trusted."""

    event_id: str = Field(min_length=1, strict=True)
    tenant_id: str = Field(min_length=1, strict=True)
    record_id: str = ""
    version: str = ""
    event_type: str = ""
    source: str = ""
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, Any] = Field(default_factory=dict)
    case_id: str | None = None
    processed_at: datetime | None = None
    trace_id: str | None = None
    idempotency_key: str = ""

    _normalize_received_at = field_validator("received_at")(_utc)
    _normalize_processed_at = field_validator("processed_at")(_utc)


class DeadLetterRecord(DomainModel):
    """A failed event parked on the dead letter queue."""

    record_id: str
    tenant_id: str
    event_id: str
    event: NormalizedEvent | None = None
    error_type: str
    error_message: str
    retryable: bool = False
    attempt_count: int = Field(default=1, ge=1)
    next_action: str = "manual_review"
    last_attempt_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    _normalize_last_attempt_at = field_validator("last_attempt_at")(_utc)


def receive_event(envelope: ExternalEvent | dict[str, Any]) -> NormalizedEvent:
    """Normalize an external envelope into a :class:`NormalizedEvent`.

    Raises :class:`SchemaError` when the envelope cannot be normalized.
    """
    if isinstance(envelope, ExternalEvent):
        data = envelope.model_dump()
    elif isinstance(envelope, dict):
        data = dict(envelope)
    else:
        raise SchemaError(
            "envelope must be ExternalEvent or dict",
            event_id=getattr(envelope, "event_id", None),
            tenant_id=getattr(envelope, "tenant_id", None),
        )
    try:
        normalized = NormalizedEvent(**data)
    except ValidationError as exc:
        raise SchemaError(
            str(exc),
            event_id=_best_effort(data, "event_id"),
            tenant_id=_best_effort(data, "tenant_id"),
        ) from exc
    normalized.idempotency_key = f"{normalized.tenant_id}:{normalized.event_id}"
    return normalized


class EventBus:
    """In-memory idempotent event bus with dedup, DLQ routing, and replay."""

    def __init__(
        self,
        *,
        handler: EventHandler | None = None,
        ledger: AuditLedger | None = None,
        now: Callable[[], datetime] | None = None,
        max_attempts: int = 3,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._handler = handler or self._default_handler
        self._ledger = ledger
        self._now = now
        self._max_attempts = max_attempts
        self._processed: dict[tuple[str, str], NormalizedEvent] = {}
        self._dlq: dict[tuple[str, str], DeadLetterRecord] = {}
        self._case_counts: dict[tuple[str, str], int] = {}
        self._review_tasks: dict[tuple[str, str], ReviewTask] = {}

    def _clock(self) -> datetime:
        return self._now() if self._now is not None else datetime.now(UTC)

    @staticmethod
    def _default_handler(normalized: NormalizedEvent) -> str:
        """Deterministic mock case creation; adapters provide the real one."""
        return _deterministic_case_id(normalized.tenant_id, normalized.event_id)

    # -- public API ------------------------------------------------------------

    def receive_event(self, envelope: ExternalEvent | dict[str, Any]) -> NormalizedEvent:
        """Normalize, deduplicate, process, or dead-letter one event."""
        try:
            normalized = receive_event(envelope)
        except SchemaError as exc:
            placeholder = self._placeholder(exc)
            self._dead_letter(
                placeholder,
                key=(placeholder.tenant_id, placeholder.event_id),
                exc=exc,
                retryable=False,
            )
            return placeholder
        key = (normalized.tenant_id, normalized.event_id)
        existing = self._processed.get(key)
        if existing is not None:
            self._audit(
                "event_duplicate",
                case_id=existing.case_id or "",
                trace_id=existing.trace_id or "",
                payload={"event_id": existing.event_id},
            )
            return existing
        parked = self._dlq.get(key)
        if parked is not None and (not parked.retryable or parked.attempt_count >= self._max_attempts):
            return normalized
        self._audit(
            "event_received",
            case_id="",
            trace_id=normalized.trace_id or "",
            payload={"event_id": normalized.event_id, "event_type": normalized.event_type},
        )
        try:
            case_id = self._handler(normalized)
        except RetryableProcessingError as exc:
            self._dead_letter(normalized, key=key, exc=exc, retryable=True)
            return normalized
        except (NonRetryableProcessingError, PermissionError) as exc:
            self._dead_letter(normalized, key=key, exc=exc, retryable=False)
            return normalized
        self._commit(normalized, case_id)
        return normalized

    def created_case_count(self, event_id: str, tenant_id: str | None = None) -> int:
        """Number of cases created for an event id; never more than one per tenant."""
        if tenant_id is not None:
            return self._case_counts.get((tenant_id, event_id), 0)
        return sum(count for (tid, eid), count in self._case_counts.items() if eid == event_id)

    def review_tasks_for_event(self, event_id: str, tenant_id: str | None = None) -> list[ReviewTask]:
        if tenant_id is not None:
            task = self._review_tasks.get((tenant_id, event_id))
            return [task] if task is not None else []
        return [task for (tid, eid), task in self._review_tasks.items() if eid == event_id]

    def review_task_count(self, event_id: str, tenant_id: str | None = None) -> int:
        if tenant_id is not None:
            return 1 if (tenant_id, event_id) in self._review_tasks else 0
        return sum(1 for (tid, eid) in self._review_tasks if eid == event_id)

    def processed(self) -> list[NormalizedEvent]:
        return list(self._processed.values())

    def read_dlq(self) -> list[DeadLetterRecord]:
        """Return all dead-lettered records for inspection."""
        return list(self._dlq.values())

    def replay_dlq(self, record_id: str | None = None) -> list[NormalizedEvent]:
        """Replay one or all dead-lettered events; side effects apply at most once."""
        records = self._select_dlq(record_id)
        replayed: list[NormalizedEvent] = []
        for record in records:
            if record.event is None:
                record.next_action = "manual_review"
                continue
            if record.error_type == "SchemaError":
                record.next_action = "manual_review"
                continue
            key = (record.tenant_id, record.event_id)
            if key in self._processed:
                self._dlq.pop(key, None)
                replayed.append(self._processed[key])
                continue
            if record.attempt_count >= self._max_attempts:
                record.next_action = "manual_review"
                continue
            try:
                case_id = self._handler(record.event)
            except RetryableProcessingError as exc:
                self._record_failure(record, exc, retryable=True)
                continue
            except (NonRetryableProcessingError, PermissionError) as exc:
                self._record_failure(record, exc, retryable=False)
                continue
            self._commit(record.event, case_id)
            self._audit(
                "dlq_replay",
                case_id=record.event.case_id or "",
                trace_id=record.event.trace_id or "",
                payload={"event_id": record.event.event_id},
            )
            replayed.append(record.event)
        return replayed

    # -- internals -------------------------------------------------------------

    def _placeholder(self, exc: SchemaError) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=exc.event_id or "unknown",
            tenant_id=exc.tenant_id or "unknown",
            record_id="",
            version="",
            event_type="",
            source="",
            received_at=self._clock(),
        )

    def _commit(self, normalized: NormalizedEvent, case_id: str | None) -> NormalizedEvent:
        normalized.case_id = case_id
        normalized.processed_at = self._clock()
        key = (normalized.tenant_id, normalized.event_id)
        self._processed[key] = normalized
        self._dlq.pop(key, None)
        self._case_counts[(normalized.tenant_id, normalized.event_id)] = (
            self._case_counts.get((normalized.tenant_id, normalized.event_id), 0) + 1
        )
        if normalized.event_type in _REVIEW_EVENT_TYPES:
            self._review_tasks[(normalized.tenant_id, normalized.event_id)] = self._build_review_task(
                normalized
            )
        self._audit(
            "event_processed",
            case_id=normalized.case_id or "",
            trace_id=normalized.trace_id or "",
            payload={"event_id": normalized.event_id, "case_id": normalized.case_id},
        )
        return normalized

    def _build_review_task(self, normalized: NormalizedEvent) -> ReviewTask:
        return ReviewTask(
            task_id=f"review-{_digest(f'{normalized.tenant_id}:{normalized.event_id}')[:12]}",
            case_id=normalized.case_id or "",
            trace_id=normalized.trace_id or f"trace-{normalized.event_id}",
            required_role=_REVIEW_ROLE_BY_TYPE.get(normalized.event_type, Role.REVIEWER),
            finding_ids=[],
            created_at=self._clock(),
            market=normalized.payload.get("market"),
            sla_label="24h",
        )

    def _dead_letter(
        self,
        normalized: NormalizedEvent,
        *,
        key: tuple[str, str],
        exc: Exception,
        retryable: bool,
    ) -> None:
        now = self._clock()
        existing = self._dlq.get(key)
        if existing is not None:
            existing.event = normalized
            existing.error_type = type(exc).__name__
            existing.error_message = str(exc)
            existing.retryable = retryable
            existing.attempt_count += 1
            existing.last_attempt_at = now
            existing.next_action = (
                "retry" if retryable and existing.attempt_count < self._max_attempts else "manual_review"
            )
        else:
            existing = DeadLetterRecord(
                record_id=f"dlq-{uuid.uuid4().hex}",
                tenant_id=normalized.tenant_id,
                event_id=normalized.event_id,
                event=normalized,
                error_type=type(exc).__name__,
                error_message=str(exc),
                retryable=retryable,
                attempt_count=1,
                next_action="retry" if retryable else "manual_review",
                last_attempt_at=now,
            )
            self._dlq[key] = existing
        self._audit(
            "event_dead_lettered",
            case_id=normalized.case_id or "",
            trace_id=normalized.trace_id or "",
            payload={
                "event_id": normalized.event_id,
                "error_type": type(exc).__name__,
                "retryable": retryable,
                "attempt_count": existing.attempt_count,
                "next_action": existing.next_action,
            },
        )

    def _record_failure(self, record: DeadLetterRecord, exc: Exception, *, retryable: bool) -> None:
        record.attempt_count += 1
        record.error_type = type(exc).__name__
        record.error_message = str(exc)
        record.retryable = retryable
        record.last_attempt_at = self._clock()
        record.next_action = (
            "retry" if retryable and record.attempt_count < self._max_attempts else "manual_review"
        )
        self._audit(
            "event_dead_lettered",
            case_id=record.event.case_id or "" if record.event is not None else "",
            trace_id=record.event.trace_id or "" if record.event is not None else "",
            payload={
                "event_id": record.event_id,
                "error_type": type(exc).__name__,
                "retryable": retryable,
                "attempt_count": record.attempt_count,
                "next_action": record.next_action,
            },
        )

    def _select_dlq(self, record_id: str | None) -> list[DeadLetterRecord]:
        if record_id is None:
            return list(self._dlq.values())
        for record in self._dlq.values():
            if record.record_id == record_id:
                return [record]
        raise KeyError(f"no dead letter record with id {record_id!r}")

    def _audit(self, event_type: str, *, case_id: str, trace_id: str, payload: dict) -> None:
        if self._ledger is None:
            return
        self._ledger.append(
            AuditEvent(
                event_id=f"audit-{uuid.uuid4().hex}",
                case_id=case_id,
                trace_id=trace_id,
                event_type=event_type,
                occurred_at=self._clock(),
                payload=payload,
            )
        )


__all__ = [
    "DeadLetterRecord",
    "EventBus",
    "EventHandler",
    "EventProcessingError",
    "ExternalEvent",
    "NonRetryableProcessingError",
    "NormalizedEvent",
    "RetryableProcessingError",
    "SchemaError",
    "receive_event",
]
