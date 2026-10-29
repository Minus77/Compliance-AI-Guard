"""Event envelopes, normalization, and processing errors."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field, ValidationError, field_validator

from compliance_guard.domain.models import DomainModel


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


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
