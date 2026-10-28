"""Idempotent in-memory safety intake with a durable pending boundary."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from compliance_guard.domain.enums import DataClass

from .contracts import (
    ConnectorInfo,
    HealthStatus,
    SafetyCandidate,
    SafetyReceipt,
)


class SafetyIntakeError(RuntimeError):
    """Safety intake is temporarily unavailable."""


@runtime_checkable
class SafetyIntake(Protocol):
    def submit(self, event: SafetyCandidate, idempotency_key: str) -> SafetyReceipt: ...


class InMemorySafetyIntake:
    """Reference intake that retains candidates until acceptance succeeds."""

    def __init__(
        self,
        *,
        connector_id: str = "safety_intake",
        label: str = "Reference safety intake",
    ) -> None:
        self._info = ConnectorInfo(
            connector_id=connector_id,
            connector_kind="safety_intake",
            label=label,
            description="Idempotent in-memory safety signal intake.",
            capabilities=["submit", "idempotency", "pending_retry"],
            data_classes=[
                DataClass.CONFIDENTIAL,
                DataClass.PII_TOKENIZED,
                DataClass.PHI_TOKENIZED,
            ],
            allowed_actions=["submit_safety_signal"],
        )
        self._pending: dict[str, SafetyCandidate] = {}
        self._receipts: dict[str, SafetyReceipt] = {}
        self._fail_next = 0

    @property
    def info(self) -> ConnectorInfo:
        return self._info.model_copy(deep=True)

    def fail_next(self, count: int = 1) -> None:
        """Simulate a transient downstream failure without losing the event."""
        if count < 1:
            raise ValueError("failure count must be at least 1")
        self._fail_next += count

    def submit(self, event: SafetyCandidate, idempotency_key: str) -> SafetyReceipt:
        key = idempotency_key.strip()
        if not key:
            raise ValueError("idempotency key required")
        existing = self._receipts.get(key)
        if existing is not None:
            return existing.model_copy(deep=True)

        # Persist locally before attempting the downstream call. A failed attempt
        # therefore remains available for retry instead of disappearing with the
        # original request.
        self._pending[key] = event.model_copy(deep=True)
        if self._fail_next:
            self._fail_next -= 1
            raise SafetyIntakeError("safety intake unavailable; event retained locally")

        receipt = SafetyReceipt(
            receipt_id=f"safety-{uuid.uuid4().hex}",
            record_id=event.record_id,
            version=event.version,
            idempotency_key=key,
            accepted_at=datetime.now(UTC),
        )
        self._receipts[key] = receipt
        self._pending.pop(key, None)
        return receipt.model_copy(deep=True)

    def pending_events(self) -> list[SafetyCandidate]:
        return [item.model_copy(deep=True) for item in self._pending.values()]

    def receipts(self) -> list[SafetyReceipt]:
        return [item.model_copy(deep=True) for item in self._receipts.values()]

    def health(self) -> HealthStatus:
        if self._fail_next:
            status, detail = "degraded", "simulated transient intake failure"
        else:
            status = "healthy"
            detail = f"{len(self._pending)} pending, {len(self._receipts)} accepted"
        return HealthStatus(
            connector_id=self._info.connector_id,
            status=status,
            detail=detail,
            checked_at=datetime.now(UTC),
        )


__all__ = ["InMemorySafetyIntake", "SafetyIntake", "SafetyIntakeError"]
