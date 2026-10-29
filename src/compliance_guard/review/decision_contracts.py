"""Contracts for authorized review overrides."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import Field

from compliance_guard.audit.signature import ElectronicSignature
from compliance_guard.domain.models import Actor, DomainModel


class DecisionRecord(DomainModel):
    """Immutable record of one review override with before/after values."""

    record_id: str = Field(default_factory=lambda: f"decision-{uuid.uuid4().hex}")
    task_id: str
    case_id: str
    trace_id: str
    actor: Actor
    decision: str
    override_reason: str
    before_decision: str
    after_decision: str
    before_severity: str | None = None
    after_severity: str | None = None
    before_routing: list[str] = Field(default_factory=list)
    after_routing: list[str] = Field(default_factory=list)
    purpose: str = ""
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    audit_event_id: str = Field(default_factory=lambda: f"audit-{uuid.uuid4().hex}")
    # Part 11-style manifestation: signer, time, and meaning of the signing,
    # digest-bound to the decision content so tampering is detectable.
    signature: ElectronicSignature | None = None


__all__ = ["DecisionRecord"]
