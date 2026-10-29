"""Case lifecycle, extraction, review, audit, and tracing contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import AliasChoices, Field, field_validator

from .base import DomainModel, _contains_reserved_model_field, _utc
from .content import CandidateFinding, Entity
from .enums import (
    CaseState,
    ContentType,
    Decision,
    ReviewTaskStatus,
    Role,
    Severity,
    SpanStatus,
    normalize_content_type,
)


class CaseContext(DomainModel):
    case_id: str
    trace_id: str
    tenant_id: str
    market: str
    language: str
    product_id: str
    channel: str
    actor: Actor | None = None
    source: str | None = None
    source_version: str | None = None
    content_type: ContentType | None = None
    content_version: str = ""
    therapeutic_area: str | None = None
    policy_version: str | None = None
    knowledge_snapshot_id: str | None = None

    @field_validator("content_type", mode="before")
    @classmethod
    def _normalize_content_type(cls, value: Any) -> Any:
        if value is None or isinstance(value, ContentType):
            return value
        return normalize_content_type(str(value))


class ExtractedData(DomainModel):
    """Candidate extraction; final decisions stay on CheckCaseResponse."""

    entities: list[Entity] = Field(default_factory=list)
    findings: list[CandidateFinding] = Field(
        default_factory=list,
        validation_alias=AliasChoices("findings", "candidate_findings"),
    )
    extracted_fields: dict[str, Any] = Field(default_factory=dict)
    # Client declarations. Useful for prefilling forms and for cross-checking the
    # narrative, but never an input to the decision: content that can vouch for
    # itself is content that can wave itself through (defect P-1).
    claimed_fields: dict[str, Any] = Field(default_factory=dict)
    # Server-derived facts. The only fields judgment reads.
    resolved_fields: dict[str, Any] = Field(default_factory=dict)
    field_discrepancies: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)

    @field_validator("extracted_fields", "claimed_fields", "resolved_fields")
    @classmethod
    def _reject_server_controlled_fields(cls, value: dict[str, Any]) -> dict[str, Any]:
        if _contains_reserved_model_field(value):
            raise ValueError("model candidates cannot set server-controlled fields")
        return value

    @property
    def decision_fields(self) -> dict[str, Any]:
        """Fields the policy layer is allowed to judge on.

        ``resolved_fields`` when the server derived anything, otherwise the
        extractor's candidates. Client claims never appear here.
        """
        return self.resolved_fields or self.extracted_fields


class KnowledgeFilter(DomainModel):
    tenant_id: str
    market: str
    product_id: str
    language: str
    as_of: datetime | None = Field(
        default=None,
        validation_alias=AliasChoices("as_of", "effective_at"),
    )
    purpose: str
    access_scope: list[str] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list)

    _normalize_as_of = field_validator("as_of")(_utc)


class Actor(DomainModel):
    actor_id: str
    role: Role
    tenant_id: str | None = None
    actor_type: str = "human"


class ReviewTask(DomainModel):
    task_id: str = Field(default_factory=lambda: f"review-{uuid4().hex}")
    case_id: str
    trace_id: str
    required_role: Role
    status: ReviewTaskStatus = ReviewTaskStatus.PENDING
    finding_ids: list[str] = Field(default_factory=list)
    decision: Decision | None = None
    reason: str | None = None
    actor: Actor | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None
    severity: Severity | None = None
    sla_label: str = "24h"
    sla_deadline: datetime | None = None
    market: str | None = None
    system_decision: Decision | None = None

    _normalize_created_at = field_validator("created_at")(_utc)
    _normalize_completed_at = field_validator("completed_at")(_utc)
    _normalize_sla_deadline = field_validator("sla_deadline")(_utc)


class AuditEvent(DomainModel):
    event_id: str
    case_id: str
    trace_id: str
    event_type: str
    occurred_at: datetime
    from_state: CaseState | None = None
    to_state: CaseState | None = None
    actor: Actor | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    configuration_versions: dict[str, str] = Field(default_factory=dict)
    # Tamper-evidence fields, assigned by the ledger on append. Append-only says
    # the program does not rewrite records; the chain is what makes an outside
    # edit detectable (21 CFR Part 11 §11.10(e)).
    seq: int = 0
    prev_hash: str = ""
    entry_hash: str = ""

    _normalize_occurred_at = field_validator("occurred_at")(_utc)

    def chain_body(self) -> dict[str, Any]:
        """The event body the digest covers, excluding the digest itself."""
        body = self.model_dump(mode="json")
        body.pop("entry_hash", None)
        return body


class TraceSpan(DomainModel):
    span_id: str
    trace_id: str
    case_id: str
    operation: str
    status: SpanStatus = SpanStatus.OK
    started_at: datetime
    ended_at: datetime | None = None
    parent_span_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    _normalize_started_at = field_validator("started_at")(_utc)
    _normalize_ended_at = field_validator("ended_at")(_utc)
