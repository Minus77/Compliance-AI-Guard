"""Candidate, server finding, and security finding contracts."""

from __future__ import annotations

from uuid import uuid4

from pydantic import Field

from .base import DomainModel
from .content_primitives import CharacterSpan
from .enums import Decision, Role, SecurityAction, Severity


class Finding(DomainModel):
    finding_id: str = Field(default_factory=lambda: f"finding-{uuid4().hex}")
    type: str
    severity: Severity
    decision: Decision
    confidence: float | None = Field(default=None, ge=0, le=1)
    reason: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    required_role: Role | None = None
    next_action: str | None = None
    evidence_gap: bool = False
    # Auditable rule provenance, surfaced so the UI can render a natural-language
    # explanation instead of echoing the internal reason string. Optional to keep
    # every existing construction site valid.
    rule_id: str | None = None
    matched_terms: list[str] = Field(default_factory=list)
    sla_label: str | None = None
    required_roles: list[Role] = Field(default_factory=list)
    spans: list[CharacterSpan] = Field(default_factory=list)
    rule_version: str = ""
    category: str = ""
    allow_save: bool = True
    allow_generate: bool = True
    allow_publish: bool = True
    notification_message: str = ""
    remediation_guidance: str = ""


class CandidateFinding(DomainModel):
    """Untrusted model candidate without server-owned risk or decision fields."""

    finding_id: str = Field(default_factory=lambda: f"candidate-{uuid4().hex}")
    type: str
    confidence: float | None = Field(default=None, ge=0, le=1)
    reason: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)


class SecurityFinding(DomainModel):
    finding_id: str = Field(
        default_factory=lambda: f"security-{uuid4().hex}",
        min_length=1,
        strict=True,
    )
    type: str = Field(min_length=1, strict=True)
    severity: Severity
    action: SecurityAction
    reason: str | None = None
    spans: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    evidence_gap: bool = Field(default=False, strict=True)
    blocked: bool = Field(default=True, strict=True)
