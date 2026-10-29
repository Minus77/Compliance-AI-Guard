"""Policy evaluation result contracts."""

from __future__ import annotations

from pydantic import Field

from compliance_guard.domain.enums import Decision, Role, Severity
from compliance_guard.domain.models import CharacterSpan, DomainModel, Finding

from .routing import ReviewPlan


class PolicyFinding(Finding):
    """A server-owned finding extended with the auditable rule and roles."""

    rule_id: str = ""
    required_roles: list[Role] = Field(default_factory=list)
    sla_label: str | None = None
    irreversible: bool = False
    spans: list[CharacterSpan] = Field(default_factory=list)
    rule_version: str = ""
    category: str = ""
    allow_save: bool = True
    allow_generate: bool = True
    allow_publish: bool = True
    notification_message: str = ""
    remediation_guidance: str = ""


class PolicyResult(DomainModel):
    decision: Decision
    severity: Severity
    findings: list[PolicyFinding] = Field(default_factory=list)
    policy_version: str
    reasons: list[str] = Field(default_factory=list)
    routing: ReviewPlan | None = None
    evidence_gap: bool = False
    rule_ids: list[str] = Field(default_factory=list)
    case_id: str = ""
    trace_id: str = ""
    content_version: str = ""


__all__ = ["PolicyFinding", "PolicyResult"]
