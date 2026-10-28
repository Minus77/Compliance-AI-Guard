"""Review RACI: deterministic role and SLA routing for policy findings.

The model cannot change a route or its severity. Every review plan records the
rule IDs, required roles, SLA label, and next actions that produced it.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from compliance_guard.domain.enums import Role, Severity
from compliance_guard.domain.models import DomainModel, ReviewTask

ROUTE_VERSION = "routing-v1"

_SLA_RANK = {"immediate": 0, "4h": 1, "8h": 2, "24h": 3, "72h": 4}


class RaciEntry(DomainModel):
    severity: Severity | None = None
    categories: list[str] = Field(default_factory=list)
    roles: list[Role] = Field(default_factory=list)
    sla_label: str = "24h"
    next_actions: list[str] = Field(default_factory=list)
    responsibility: str = "R"


class RaciMatrix(DomainModel):
    entries: list[RaciEntry] = Field(default_factory=list)
    fallback: RaciEntry = Field(
        default_factory=lambda: RaciEntry(
            roles=[Role.REVIEWER],
            sla_label="72h",
            next_actions=["low-risk guidance"],
        )
    )

    def resolve(self, finding: Any) -> RaciEntry:
        """Pick the entry for a finding: category match wins over severity."""
        for entry in self.entries:
            if finding.type in entry.categories:
                return entry
        for entry in self.entries:
            if entry.severity is not None and entry.severity == finding.severity:
                return entry
        return self.fallback

    def roles_for_severity(self, severity: Severity) -> list[Role]:
        for entry in self.entries:
            if entry.severity == severity and not entry.categories:
                return entry.roles
        return self.fallback.roles


class ReviewPlan(DomainModel):
    review_tasks: list[ReviewTask] = Field(default_factory=list)
    required_roles: list[Role] = Field(default_factory=list)
    sla_label: str = "24h"
    next_actions: list[str] = Field(default_factory=list)
    routing_basis: str = ""
    route_version: str = ROUTE_VERSION
    immutable: bool = True


def default_raci() -> RaciMatrix:
    """The code-controlled default RACI for the China content demo."""
    return RaciMatrix(
        entries=[
            RaciEntry(
                severity=Severity.S0,
                roles=[Role.PHARMACOVIGILANCE, Role.MEDICAL_REVIEW],
                sla_label="4h",
                next_actions=["immediate PV intake", "medical review"],
            ),
            RaciEntry(
                categories=["serious_adverse_event"],
                roles=[Role.PHARMACOVIGILANCE, Role.MEDICAL_REVIEW],
                sla_label="4h",
                next_actions=["immediate PV intake", "medical review"],
            ),
            RaciEntry(
                categories=["potential_adverse_event"],
                roles=[Role.PHARMACOVIGILANCE, Role.MEDICAL_REVIEW],
                sla_label="8h",
                next_actions=["PV intake", "medical review"],
            ),
            RaciEntry(
                categories=["bribery_or_inducement"],
                roles=[Role.COMPLIANCE, Role.LEGAL],
                sla_label="8h",
                next_actions=["compliance and regulatory review"],
            ),
            RaciEntry(
                categories=["unapproved_promotion"],
                roles=[Role.COMPLIANCE, Role.LEGAL],
                sla_label="4h",
                next_actions=["compliance and regulatory review"],
            ),
            RaciEntry(
                categories=["off_label"],
                roles=[Role.COMPLIANCE, Role.MEDICAL_REVIEW],
                sla_label="8h",
                next_actions=["label comparison review"],
            ),
            RaciEntry(
                categories=["comparative_claim"],
                roles=[Role.COMPLIANCE, Role.MEDICAL_REVIEW],
                sla_label="8h",
                next_actions=["comparison context substantiation"],
            ),
            RaciEntry(
                categories=["evidence_conflict"],
                roles=[Role.COMPLIANCE, Role.MEDICAL_REVIEW],
                sla_label="8h",
                next_actions=["resolve evidence conflict"],
            ),
            RaciEntry(
                categories=["pii", "phi"],
                roles=[Role.SECURITY],
                sla_label="8h",
                next_actions=["privacy review", "redaction check"],
            ),
            RaciEntry(
                categories=["severe_pii_leak"],
                roles=[Role.SECURITY],
                sla_label="immediate",
                next_actions=["block and escalate as data breach"],
            ),
            RaciEntry(
                categories=["prompt_injection"],
                roles=[Role.SECURITY],
                sla_label="immediate",
                next_actions=["block and escalate to security"],
            ),
            RaciEntry(
                categories=["permission_failure", "security_issue"],
                roles=[Role.SECURITY],
                sla_label="8h",
                next_actions=["security review"],
            ),
            RaciEntry(
                categories=["irreversible_write"],
                roles=[Role.ADMIN],
                sla_label="immediate",
                next_actions=["admin approval review"],
            ),
            RaciEntry(
                categories=["missing_evidence", "expired_evidence"],
                roles=[Role.REPRESENTATIVE, Role.MEDICAL_REVIEW],
                sla_label="24h",
                next_actions=["business clarification", "professional review"],
            ),
            RaciEntry(
                categories=["missing_context"],
                roles=[Role.REVIEWER],
                sla_label="24h",
                next_actions=["request missing context"],
            ),
            RaciEntry(
                severity=Severity.S1,
                roles=[Role.COMPLIANCE, Role.MEDICAL_REVIEW],
                sla_label="8h",
                next_actions=["compliance review"],
            ),
            RaciEntry(
                severity=Severity.S2,
                roles=[Role.REVIEWER],
                sla_label="24h",
                next_actions=["review and clarify"],
            ),
            RaciEntry(
                severity=Severity.S3,
                roles=[Role.REVIEWER],
                sla_label="72h",
                next_actions=["low-risk guidance"],
            ),
        ]
    )


def route_review(policy_result: Any, raci: RaciMatrix | None = None, route_version: str = ROUTE_VERSION) -> ReviewPlan:
    """Build the immutable ReviewPlan for a PolicyResult using a RACI matrix."""
    matrix = raci if raci is not None and raci.entries else default_raci()

    roles: list[Role] = []
    actions: list[str] = []
    basis: list[str] = []
    sla_rank = 10**9
    sla_label = ""
    role_findings: dict[Role, list[str]] = {}

    for finding in policy_result.findings:
        entry = matrix.resolve(finding)
        for role in entry.roles:
            if role not in roles:
                roles.append(role)
            role_findings.setdefault(role, []).append(finding.finding_id)
        for action in entry.next_actions:
            if action not in actions:
                actions.append(action)
        rank = _SLA_RANK.get(entry.sla_label, len(_SLA_RANK) + 1)
        if rank < sla_rank:
            sla_rank = rank
            sla_label = entry.sla_label
        basis.append(
            f"{finding.rule_id} ({finding.type}, {finding.severity.value}) -> "
            f"{','.join(role.value for role in entry.roles)}"
        )

    tasks = [
        ReviewTask(
            case_id=policy_result.case_id,
            trace_id=policy_result.trace_id,
            required_role=role,
            finding_ids=role_findings[role],
        )
        for role in roles
    ]

    return ReviewPlan(
        review_tasks=tasks,
        required_roles=roles,
        sla_label=sla_label or "72h",
        next_actions=actions,
        routing_basis="; ".join(basis),
        route_version=route_version,
        immutable=True,
    )


__all__ = [
    "RaciEntry",
    "RaciMatrix",
    "ReviewPlan",
    "ROUTE_VERSION",
    "default_raci",
    "route_review",
]
