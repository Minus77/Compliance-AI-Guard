"""Deterministic severity aggregation: consequence and reversibility.

The highest severity dominates. Among findings at the same severity the most
restrictive decision and irreversibility break the tie for the audit basis.
S0 is reserved for death/life-threatening SAE, severe PII leaks, explicit
unapproved promotion, and approval-bypass events.
"""

from __future__ import annotations

from compliance_guard.domain.enums import Decision, Severity
from compliance_guard.domain.models import DomainModel

_SEVERITY_RANK = {
    Severity.S0: 0,
    Severity.S1: 1,
    Severity.S2: 2,
    Severity.S3: 3,
}
_DECISION_RANK = {
    Decision.BLOCKED: 0,
    Decision.REFUSED: 1,
    Decision.HUMAN_REVIEW: 2,
    Decision.NEEDS_INFO: 3,
    Decision.ALLOW: 4,
}


class SeverityResult(DomainModel):
    severity: Severity
    basis: str
    driving_rule_ids: list[str]
    irreversible: bool = False


def calculate_severity(findings) -> SeverityResult:
    """Aggregate finding severities; the highest severity dominates."""
    if not findings:
        return SeverityResult(
            severity=Severity.S3,
            basis="no findings; default low-risk severity",
            driving_rule_ids=[],
            irreversible=False,
        )

    highest = min(findings, key=lambda finding: _SEVERITY_RANK[finding.severity])
    drivers = [finding for finding in findings if finding.severity == highest.severity]
    blocking = min(drivers, key=lambda finding: _DECISION_RANK[finding.decision])
    irreversible = any(getattr(driver, "irreversible", False) for driver in drivers)

    basis = (
        f"highest severity {highest.severity.value} dominates; "
        f"driven by {','.join(getattr(driver, 'rule_id', '?') for driver in drivers)}; "
        f"blocking decision {blocking.decision.value}"
    )
    return SeverityResult(
        severity=highest.severity,
        basis=basis,
        driving_rule_ids=[getattr(driver, "rule_id", "") for driver in drivers],
        irreversible=irreversible,
    )


__all__ = ["SeverityResult", "calculate_severity"]
