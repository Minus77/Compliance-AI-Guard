"""Privacy-minimized audit views for content checks and AI publications."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pydantic import Field, field_validator

from compliance_guard.domain.enums import Entrypoint
from compliance_guard.domain.models import DomainModel

if TYPE_CHECKING:
    from compliance_guard.workflow.checks import CheckResult


_WITHDRAWN_STATUSES = frozenset({"output_withdrawn", "failed_safe"})


def privacy_safe_audit_payload(
    check: CheckResult,
    entrypoint: Entrypoint,
    model_status: str | None = None,
) -> dict[str, object]:
    """Return the minimum audit evidence needed to explain one check.

    Narrative text, generated text, prompts, matched terms and token maps stay
    outside the ledger. Hashes and character spans retain enough provenance to
    identify the checked version without turning the append-only ledger into a
    second copy of sensitive source material.
    """
    derived_status = (
        "called" if check.model_called else "not_called"
    ) if model_status is None else model_status
    withdrawn = check.status in _WITHDRAWN_STATUSES
    error_category = None
    if check.status == "failed_safe":
        error_category = "output_guard_failed"
    elif check.status == "output_withdrawn":
        error_category = "policy_blocked_output"

    finding_details: list[dict[str, object]] = []
    for finding in check.findings:
        finding_details.append(
            {
                "finding_id": finding.finding_id,
                "type": finding.type,
                "severity": finding.severity.value,
                "decision": finding.decision.value,
                "rule_id": finding.rule_id,
                "rule_version": finding.rule_version,
                "category": finding.category,
                "spans": [
                    {
                        "start": span.start,
                        "end": span.end,
                        "quote_hash": span.quote_hash,
                    }
                    for span in finding.spans
                ],
                "allow_save": finding.allow_save,
                "allow_generate": finding.allow_generate,
                "allow_publish": finding.allow_publish,
            }
        )

    return {
        "check_id": check.check_id,
        "decision": check.decision.value,
        "severity": check.severity.value,
        "policy_version": check.policy_version,
        "content_sha256": check.content_version,
        "content_version": check.content_version,
        "entrypoint": entrypoint.value,
        "model_status": derived_status,
        "model_called": check.model_called,
        "status": check.status,
        "spans_stale": check.spans_stale,
        "masked_count": check.masked_count,
        "created_at": check.created_at.astimezone(UTC).isoformat(),
        "withdrawn": withdrawn,
        "error_category": error_category,
        "finding_details": finding_details,
    }


class Tombstone(DomainModel):
    """Minimal evidence that a governed record was deleted."""

    record_id: str = Field(min_length=1)
    original_hash: str = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=256)
    deleted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("deleted_at")
    @classmethod
    def _normalize_deleted_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


__all__ = ["Tombstone", "privacy_safe_audit_payload"]
