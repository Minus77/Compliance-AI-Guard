"""PV (Vault Safety / PV Signal) adapter contract mock.

Contract-only mock: no live Vault Safety/PV system, license, credential, or
network call is used. Source safety records are re-read through
:meth:`PvAdapter.get_current_record` with stale-version rejection, and case
submissions are approval-gated with role, purpose, source version, and an
idempotency key.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Callable

from pydantic import Field, field_validator

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.domain.models import DomainModel

from .veeva_adapter import (
    ApprovalDeniedError,
    ApprovalToken,
    ContentDraft,
    SourceRecord,
    SourceStoreMixin,
    StaleVersionError,
    WriteResult,
    validate_approval_token,
)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class PvCaseRecord(DomainModel):
    """A safety case envelope submitted to the (mock) PV system."""

    case_ref: str
    record_id: str
    source_version: str
    idempotency_key: str
    status: str = "submitted"
    safety_case_url: str = ""
    created_at: datetime

    _normalize_created_at = field_validator("created_at")(_utc)


class PvAdapter(SourceStoreMixin):
    """Vault Safety / PV approval-gated case submission contract."""

    def __init__(
        self,
        *,
        ledger: AuditLedger | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._init_store(ledger=ledger, now=now)
        self._cases: dict[tuple[str, str], PvCaseRecord] = {}

    def submit_safety_case(
        self,
        draft: ContentDraft,
        approval_token: ApprovalToken | None,
        idempotency_key: str,
    ) -> PvCaseRecord:
        """Submit a safety case to the mock PV system, gated by approval token."""
        if not idempotency_key:
            raise ValueError("idempotency key required")
        try:
            if approval_token is None:
                raise ApprovalDeniedError("approval token required")
            self.get_current_record(draft.record_id, version=draft.source_version)
            validate_approval_token(
                approval_token, now=self._clock, source_version=draft.source_version
            )
        except (ApprovalDeniedError, StaleVersionError) as exc:
            self._audit(
                "pv_case_denied",
                payload={
                    "record_id": draft.record_id,
                    "source_version": draft.source_version,
                    "reason": str(exc),
                },
            )
            raise
        key = (approval_token.tenant_id, idempotency_key)
        existing = self._cases.get(key)
        if existing is not None:
            return existing
        case = PvCaseRecord(
            case_ref=f"pv-{uuid.uuid4().hex}",
            record_id=draft.record_id,
            source_version=draft.source_version,
            idempotency_key=idempotency_key,
            status="submitted",
            safety_case_url=f"mock://safety/cases/{draft.record_id}",
            created_at=self._clock(),
        )
        self._cases[key] = case
        self._audit(
            "pv_case_submitted",
            payload={
                "case_ref": case.case_ref,
                "record_id": draft.record_id,
                "source_version": draft.source_version,
            },
        )
        return case

    def case_count(self) -> int:
        return len(self._cases)

    def submitted_cases(self) -> list[PvCaseRecord]:
        return list(self._cases.values())


__all__ = [
    "PvAdapter",
    "PvCaseRecord",
    "SourceRecord",
    "StaleVersionError",
    "WriteResult",
]
