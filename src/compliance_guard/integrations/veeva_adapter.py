"""Veeva/Vault adapter contract mock: source re-read, approval-gated writes.

This is a contract-only mock. No live Veeva/Vault system, license, credential,
or network call is used; every returned reference is a ``mock://`` receipt.

Source records are held in an in-memory store and read back through
:meth:`VeevaAdapter.get_current_record`, which rejects stale event versions
instead of trusting the event payload. Event payloads are never authoritative.

Writes require a short-lived :class:`ApprovalToken` carrying role, purpose, and
source version, plus an explicit idempotency key. The Mock records an audit
event for every action and never performs a network call.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from pydantic import Field, field_validator

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import AuditEvent, DomainModel, ReviewTask


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def digest(value: str) -> str:
    """Stable SHA-256 hex digest used for deterministic external references."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def version_number(version: str) -> int:
    """Extract the leading integer from a version label (``"v3"`` -> 3)."""
    digits = "".join(ch for ch in version if ch.isdigit())
    return int(digits) if digits else 0


ALLOWED_WRITE_ROLES = frozenset(
    {
        Role.COMPLIANCE,
        Role.COMPLIANCE_ADMIN,
        Role.REVIEWER,
        Role.MEDICAL_REVIEWER,
        Role.PV_REVIEWER,
        Role.MEDICAL_REVIEW,
        Role.LEGAL,
    }
)

APPROVED_PURPOSES = frozenset(
    {"medcomms", "call_report", "safety_submission", "promotional", "review"}
)


class AdapterError(Exception):
    """Base class for adapter contract failures."""


class SourceNotFoundError(AdapterError, KeyError):
    """The requested source record is not present in the mock store."""


class StaleVersionError(AdapterError):
    """The event/draft version is older than the authoritative current version."""


class ApprovalDeniedError(AdapterError, PermissionError):
    """An approval-gated write was denied by token validation."""


class SourceRecord(DomainModel):
    """Authoritative source record re-read from the mock store."""

    record_id: str = Field(min_length=1, strict=True)
    version: str = Field(min_length=1, strict=True)
    source: str = Field(default="veeva_vault", min_length=1)
    event_type: str = ""
    tenant_id: str = ""
    market: str = ""
    product_id: str = ""
    content: str = ""
    summary: str = ""
    updated_at: datetime | None = None

    _normalize_updated_at = field_validator("updated_at")(_utc)


class ContentDraft(DomainModel):
    """An approved content draft ready to be written back to Vault."""

    record_id: str = Field(min_length=1, strict=True)
    source_version: str = Field(min_length=1, strict=True)
    tenant_id: str = Field(min_length=1, strict=True)
    market: str = ""
    product_id: str = ""
    content: str = Field(min_length=1)


class ApprovalToken(DomainModel):
    """Short-lived token granting one approval-gated write or task creation.

    Role, purpose, and source version are bound to the token at issuance and
    re-checked on every use; the token also carries an absolute expiry.
    """

    token: str = Field(min_length=1, strict=True)
    role: Role
    purpose: str = Field(min_length=1, strict=True)
    source_version: str = Field(min_length=1, strict=True)
    tenant_id: str = Field(min_length=1, strict=True)
    record_id: str | None = None
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime

    _normalize_issued_at = field_validator("issued_at")(_utc)
    _normalize_expires_at = field_validator("expires_at")(_utc)


class ExternalTaskRef(DomainModel):
    """Receipt for a review task created in the (mock) Vault."""

    external_task_id: str
    vault_url: str
    task_id: str
    case_id: str
    status: str = "created"
    created_at: datetime

    _normalize_created_at = field_validator("created_at")(_utc)


class WriteResult(DomainModel):
    """Receipt for an approval-gated draft write (never a network call)."""

    write_id: str
    record_id: str
    source_version: str
    idempotency_key: str
    status: str = "accepted"
    vault_document_url: str = ""
    created_at: datetime
    duplicate: bool = False

    _normalize_created_at = field_validator("created_at")(_utc)


def validate_approval_token(
    token: ApprovalToken | None,
    *,
    now: Callable[[], datetime],
    source_version: str | None = None,
) -> ApprovalToken:
    """Validate an approval token; raise :class:`ApprovalDeniedError` on denial.

    Enforces presence, expiry, allowed role, approved purpose, and (when
    supplied) source-version agreement.
    """
    if token is None or not isinstance(token, ApprovalToken):
        raise ApprovalDeniedError("approval token required")
    if now() > token.expires_at:
        raise ApprovalDeniedError("approval token expired")
    if token.role not in ALLOWED_WRITE_ROLES:
        raise ApprovalDeniedError(f"role {token.role.value!r} is not approved for writes")
    if token.purpose not in APPROVED_PURPOSES:
        raise ApprovalDeniedError(f"purpose {token.purpose!r} is not approved for writes")
    if source_version is not None and token.source_version != source_version:
        raise StaleVersionError(
            f"approval token source version {token.source_version!r} "
            f"does not match {source_version!r}"
        )
    return token


def deterministic_case_id(tenant_id: str, event_id: str) -> str:
    return f"CASE-{digest(f'{tenant_id}:{event_id}')[:12]}"


class SourceStoreMixin:
    """In-memory source record store with stale-version rejection and audit."""

    def _init_store(self, *, ledger: AuditLedger | None, now: Callable[[], datetime] | None) -> None:
        self._ledger = ledger
        self._now = now
        self._records: dict[str, SourceRecord] = {}
        self._tokens: dict[str, ApprovalToken] = {}

    def _clock(self) -> datetime:
        return self._now() if self._now is not None else datetime.now(UTC)

    def seed(self, record: SourceRecord) -> None:
        """Load an authoritative record into the mock store."""
        self._records[record.record_id] = record

    def get_current_record(self, record_id: str, version: str | None = None) -> SourceRecord:
        """Re-read the authoritative record; reject stale event versions.

        ``version`` is the version carried by an external event. When it is
        older than the store's current version the adapter refuses to trust it.
        """
        record = self._records.get(record_id)
        if record is None:
            self._audit(
                "source_read_miss", payload={"record_id": record_id}
            )
            raise SourceNotFoundError(f"no source record {record_id!r}")
        if version is not None and version_number(version) < version_number(record.version):
            self._audit(
                "source_version_rejected",
                payload={
                    "record_id": record_id,
                    "event_version": version,
                    "current_version": record.version,
                },
            )
            raise StaleVersionError(
                f"event version {version!r} is stale; current version is {record.version!r}"
            )
        self._audit(
            "source_read", payload={"record_id": record_id, "version": record.version}
        )
        return record

    def normalize_event(self, event: Any) -> SourceRecord:
        """Normalize an external envelope into a :class:`SourceRecord`.

        Details always come from the re-read authoritative record; the event
        payload is never authoritative.
        """
        return self.get_current_record(event.record_id, version=event.version)

    def issue_approval_token(
        self,
        *,
        role: Role,
        purpose: str,
        source_version: str,
        tenant_id: str,
        record_id: str | None = None,
        ttl_seconds: int = 300,
    ) -> ApprovalToken:
        """Issue a short-lived approval token bound to role/purpose/version."""
        issued = self._clock()
        token = ApprovalToken(
            token=f"at-{uuid.uuid4().hex}",
            role=role,
            purpose=purpose,
            source_version=source_version,
            tenant_id=tenant_id,
            record_id=record_id,
            issued_at=issued,
            expires_at=issued + timedelta(seconds=ttl_seconds),
        )
        self._tokens[token.token] = token
        self._audit(
            "approval_token_issued",
            payload={
                "token_digest": digest(token.token),
                "role": role.value,
                "purpose": purpose,
                "source_version": source_version,
            },
        )
        return token

    def _audit(
        self,
        event_type: str,
        *,
        case_id: str = "",
        trace_id: str = "",
        payload: dict[str, Any] | None = None,
    ) -> None:
        if self._ledger is None:
            return
        self._ledger.append(
            AuditEvent(
                event_id=f"audit-{uuid.uuid4().hex}",
                case_id=case_id,
                trace_id=trace_id,
                event_type=event_type,
                occurred_at=self._clock(),
                payload=payload or {},
            )
        )


class VeevaAdapter(SourceStoreMixin):
    """Veeva/Vault (CRM Call Report) read and approval-gated write contract."""

    def __init__(
        self,
        *,
        ledger: AuditLedger | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._init_store(ledger=ledger, now=now)
        self._tasks: dict[tuple[str, str], ExternalTaskRef] = {}
        self._writes: dict[tuple[str, str], WriteResult] = {}

    def handle_event(self, normalized: Any) -> str:
        """EventBus handler: normalize (re-read) then create one deterministic case."""
        self.normalize_event(normalized)
        return deterministic_case_id(normalized.tenant_id, normalized.event_id)

    def create_review_task_in_vault(
        self,
        task: ReviewTask,
        approval_token: ApprovalToken | None,
        idempotency_key: str | None = None,
    ) -> ExternalTaskRef:
        """Create a review task in the mock Vault, gated by an approval token.

        Mirrors the draft/safety-case write paths: the approval token's bound
        source version is re-read against the authoritative record, and stale
        versions are denied rather than trusted.
        """
        idem = idempotency_key or task.task_id
        if not idem:
            raise ValueError("idempotency key required")
        try:
            if approval_token is None:
                raise ApprovalDeniedError("approval token required")
            validate_approval_token(approval_token, now=self._clock)
            if approval_token.record_id is not None:
                self.get_current_record(
                    approval_token.record_id, version=approval_token.source_version
                )
        except (ApprovalDeniedError, StaleVersionError) as exc:
            self._audit(
                "vault_review_task_denied",
                case_id=task.case_id,
                trace_id=task.trace_id,
                payload={
                    "task_id": task.task_id,
                    "reason": str(exc),
                },
            )
            raise
        key = (approval_token.tenant_id, idem)
        existing = self._tasks.get(key)
        if existing is not None:
            return existing
        ref = ExternalTaskRef(
            external_task_id=f"vt-{digest(f'{approval_token.tenant_id}:{idem}')[:16]}",
            vault_url=(
                f"mock://vault/tasks/"
                f"{digest(f'{approval_token.tenant_id}:{idem}')[:16]}"
            ),
            task_id=task.task_id,
            case_id=task.case_id,
            status="created",
            created_at=self._clock(),
        )
        self._tasks[key] = ref
        self._audit(
            "vault_review_task_created",
            case_id=task.case_id,
            trace_id=task.trace_id,
            payload={
                "external_task_id": ref.external_task_id,
                "task_id": task.task_id,
            },
        )
        return ref

    def write_draft_after_approval(
        self,
        draft: ContentDraft,
        approval_token: ApprovalToken | None,
        idempotency_key: str,
    ) -> WriteResult:
        """Write an approved draft back to the mock Vault, idempotently."""
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
                "vault_draft_write_denied",
                payload={
                    "record_id": draft.record_id,
                    "source_version": draft.source_version,
                    "reason": str(exc),
                },
            )
            raise
        key = (approval_token.tenant_id, idempotency_key)
        existing = self._writes.get(key)
        if existing is not None:
            return existing
        result = WriteResult(
            write_id=f"wr-{uuid.uuid4().hex}",
            record_id=draft.record_id,
            source_version=draft.source_version,
            idempotency_key=idempotency_key,
            status="accepted",
            vault_document_url=f"mock://vault/documents/{draft.record_id}",
            created_at=self._clock(),
        )
        self._writes[key] = result
        self._audit(
            "vault_draft_write",
            payload={
                "write_id": result.write_id,
                "record_id": draft.record_id,
                "source_version": draft.source_version,
                "idempotency_key": idempotency_key,
            },
        )
        return result

    def write_count(self) -> int:
        return len(self._writes)

    def task_count(self) -> int:
        return len(self._tasks)

    def receipts(self) -> list[WriteResult]:
        return list(self._writes.values())


__all__ = [
    "ALLOWED_WRITE_ROLES",
    "APPROVED_PURPOSES",
    "AdapterError",
    "ApprovalDeniedError",
    "ApprovalToken",
    "ContentDraft",
    "ExternalTaskRef",
    "SourceNotFoundError",
    "SourceRecord",
    "SourceStoreMixin",
    "StaleVersionError",
    "VeevaAdapter",
    "WriteResult",
    "deterministic_case_id",
    "digest",
    "validate_approval_token",
    "version_number",
]
