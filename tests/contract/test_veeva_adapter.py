"""Veeva/Vault adapter contract: source re-read, stale-version rejection,
approval-gated writes, idempotency, and audit.

Covers the Task 7 adapter contracts:
- duplicate events create a single case through the adapter handler
- event payload is never authoritative; details come from ``get_current_record``
- stale event versions are rejected instead of trusted
- writes without an approval token are denied
- approval-gated writes require role, purpose, source version, and idempotency key
- audit events are recorded for each adapter action
- audit payloads never carry full approval tokens (digest only)
- review-task creation enforces source-version agreement like other write paths
"""

import json
import socket
from datetime import UTC, datetime, timedelta

import pytest

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import ReviewTask
from compliance_guard.integrations.event_bus import EventBus, ExternalEvent
from compliance_guard.integrations.veeva_adapter import (
    ApprovalToken,
    ContentDraft,
    ExternalTaskRef,
    SourceRecord,
    StaleVersionError,
    VeevaAdapter,
    WriteResult,
    digest,
)

FIXED_NOW = datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def ledger(tmp_path) -> AuditLedger:
    return AuditLedger(path=tmp_path / "adapter_audit.jsonl")


@pytest.fixture
def veeva_adapter(ledger) -> VeevaAdapter:
    return VeevaAdapter(ledger=ledger, now=lambda: FIXED_NOW)


@pytest.fixture
def seeded_adapter(veeva_adapter, current_record) -> VeevaAdapter:
    veeva_adapter.seed(current_record)
    return veeva_adapter


@pytest.fixture
def sample_event() -> ExternalEvent:
    return ExternalEvent(
        event_id="EVT-001",
        tenant_id="TENANT-CN",
        record_id="SR-001",
        version="v3",
        event_type="call_report",
        source="veeva_vault",
        received_at=FIXED_NOW,
        payload={
            "market": "CN",
            "product_id": "PRODUCT-001",
            "content": "untrusted payload content",
        },
    )


@pytest.fixture
def current_record() -> SourceRecord:
    return SourceRecord(
        record_id="SR-001",
        version="v3",
        source="veeva_vault",
        event_type="call_report",
        tenant_id="TENANT-CN",
        market="CN",
        product_id="PRODUCT-001",
        content="authoritative call report content",
        summary="Approved compliant call report",
        updated_at=FIXED_NOW,
    )


@pytest.fixture
def draft(current_record) -> ContentDraft:
    return ContentDraft(
        record_id=current_record.record_id,
        source_version=current_record.version,
        tenant_id=current_record.tenant_id,
        market=current_record.market,
        product_id=current_record.product_id,
        content="Approved compliant message draft",
    )


@pytest.fixture
def approval_token(veeva_adapter, current_record) -> ApprovalToken:
    return veeva_adapter.issue_approval_token(
        role=Role.COMPLIANCE,
        purpose="medcomms",
        source_version=current_record.version,
        tenant_id=current_record.tenant_id,
        record_id=current_record.record_id,
        ttl_seconds=300,
    )


def test_duplicate_event_creates_one_case(veeva_adapter, sample_event, current_record):
    veeva_adapter.seed(current_record)
    bus = EventBus(handler=veeva_adapter.handle_event)
    first = bus.receive_event(sample_event)
    second = bus.receive_event(sample_event)
    assert first.case_id == second.case_id
    assert bus.created_case_count(sample_event.event_id) == 1


def test_get_current_record_rejects_stale_version(veeva_adapter, current_record):
    veeva_adapter.seed(current_record)
    with pytest.raises(StaleVersionError):
        veeva_adapter.get_current_record(current_record.record_id, version="v2")
    fresh = veeva_adapter.get_current_record(current_record.record_id, version="v3")
    assert fresh.version == "v3"


def test_event_payload_is_never_authoritative(veeva_adapter, sample_event, current_record):
    veeva_adapter.seed(current_record)
    record = veeva_adapter.normalize_event(sample_event)
    assert record.content == current_record.content
    assert record.content != sample_event.payload.get("content")


def test_write_requires_approval_token(veeva_adapter, draft):
    with pytest.raises(PermissionError):
        veeva_adapter.write_draft_after_approval(
            draft, approval_token=None, idempotency_key="K-1"
        )


def test_write_rejects_expired_approval_token(seeded_adapter, draft, current_record):
    expired = ApprovalToken(
        token="at-expired",
        role=Role.COMPLIANCE,
        purpose="medcomms",
        source_version=current_record.version,
        tenant_id=current_record.tenant_id,
        record_id=current_record.record_id,
        issued_at=FIXED_NOW - timedelta(minutes=10),
        expires_at=FIXED_NOW - timedelta(minutes=5),
    )
    with pytest.raises(PermissionError):
        seeded_adapter.write_draft_after_approval(
            draft, approval_token=expired, idempotency_key="K-2"
        )


def test_write_requires_role(seeded_adapter, draft, current_record):
    token = seeded_adapter.issue_approval_token(
        role=Role.FIELD_REP,
        purpose="medcomms",
        source_version=current_record.version,
        tenant_id=current_record.tenant_id,
        record_id=current_record.record_id,
    )
    with pytest.raises(PermissionError):
        seeded_adapter.write_draft_after_approval(
            draft, approval_token=token, idempotency_key="K-3"
        )


def test_write_requires_purpose(seeded_adapter, draft, current_record):
    token = seeded_adapter.issue_approval_token(
        role=Role.COMPLIANCE,
        purpose="spam",
        source_version=current_record.version,
        tenant_id=current_record.tenant_id,
        record_id=current_record.record_id,
    )
    with pytest.raises(PermissionError):
        seeded_adapter.write_draft_after_approval(
            draft, approval_token=token, idempotency_key="K-4"
        )


def test_write_requires_source_version(seeded_adapter, draft, current_record):
    token = seeded_adapter.issue_approval_token(
        role=Role.COMPLIANCE,
        purpose="medcomms",
        source_version="v2",
        tenant_id=current_record.tenant_id,
        record_id=current_record.record_id,
    )
    with pytest.raises(StaleVersionError):
        seeded_adapter.write_draft_after_approval(
            draft, approval_token=token, idempotency_key="K-5"
        )


def test_write_rejects_stale_source_record(veeva_adapter, draft, approval_token, current_record):
    veeva_adapter.seed(current_record)
    stale_draft = draft.model_copy(update={"source_version": "v2"})
    with pytest.raises(StaleVersionError):
        veeva_adapter.write_draft_after_approval(
            stale_draft, approval_token=approval_token, idempotency_key="K-6"
        )


def test_write_requires_idempotency_key(veeva_adapter, draft, approval_token):
    with pytest.raises(ValueError):
        veeva_adapter.write_draft_after_approval(
            draft, approval_token=approval_token, idempotency_key=""
        )


def test_write_is_idempotent_by_key(seeded_adapter, draft, approval_token):
    first = seeded_adapter.write_draft_after_approval(
        draft, approval_token=approval_token, idempotency_key="K-10"
    )
    second = seeded_adapter.write_draft_after_approval(
        draft, approval_token=approval_token, idempotency_key="K-10"
    )
    assert isinstance(first, WriteResult)
    assert first.write_id == second.write_id
    assert first.status == "accepted"
    assert seeded_adapter.write_count() == 1


def test_create_review_task_requires_approval_token(veeva_adapter):
    task = ReviewTask(
        task_id="RT-1", case_id="CASE-1", trace_id="TR-1", required_role=Role.COMPLIANCE
    )
    with pytest.raises(PermissionError):
        veeva_adapter.create_review_task_in_vault(task, approval_token=None)


def test_create_review_task_rejects_stale_source_version(seeded_adapter, current_record):
    task = ReviewTask(
        task_id="RT-3", case_id="CASE-3", trace_id="TR-3", required_role=Role.COMPLIANCE
    )
    stale = seeded_adapter.issue_approval_token(
        role=Role.COMPLIANCE,
        purpose="medcomms",
        source_version="v2",
        tenant_id=current_record.tenant_id,
        record_id=current_record.record_id,
    )
    with pytest.raises(StaleVersionError):
        seeded_adapter.create_review_task_in_vault(
            task, approval_token=stale, idempotency_key="KT-2"
        )
    assert seeded_adapter.task_count() == 0


def test_create_review_task_accepts_current_source_version(seeded_adapter, approval_token):
    task = ReviewTask(
        task_id="RT-5", case_id="CASE-5", trace_id="TR-5", required_role=Role.COMPLIANCE
    )
    ref = seeded_adapter.create_review_task_in_vault(
        task, approval_token=approval_token, idempotency_key="KT-3"
    )
    assert ref.status == "created"
    assert seeded_adapter.task_count() == 1


def test_create_review_task_is_idempotent(seeded_adapter, approval_token):
    task = ReviewTask(
        task_id="RT-2", case_id="CASE-2", trace_id="TR-2", required_role=Role.COMPLIANCE
    )
    first = seeded_adapter.create_review_task_in_vault(
        task, approval_token=approval_token, idempotency_key="KT-1"
    )
    second = seeded_adapter.create_review_task_in_vault(
        task, approval_token=approval_token, idempotency_key="KT-1"
    )
    assert isinstance(first, ExternalTaskRef)
    assert first.external_task_id == second.external_task_id
    assert seeded_adapter.task_count() == 1


def test_adapter_never_performs_network_call(monkeypatch, seeded_adapter, draft, approval_token):
    def fail_network(*args, **kwargs):
        raise AssertionError("mock adapter must not open a network socket")

    monkeypatch.setattr(socket, "socket", fail_network)
    monkeypatch.setattr(socket, "create_connection", fail_network)

    result = seeded_adapter.write_draft_after_approval(
        draft, approval_token=approval_token, idempotency_key="K-20"
    )
    assert result.status == "accepted"


def test_adapter_records_audit_events(
    veeva_adapter, ledger, current_record, draft, approval_token
):
    veeva_adapter.seed(current_record)
    veeva_adapter.get_current_record(current_record.record_id, version=current_record.version)
    with pytest.raises(StaleVersionError):
        veeva_adapter.get_current_record(current_record.record_id, version="v1")
    veeva_adapter.write_draft_after_approval(
        draft, approval_token=approval_token, idempotency_key="K-30"
    )
    types = [event.event_type for event in ledger.all()]
    assert "source_read" in types
    assert "source_version_rejected" in types
    assert "vault_draft_write" in types
    assert "approval_token_issued" in types


def test_approval_token_audit_does_not_contain_full_token(
    veeva_adapter, ledger, current_record
):
    token = veeva_adapter.issue_approval_token(
        role=Role.COMPLIANCE,
        purpose="medcomms",
        source_version=current_record.version,
        tenant_id=current_record.tenant_id,
        record_id=current_record.record_id,
    )
    issued = [event for event in ledger.all() if event.event_type == "approval_token_issued"]
    assert issued
    raw = json.dumps([event.model_dump(mode="json") for event in issued])
    assert token.token not in raw
    assert all(token.token not in event.payload.values() for event in issued)
    for event in issued:
        assert event.payload.get("token_digest") == digest(token.token)
        assert event.payload.get("role") == Role.COMPLIANCE.value
        assert event.payload.get("purpose") == "medcomms"
        assert event.payload.get("source_version") == current_record.version


def test_denied_write_records_audit_event(veeva_adapter, ledger, draft):
    with pytest.raises(PermissionError):
        veeva_adapter.write_draft_after_approval(
            draft, approval_token=None, idempotency_key="K-40"
        )
    types = [event.event_type for event in ledger.all()]
    assert "vault_draft_write_denied" in types


def test_stale_version_write_denial_is_audited(seeded_adapter, ledger, draft, current_record):
    stale = seeded_adapter.issue_approval_token(
        role=Role.COMPLIANCE,
        purpose="medcomms",
        source_version="v2",
        tenant_id=current_record.tenant_id,
        record_id=current_record.record_id,
    )
    with pytest.raises(StaleVersionError):
        seeded_adapter.write_draft_after_approval(
            draft, approval_token=stale, idempotency_key="K-50"
        )
    types = [event.event_type for event in ledger.all()]
    assert "vault_draft_write_denied" in types


def test_create_review_task_denial_is_audited(seeded_adapter, ledger, current_record):
    task = ReviewTask(
        task_id="RT-4", case_id="CASE-4", trace_id="TR-4", required_role=Role.COMPLIANCE
    )
    stale = seeded_adapter.issue_approval_token(
        role=Role.COMPLIANCE,
        purpose="medcomms",
        source_version="v2",
        tenant_id=current_record.tenant_id,
        record_id=current_record.record_id,
    )
    with pytest.raises(StaleVersionError):
        seeded_adapter.create_review_task_in_vault(
            task, approval_token=stale, idempotency_key="KT-4"
        )
    types = [event.event_type for event in ledger.all()]
    assert "vault_review_task_denied" in types
