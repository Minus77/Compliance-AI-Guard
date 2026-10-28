"""Privacy-minimized audit views never become a second copy of source text."""

import hashlib
import json
from datetime import UTC, datetime

import pytest

from compliance_guard.audit.ledger import AuditLedger, AuditWriteError
from compliance_guard.audit.privacy import Tombstone, privacy_safe_audit_payload
from compliance_guard.domain.enums import Decision, Entrypoint, Severity
from compliance_guard.domain.models import CharacterSpan
from compliance_guard.workflow.checks import CheckFinding, CheckResult


def _check_result(raw: str) -> CheckResult:
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    finding = CheckFinding(
        finding_id="finding-1",
        type="pii",
        severity=Severity.S2,
        decision=Decision.BLOCKED,
        rule_id="PII-001",
        rule_version="demo-v1",
        category="personal_data",
        matched_terms=[raw, "13800138000"],
        spans=[CharacterSpan(start=0, end=4, quote_hash="quote-hash")],
        allow_publish=False,
    )
    return CheckResult(
        check_id="check-1",
        decision=Decision.BLOCKED,
        severity=Severity.S2,
        findings=[finding],
        policy_version="demo-v1",
        content_version=digest,
        created_at=datetime(2026, 10, 28, tzinfo=UTC),
        safe_text=raw,
        masked_count=2,
        model_called=False,
        status="prechecked",
    )


def test_audit_payload_excludes_raw_text_and_tokens():
    payload = privacy_safe_audit_payload(
        _check_result(raw="患者李四电话13800138000"),
        entrypoint=Entrypoint.INPUT,
        model_status="not_called",
    )
    serialized = json.dumps(payload, ensure_ascii=False)

    assert "患者李四" not in serialized
    assert "13800138000" not in serialized
    assert "matched_terms" not in serialized
    assert payload["content_sha256"]
    assert payload["policy_version"] == "demo-v1"
    assert payload["finding_details"][0]["rule_version"] == "demo-v1"
    assert payload["entrypoint"] == "input"
    assert payload["finding_details"][0]["spans"] == [
        {"start": 0, "end": 4, "quote_hash": "quote-hash"}
    ]


def test_tombstone_records_hash_without_the_deleted_content(tmp_path):
    ledger = AuditLedger(path=tmp_path / "audit.jsonl")
    event = ledger.append_tombstone(
        Tombstone(
            record_id="record-123",
            original_hash="sha256:abc",
            reason="retention_expired",
            deleted_at=datetime(2026, 10, 28, tzinfo=UTC),
        )
    )

    assert event.event_type == "record_tombstone"
    assert event.payload["record_id"] == "record-123"
    assert event.payload["original_hash"] == "sha256:abc"
    assert event.payload["reason"] == "retention_expired"
    assert ledger.verify().ok is True


def test_failed_file_append_does_not_update_in_memory_history(tmp_path):
    ledger = AuditLedger(path=tmp_path / "audit.jsonl")
    original_path = ledger._path
    ledger._path = tmp_path / "is-a-directory"
    ledger._path.mkdir()

    with pytest.raises(AuditWriteError):
        ledger.append_tombstone(
            Tombstone(
                record_id="record-123",
                original_hash="sha256:abc",
                reason="retention_expired",
            )
        )

    assert ledger.count() == 0
    ledger._path = original_path
    assert ledger.verify().ok is True
