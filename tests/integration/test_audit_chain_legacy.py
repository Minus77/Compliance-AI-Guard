"""Verification must tell "written before the chain existed" from "tampered".

Found by running the real server: the repository's ledger holds 4,255 entries
written before the hash chain was introduced, so entry 1 carries no digest and
verification reported ``ok: false, first_broken_seq: 1``.

That is the wrong answer, and specifically the wrong *kind* of wrong. An integrity
check that cries tampering over a benign upgrade gets ignored within a week, and
then it is not an integrity check at all. It also overstates what the chain can
prove: it can only attest to entries created after it was turned on, and saying
otherwise would be a false assurance in the one place assurances must be exact.

So leading un-chained entries are reported as ``legacy_entries`` — counted and
named, never silently skipped — and the chain is verified from the first entry
that carries a digest. A legacy-shaped entry appearing *after* chained ones is
still a break, because that is what an insertion would look like.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.domain.models import AuditEvent


def _event(index: int) -> AuditEvent:
    return AuditEvent(
        event_id=f"audit-{index:04d}",
        case_id="CASE-LEGACY",
        trace_id="trace-legacy",
        event_type=f"event_{index}",
        occurred_at=datetime(2026, 8, 20, 10, index % 60, tzinfo=UTC),
        payload={"step": index},
    )


def _write_legacy(path, count: int) -> None:
    """Entries in the pre-chain shape: no seq, no prev_hash, no entry_hash."""
    with path.open("w", encoding="utf-8") as handle:
        for index in range(1, count + 1):
            row = _event(index).model_dump(mode="json")
            for field in ("seq", "prev_hash", "entry_hash"):
                row.pop(field, None)
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


@pytest.fixture
def legacy_path(tmp_path):
    path = tmp_path / "audit_ledger.jsonl"
    _write_legacy(path, 5)
    return path


def test_legacy_only_ledger_is_not_reported_as_tampered(legacy_path):
    result = AuditLedger(path=legacy_path).verify()
    assert result.ok is True
    assert result.first_broken_seq is None


def test_legacy_entries_are_counted_not_hidden(legacy_path):
    result = AuditLedger(path=legacy_path).verify()
    assert result.legacy_entries == 5
    assert result.checked == 0


def test_verification_states_what_it_cannot_attest_to(legacy_path):
    """Silence about the limit would be a false assurance."""
    result = AuditLedger(path=legacy_path).verify()
    assert result.note
    lowered = result.note.casefold()
    # The note must say both things: how many entries are outside the chain, and
    # that they cannot be attested to. Either half alone is misleading.
    assert "predate" in lowered or "legacy" in lowered
    assert "cannot be attested" in lowered
    assert "5" in result.note


def test_entries_appended_after_the_upgrade_are_chained(legacy_path):
    ledger = AuditLedger(path=legacy_path)
    ledger.append(_event(6))
    ledger.append(_event(7))
    result = AuditLedger(path=legacy_path).verify()
    assert result.ok is True
    assert result.legacy_entries == 5
    assert result.checked == 2


def test_new_chain_starts_at_one_after_legacy_entries(legacy_path):
    ledger = AuditLedger(path=legacy_path)
    appended = ledger.append(_event(6))
    assert appended.seq == 1
    assert appended.prev_hash == ""


def test_tampering_with_a_chained_entry_is_still_detected(legacy_path):
    ledger = AuditLedger(path=legacy_path)
    for index in (6, 7, 8):
        ledger.append(_event(index))

    lines = legacy_path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[6])          # the second chained entry
    row["payload"]["step"] = 999
    lines[6] = json.dumps(row, ensure_ascii=False, sort_keys=True)
    legacy_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = AuditLedger(path=legacy_path).verify()
    assert result.ok is False
    assert result.first_broken_seq == 2


def test_deleting_a_chained_entry_is_still_detected(legacy_path):
    ledger = AuditLedger(path=legacy_path)
    for index in (6, 7, 8):
        ledger.append(_event(index))

    lines = legacy_path.read_text(encoding="utf-8").splitlines()
    del lines[6]
    legacy_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = AuditLedger(path=legacy_path).verify()
    assert result.ok is False


def test_an_unchained_entry_after_chained_ones_is_a_break(legacy_path):
    """Legacy shape is only credible at the front; later it looks like an insertion."""
    ledger = AuditLedger(path=legacy_path)
    ledger.append(_event(6))

    row = _event(99).model_dump(mode="json")
    for field in ("seq", "prev_hash", "entry_hash"):
        row.pop(field, None)
    with legacy_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    result = AuditLedger(path=legacy_path).verify()
    assert result.ok is False
    assert result.reason


def test_fully_chained_ledger_reports_no_legacy_entries(tmp_path):
    ledger = AuditLedger(path=tmp_path / "fresh.jsonl")
    for index in (1, 2, 3):
        ledger.append(_event(index))
    result = ledger.verify()
    assert result.ok is True
    assert result.legacy_entries == 0
    assert result.checked == 3


def test_api_reports_legacy_entries_without_alarming(client, sample_request):
    client.post("/api/cases/check", json=sample_request("ae").model_dump(mode="json"))
    body = client.get("/api/audit-trail/verify", headers={"x-demo-role": "auditor"}).json()
    assert body["ok"] is True
    assert "legacy_entries" in body
