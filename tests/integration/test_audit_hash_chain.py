"""C1: append-only is not the same as tamper-evident (defect D-3).

The ledger guaranteed that *the program* never rewrote a record. It said nothing
about anyone editing the file, and a JSONL file with no linkage between lines
cannot tell you that a line changed or vanished.

Each entry now carries a digest over (previous digest + its own normalised body),
so any edit, deletion or insertion breaks the chain at a locatable point. That is
what 21 CFR Part 11 §11.10(e) means by record changes not obscuring prior records:
the change may happen, but it cannot happen invisibly.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.domain.models import AuditEvent


def _event(index: int, case_id: str = "CASE-CHAIN") -> AuditEvent:
    return AuditEvent(
        event_id=f"audit-{index:04d}",
        case_id=case_id,
        trace_id="trace-chain",
        event_type=f"event_{index}",
        occurred_at=datetime(2026, 8, 20, 10, index % 60, tzinfo=UTC),
        payload={"step": index},
    )


@pytest.fixture
def ledger(tmp_path) -> AuditLedger:
    store = AuditLedger(path=tmp_path / "audit_ledger.jsonl")
    for index in range(1, 6):
        store.append(_event(index))
    return store


def test_entries_are_sequenced_from_one(ledger):
    assert [event.seq for event in ledger.all()] == [1, 2, 3, 4, 5]


def test_first_entry_has_no_predecessor(ledger):
    assert ledger.all()[0].prev_hash == ""


def test_each_entry_links_to_the_previous_digest(ledger):
    events = ledger.all()
    for previous, current in zip(events, events[1:]):
        assert current.prev_hash == previous.entry_hash


def test_entry_hash_is_present_and_stable(ledger):
    for event in ledger.all():
        assert event.entry_hash
        assert len(event.entry_hash) == 64


def test_intact_chain_verifies(ledger):
    result = ledger.verify()
    assert result.ok is True
    assert result.first_broken_seq is None
    assert result.checked == 5


def test_reads_do_not_expose_mutable_audit_entries(ledger):
    event = ledger.for_case("CASE-CHAIN")[0]
    event.payload["step"] = 999
    event.entry_hash = "tampered"

    stored = ledger.all()[0]
    assert stored.payload == {"step": 1}
    assert stored.entry_hash != "tampered"
    assert ledger.verify().ok is True


def test_reload_from_disk_verifies(tmp_path, ledger):
    reloaded = AuditLedger(path=ledger.path)
    result = reloaded.verify()
    assert result.ok is True
    assert result.checked == 5


def test_edited_line_is_detected_at_its_position(ledger):
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[2])
    row["payload"]["step"] = 999
    lines[2] = json.dumps(row, ensure_ascii=False, sort_keys=True)
    ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = AuditLedger(path=ledger.path).verify()
    assert result.ok is False
    assert result.first_broken_seq == 3
    assert "payload" in result.reason or result.reason


def test_deleted_line_is_detected(ledger):
    """Removing the third record makes position 3 onwards untrustworthy."""
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    del lines[2]
    ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = AuditLedger(path=ledger.path).verify()
    assert result.ok is False
    assert result.first_broken_seq == 3
    assert result.checked == 2


def test_forged_appended_line_is_detected(ledger):
    forged = _event(99)
    row = forged.model_dump(mode="json")
    row["seq"] = 6
    row["prev_hash"] = "0" * 64
    row["entry_hash"] = "f" * 64
    with ledger.path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    result = AuditLedger(path=ledger.path).verify()
    assert result.ok is False
    assert result.first_broken_seq == 6


def test_reordered_lines_are_detected(ledger):
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[3] = lines[3], lines[1]
    ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = AuditLedger(path=ledger.path).verify()
    assert result.ok is False
    assert result.first_broken_seq == 2


def test_empty_ledger_verifies_as_intact(tmp_path):
    result = AuditLedger(path=tmp_path / "empty.jsonl").verify()
    assert result.ok is True
    assert result.checked == 0


def test_hash_excludes_itself_so_verification_is_reproducible(ledger):
    """The digest must be computed over the body without the digest field."""
    event = ledger.all()[2]
    recomputed = AuditLedger.compute_entry_hash(event.prev_hash, event)
    assert recomputed == event.entry_hash


def test_appending_after_reload_continues_the_chain(ledger):
    reloaded = AuditLedger(path=ledger.path)
    reloaded.append(_event(6))
    result = AuditLedger(path=ledger.path).verify()
    assert result.ok is True
    assert result.checked == 6
    assert reloaded.all()[-1].seq == 6


def test_concurrent_appends_keep_one_contiguous_chain(tmp_path):
    store = AuditLedger(path=tmp_path / "audit_ledger.jsonl")
    workers = 8
    start = threading.Barrier(workers)

    def append(index: int) -> None:
        start.wait()
        store.append(_event(index))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(append, range(1, workers + 1)))

    verification = AuditLedger(path=store.path).verify()
    assert verification.ok is True
    assert verification.checked == workers
    assert [event.seq for event in store.all()] == list(range(1, workers + 1))
