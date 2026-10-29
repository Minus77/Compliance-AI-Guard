"""C3: production misclassifications become candidate regression cases.

A reviewer who spots a false positive or a missed risk is holding the only signal
that reliably improves the rules over time. Without a path back into the test set
that signal dies in a queue, and the same mistake ships again next month.

Three constraints shape the design:

* **Candidates are not test cases yet.** They land in a candidate file and need a
  second confirmation before joining the golden set, so one reviewer cannot
  reshape the release gate alone.
* **De-identified before it is stored.** The candidate keeps masked text only; a
  regression fixture is a long-lived artefact and must not become a PII store.
* **Append-only.** Marking a case never edits the original record.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import Actor
from compliance_guard.review.feedback import FeedbackKind, FeedbackStore


def _actor(role: Role = Role.COMPLIANCE_ADMIN, actor_id: str = "user-compliance") -> Actor:
    return Actor(actor_id=actor_id, role=role, tenant_id="TENANT-CN")


@pytest.fixture
def store(tmp_path) -> FeedbackStore:
    return FeedbackStore(path=tmp_path / "candidates.jsonl")


def test_false_positive_is_recorded_as_a_candidate(store):
    entry = store.record(
        case_id="CASE-1",
        kind=FeedbackKind.FALSE_POSITIVE,
        reason="日常拜访描述被误判为超适应症",
        actor=_actor(),
        masked_text="[HCP_TKN_0000000000000000]对本品很认可。",
        observed_decision="human_review",
        observed_findings=["off_label"],
    )
    assert entry.kind is FeedbackKind.FALSE_POSITIVE
    assert entry.status == "candidate"
    assert entry.expected_decision == "allow"


def test_false_negative_expects_escalation_not_release(store):
    entry = store.record(
        case_id="CASE-2",
        kind=FeedbackKind.FALSE_NEGATIVE,
        reason="漏掉了不良事件",
        actor=_actor(role=Role.PV_REVIEWER),
        masked_text="患者服药后出现皮疹。",
        observed_decision="allow",
        observed_findings=[],
    )
    assert entry.expected_decision != "allow"


def test_reason_is_required(store):
    with pytest.raises(ValueError):
        store.record(
            case_id="CASE-3",
            kind=FeedbackKind.FALSE_POSITIVE,
            reason="   ",
            actor=_actor(),
            masked_text="内容",
            observed_decision="blocked",
            observed_findings=[],
        )


def test_unmasked_identifier_is_refused(store):
    """A regression fixture must never become a place PII lives."""
    with pytest.raises(ValueError):
        store.record(
            case_id="CASE-4",
            kind=FeedbackKind.FALSE_POSITIVE,
            reason="误判",
            actor=_actor(),
            masked_text="联系电话 13800138000",
            observed_decision="blocked",
            observed_findings=[],
        )


def test_candidate_is_persisted_as_jsonl(store):
    store.record(
        case_id="CASE-5",
        kind=FeedbackKind.FALSE_POSITIVE,
        reason="误判",
        actor=_actor(),
        masked_text="常规内容",
        observed_decision="blocked",
        observed_findings=[],
    )
    lines = store.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["case_id"] == "CASE-5"


def test_records_are_append_only(store):
    for index in range(3):
        store.record(
            case_id=f"CASE-{index}",
            kind=FeedbackKind.FALSE_POSITIVE,
            reason="误判",
            actor=_actor(),
            masked_text="常规内容",
            observed_decision="blocked",
            observed_findings=[],
        )
    assert len(store.pending()) == 3
    assert len(store.path.read_text(encoding="utf-8").strip().splitlines()) == 3


def test_confirmation_requires_a_second_person(store):
    entry = store.record(
        case_id="CASE-6",
        kind=FeedbackKind.FALSE_POSITIVE,
        reason="误判",
        actor=_actor(actor_id="user-a"),
        masked_text="常规内容",
        observed_decision="blocked",
        observed_findings=[],
    )
    with pytest.raises(PermissionError):
        store.confirm(entry.entry_id, actor=_actor(actor_id="user-a"))


def test_second_person_can_confirm(store):
    entry = store.record(
        case_id="CASE-7",
        kind=FeedbackKind.FALSE_POSITIVE,
        reason="误判",
        actor=_actor(actor_id="user-a"),
        masked_text="常规内容",
        observed_decision="blocked",
        observed_findings=[],
    )
    confirmed = store.confirm(entry.entry_id, actor=_actor(actor_id="user-b"))
    assert confirmed.status == "confirmed"
    assert confirmed.confirmed_by == "user-b"


def test_concurrent_confirmation_appends_once(store):
    entry = store.record(
        case_id="CASE-CONCURRENT",
        kind=FeedbackKind.FALSE_POSITIVE,
        reason="误判",
        actor=_actor(actor_id="user-a"),
        masked_text="常规内容",
        observed_decision="blocked",
        observed_findings=[],
    )
    workers = 8
    start = threading.Barrier(workers)

    def confirm(_):
        start.wait()
        return store.confirm(entry.entry_id, actor=_actor(actor_id="user-b"))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        confirmed = list(pool.map(confirm, range(workers)))

    assert {item.status for item in confirmed} == {"confirmed"}
    rows = [
        json.loads(line)
        for line in store.path.read_text(encoding="utf-8").strip().splitlines()
    ]
    assert len(rows) == 2
    assert [row["status"] for row in rows] == ["candidate", "confirmed"]


def test_confirmation_does_not_overwrite_the_original_entry(store):
    entry = store.record(
        case_id="CASE-8",
        kind=FeedbackKind.FALSE_POSITIVE,
        reason="误判",
        actor=_actor(actor_id="user-a"),
        masked_text="常规内容",
        observed_decision="blocked",
        observed_findings=[],
    )
    store.confirm(entry.entry_id, actor=_actor(actor_id="user-b"))
    rows = [json.loads(line) for line in store.path.read_text(encoding="utf-8").strip().splitlines()]
    assert len(rows) == 2
    assert rows[0]["status"] == "candidate"
    assert rows[1]["status"] == "confirmed"


def test_only_confirmed_entries_are_exportable(store):
    first = store.record(
        case_id="CASE-9",
        kind=FeedbackKind.FALSE_NEGATIVE,
        reason="漏检",
        actor=_actor(actor_id="user-a"),
        masked_text="患者出现皮疹",
        observed_decision="allow",
        observed_findings=[],
    )
    store.record(
        case_id="CASE-10",
        kind=FeedbackKind.FALSE_POSITIVE,
        reason="误判",
        actor=_actor(actor_id="user-a"),
        masked_text="常规内容",
        observed_decision="blocked",
        observed_findings=[],
    )
    store.confirm(first.entry_id, actor=_actor(actor_id="user-b"))
    exported = store.exportable()
    # An exported row gets its own golden-set id so it cannot collide with the
    # curated cases; the case it came from is kept for traceability.
    assert [row["source_case_id"] for row in exported] == ["CASE-9"]
    assert exported[0]["case_id"].startswith("R-")


def test_exported_case_has_the_golden_set_shape(store):
    entry = store.record(
        case_id="CASE-11",
        kind=FeedbackKind.FALSE_NEGATIVE,
        reason="漏检",
        actor=_actor(actor_id="user-a"),
        masked_text="患者出现皮疹",
        observed_decision="allow",
        observed_findings=[],
    )
    store.confirm(entry.entry_id, actor=_actor(actor_id="user-b"))
    row = store.exportable()[0]
    for key in ("case_id", "content", "expected_decision", "category", "note"):
        assert key in row
