"""K4: a declared retention period must actually expire something.

The policy was declared and reported by ``/health/ready``, and nothing enforced it.
A retention statement no code honours is worse than none: it reads as a control to
anyone reviewing the design, while notifications accumulate indefinitely.

The asymmetry is the whole point and is asserted here rather than described:

* transient stores (notifications, resolved appeals) expire on a bounded schedule;
* the **audit ledger is never swept**. Retention there must equal or exceed the
  business records it describes, and a sweep that deleted entries would defeat the
  hash chain that exists to make deletion detectable. A "tidy up old audit rows"
  helper is exactly the well-intentioned change that would break it, so the absence
  is pinned by a test.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import Actor
from compliance_guard.review.lifecycle import LifecycleStore, NotificationKind


def _actor(actor_id: str = "demo-field_rep") -> Actor:
    return Actor(actor_id=actor_id, role=Role.FIELD_REP, tenant_id="TENANT-CN")


@pytest.fixture
def clock() -> list[datetime]:
    return [datetime.now(UTC)]


@pytest.fixture
def store(clock) -> LifecycleStore:
    return LifecycleStore(now=lambda: clock[0])


def _notify(store: LifecycleStore, clock: list[datetime], *, age_days: int) -> str:
    now = datetime.now(UTC)
    clock[0] = now - timedelta(days=age_days)
    note = store.notify(
        case_id="CASE-1",
        recipient_id="demo-field_rep",
        kind=NotificationKind.REVIEW_DECIDED,
        title="已退回",
        next_step="请补充信息",
    )
    clock[0] = now
    return note.notification_id


def test_old_notifications_are_purged(store, clock):
    _notify(store, clock, age_days=200)
    removed = store.purge_expired()
    assert removed["notifications"] == 1
    assert store.notifications("demo-field_rep") == []


def test_recent_notifications_survive(store, clock):
    _notify(store, clock, age_days=3)
    store.purge_expired()
    assert len(store.notifications("demo-field_rep")) == 1


def test_the_cutoff_matches_the_declared_policy(store, clock):
    """90 days is declared; 89 must live and 91 must not."""
    from compliance_guard.runtime_config import retention_policy

    assert retention_policy()["notification"]["retain_days"] == 90
    _notify(store, clock, age_days=89)
    _notify(store, clock, age_days=91)
    store.purge_expired()
    assert len(store.notifications("demo-field_rep")) == 1


def test_an_unread_notification_is_never_purged_early(store, clock):
    """Expiring something the author has not seen would lose the outcome silently."""
    note_id = _notify(store, clock, age_days=200)
    note = next(n for n in store.notifications("demo-field_rep") if n.notification_id == note_id)
    assert note.unread is True
    removed = store.purge_expired(keep_unread=True)
    assert removed["notifications"] == 0
    assert len(store.notifications("demo-field_rep")) == 1


def test_resolved_appeals_expire(store, clock):
    clock[0] -= timedelta(days=200)
    appeal = store.raise_appeal(
        case_id="CASE-1", reason="判错了", actor=_actor(), decision_at_appeal="blocked"
    )
    store.resolve_appeal(
        appeal.appeal_id,
        actor=Actor(actor_id="demo-compliance_admin", role=Role.COMPLIANCE_ADMIN),
        upheld=True,
        reason="维持原判定",
    )
    clock[0] += timedelta(days=200)
    removed = store.purge_expired()
    assert removed["appeals"] == 1


def test_a_pending_appeal_is_never_purged(store, clock):
    """An open appeal is outstanding work; expiring it would close it by neglect."""
    clock[0] -= timedelta(days=500)
    store.raise_appeal(
        case_id="CASE-1", reason="判错了", actor=_actor(), decision_at_appeal="blocked"
    )
    clock[0] += timedelta(days=500)
    removed = store.purge_expired()
    assert removed["appeals"] == 0
    assert len(store.appeals(pending_only=True)) == 1


def test_purge_reports_what_it_removed(store, clock):
    _notify(store, clock, age_days=200)
    removed = store.purge_expired()
    assert set(removed) >= {"notifications", "appeals"}
    assert all(isinstance(value, int) for value in removed.values())


def test_purging_an_empty_store_is_a_no_op(store):
    assert store.purge_expired() == {"notifications": 0, "appeals": 0}


def test_returned_records_cannot_mutate_stored_state(store):
    note = store.notify(
        case_id="CASE-1",
        recipient_id="demo-field_rep",
        kind=NotificationKind.REVIEW_DECIDED,
        title="已处理",
    )
    note.title = "tampered"
    appeal = store.raise_appeal(
        case_id="CASE-1",
        reason="申请复核",
        actor=_actor(),
        decision_at_appeal="blocked",
    )
    appeal.reason = "tampered"

    assert store.notifications("demo-field_rep")[0].title == "已处理"
    assert store.appeals(case_id="CASE-1")[0].reason == "申请复核"


def test_concurrent_operations_keep_a_coherent_store(store):
    workers = 8
    start = threading.Barrier(workers)
    actor = _actor()

    def use_store(index: int) -> None:
        start.wait()
        store.notify(
            case_id=f"CASE-{index}",
            recipient_id=actor.actor_id,
            kind=NotificationKind.REVIEW_DECIDED,
            title="已处理",
        )
        appeal = store.raise_appeal(
            case_id=f"CASE-{index}",
            reason="申请复核",
            actor=actor,
            decision_at_appeal="blocked",
        )
        store.resolve_appeal(
            appeal.appeal_id,
            actor=actor,
            upheld=index % 2 == 0,
            reason="已复核",
        )
        store.appeals(pending_only=True)
        store.appeal_summary()
        store.purge_expired(keep_unread=True)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(use_store, range(workers)))

    assert len(store.notifications(actor.actor_id)) == workers
    assert store.appeal_summary() == {
        "total": workers,
        "pending": 0,
        "upheld": workers // 2,
        "overturned": workers // 2,
        "overturn_rate": 0.5,
        "resolved": workers,
    }


# -- the audit ledger is deliberately exempt --------------------------------


def test_the_audit_ledger_has_no_purge_method():
    """Pinned as an absence. A well-meaning "tidy old rows" helper would break the
    chain that exists to make deletion detectable."""
    from compliance_guard.audit.ledger import AuditLedger

    for forbidden in ("purge", "purge_expired", "prune", "cleanup", "delete", "truncate"):
        assert not hasattr(AuditLedger, forbidden), (
            f"AuditLedger must not expose {forbidden!r}: append-only means append-only"
        )


def test_the_declared_audit_retention_is_unbounded():
    from compliance_guard.runtime_config import retention_policy

    assert retention_policy()["audit_ledger"]["retain_days"] is None


def test_feedback_candidates_are_also_exempt():
    """Confirmed candidates become regression cases; expiring them loses the signal."""
    from compliance_guard.runtime_config import retention_policy

    assert retention_policy()["feedback_candidate"]["retain_days"] is None
