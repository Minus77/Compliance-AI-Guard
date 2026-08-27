"""The retention sweep must actually run, or the policy is still just prose.

``purge_expired`` existed and nothing called it, which is the same defect as
declaring a period and not enforcing it — one indirection further along.

It runs opportunistically when the notification list is read, rather than on a
background timer. This app is a single local process with no scheduler, and a
timer thread that only ever deletes things is a poor trade: the sweep is cheap,
and the moment someone reads their notifications is exactly when a stale one would
be visible.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from conftest import build_sample_request

REP = {"x-demo-role": "field_rep"}
PV = {"x-demo-role": "pv_reviewer"}


def _notify_via_review(client) -> str:
    """Produce a real notification by deciding a real review task."""
    client.post(
        "/api/cases/check",
        json=build_sample_request("ae").model_dump(mode="json"),
        headers=REP,
    )
    task = client.get("/api/reviews", headers=PV).json()["tasks"][0]
    client.post(
        f"/api/reviews/{task['task_id']}/decision",
        json={"decision": "escalated", "reason": "转医学复核"},
        headers=PV,
    )
    return client.get("/api/notifications", headers=REP).json()["notifications"][0][
        "notification_id"
    ]


def test_reading_notifications_sweeps_expired_ones(client):
    note_id = _notify_via_review(client)
    store = client.app.state.services.lifecycle

    # Age it past the declared 90 days, and mark it read so the unread guard does
    # not (correctly) protect it.
    note = next(
        n for n in store.notifications("demo-field_rep") if n.notification_id == note_id
    )
    note.created_at = datetime.now(UTC) - timedelta(days=200)
    note.read_at = datetime.now(UTC) - timedelta(days=199)

    body = client.get("/api/notifications", headers=REP).json()
    assert note_id not in [item["notification_id"] for item in body["notifications"]]


def test_an_unread_outcome_is_never_swept(client):
    """Expiring something the author has not seen loses the outcome silently."""
    note_id = _notify_via_review(client)
    store = client.app.state.services.lifecycle
    note = next(
        n for n in store.notifications("demo-field_rep") if n.notification_id == note_id
    )
    note.created_at = datetime.now(UTC) - timedelta(days=500)

    body = client.get("/api/notifications", headers=REP).json()
    assert note_id in [item["notification_id"] for item in body["notifications"]]


def test_recent_notifications_are_untouched(client):
    note_id = _notify_via_review(client)
    body = client.get("/api/notifications", headers=REP).json()
    assert note_id in [item["notification_id"] for item in body["notifications"]]


def test_readiness_reports_that_retention_is_enforced(client):
    """Distinguish a declared period from an enforced one."""
    body = client.get("/health/ready").json()
    assert body["retention"]["notification"]["enforced"] is True
    assert body["retention"]["audit_ledger"]["enforced"] is False


def test_the_audit_ledger_is_reported_as_never_swept(client):
    body = client.get("/health/ready").json()
    entry = body["retention"]["audit_ledger"]
    assert entry["retain_days"] is None
    assert entry["enforced"] is False
    assert "basis" in entry
