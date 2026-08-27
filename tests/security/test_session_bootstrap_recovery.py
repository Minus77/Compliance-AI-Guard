"""A never-used default account must not become a permanent lockout.

Found by running the server twice. The bootstrap password is generated at
provisioning and deliberately never written to disk — correct, since a plaintext
credential beside its own hash defeats the hashing. But on the *second* start the
file already exists, so ``bootstrap_password`` is ``None`` and nobody can learn the
password. The account sits there with ``must_change_password=True``, unusable, and
the only route back in is deleting a file nobody documented.

The fix rests on one distinction: an account that has never been signed into has no
history to protect, so re-keying it costs nothing. An account that *has* been used
is a real identity and must never be silently re-keyed — that would be a way in, not
a recovery.

So ``last_login_at`` is tracked, and re-keying is allowed only while it is unset.
"""

from __future__ import annotations

import json

import pytest

from compliance_guard.security.sessions import SessionStore


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "users.json"


def test_first_start_provisions_and_reveals_a_password(store_path):
    store = SessionStore(path=store_path)
    assert store.bootstrap_password


def test_second_start_still_reveals_a_usable_password(store_path):
    """The lockout: a reload used to leave no way in at all."""
    SessionStore(path=store_path)
    reloaded = SessionStore(path=store_path)
    assert reloaded.bootstrap_password
    assert reloaded.login("admin", reloaded.bootstrap_password)


def test_the_password_is_rotated_rather_than_recovered(store_path):
    """It cannot be recovered -- it is not stored -- so it is replaced."""
    first = SessionStore(path=store_path).bootstrap_password
    second = SessionStore(path=store_path).bootstrap_password
    assert first != second


def test_the_previous_bootstrap_password_stops_working(store_path):
    first = SessionStore(path=store_path).bootstrap_password
    reloaded = SessionStore(path=store_path)
    from compliance_guard.security.sessions import SessionError

    with pytest.raises(SessionError):
        reloaded.login("admin", first)


def test_an_account_that_has_been_used_is_never_rekeyed(store_path):
    """The security half. A used account is a real identity, not a spare key."""
    store = SessionStore(path=store_path)
    password = store.bootstrap_password
    store.login("admin", password)

    reloaded = SessionStore(path=store_path)
    assert reloaded.bootstrap_password is None
    # The credential the operator already holds still works.
    assert reloaded.login("admin", password)


def test_login_is_recorded_so_the_decision_is_evidence_based(store_path):
    store = SessionStore(path=store_path)
    assert store.user("admin").last_login_at is None
    store.login("admin", store.bootstrap_password)
    assert store.user("admin").last_login_at is not None


def test_a_changed_password_is_never_rekeyed(store_path):
    store = SessionStore(path=store_path)
    store.change_password("admin", store.bootstrap_password, "a-much-longer-passphrase")
    reloaded = SessionStore(path=store_path)
    assert reloaded.bootstrap_password is None
    assert reloaded.login("admin", "a-much-longer-passphrase")


def test_rekeying_never_writes_the_password_to_disk(store_path):
    SessionStore(path=store_path)
    reloaded = SessionStore(path=store_path)
    contents = store_path.read_text(encoding="utf-8")
    assert reloaded.bootstrap_password not in contents


def test_rekeying_keeps_the_change_requirement(store_path):
    SessionStore(path=store_path)
    reloaded = SessionStore(path=store_path)
    assert reloaded.user("admin").must_change_password is True


def test_summary_reports_whether_a_password_is_pending_not_its_value(store_path):
    store = SessionStore(path=store_path)
    summary = store.summary()
    assert summary["password_change_required"] is True
    assert store.bootstrap_password not in json.dumps(summary)


def test_readiness_says_a_bootstrap_credential_is_waiting(client):
    body = client.get("/health/ready").json()
    assert body["sessions"]["bootstrap_pending"] is True
    password = client.app.state.services.sessions.bootstrap_password
    if password:
        assert password not in str(body)
