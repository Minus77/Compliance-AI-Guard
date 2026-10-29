"""G4: a role must be established by the server, not asserted by the caller.

``x-demo-role`` let anyone name their own role. Changing one request header was
enough to publish model policy or read the audit trail (defect P-3). That is
acceptable in a labelled demo and unacceptable anywhere else, so the header now
works only when ``DEMO_MODE`` is switched on.

Scope, honestly: this is a minimal local session, not enterprise SSO. There is no
identity provider and no second factor. It exists so the trust boundary is in the
right *place* — the server decides who you are — with a seam an SSO integration can
replace. Claiming more than that would be the same kind of overstatement the audit
trail work was careful to avoid.
"""

from __future__ import annotations

import pytest

from compliance_guard.security import sessions
from compliance_guard.security.sessions import (
    SessionError,
    SessionStore,
    hash_password,
    verify_password,
)


# -- password handling ------------------------------------------------------


def test_password_is_never_stored_in_the_clear():
    stored = hash_password("correct horse battery staple")
    assert "correct horse battery staple" not in stored
    assert stored.startswith("scrypt$")


def test_same_password_yields_different_stored_values():
    """Per-password salt: identical passwords must not produce identical records."""
    assert hash_password("same") != hash_password("same")


def test_correct_password_verifies():
    stored = hash_password("s3cret-passphrase")
    assert verify_password("s3cret-passphrase", stored) is True


def test_wrong_password_is_rejected():
    stored = hash_password("s3cret-passphrase")
    assert verify_password("not-it", stored) is False


def test_malformed_stored_value_is_rejected_rather_than_crashing():
    assert verify_password("anything", "not-a-hash") is False


# -- sessions ---------------------------------------------------------------


@pytest.fixture
def store(tmp_path) -> SessionStore:
    return SessionStore(path=tmp_path / "users.json")


def test_default_account_requires_a_password_change(store):
    """A shipped default credential that never expires is a backdoor."""
    user = store.user("admin")
    assert user is not None
    assert user.must_change_password is True


def test_login_with_the_default_password_succeeds_but_flags_the_change(store):
    session = store.login("admin", store.bootstrap_password)
    assert session.actor.role.value in {"compliance_admin", "admin"}
    assert session.must_change_password is True


def test_login_with_a_wrong_password_is_refused(store):
    with pytest.raises(SessionError):
        store.login("admin", "wrong")


def test_login_with_an_unknown_user_is_refused(store):
    with pytest.raises(SessionError):
        store.login("nobody", "whatever")


def test_unknown_user_and_wrong_password_report_the_same_error(store):
    """Distinguishing them tells an attacker which usernames exist."""
    with pytest.raises(SessionError) as unknown:
        store.login("nobody", "whatever")
    with pytest.raises(SessionError) as wrong:
        store.login("admin", "whatever")
    assert str(unknown.value) == str(wrong.value)


def test_session_token_resolves_to_an_actor(store):
    session = store.login("admin", store.bootstrap_password)
    resolved = store.resolve(session.token)
    assert resolved is not None
    assert resolved.actor.actor_id == session.actor.actor_id


def test_mutating_resolved_objects_cannot_change_stored_access(store):
    session = store.login("admin", store.bootstrap_password)
    user = store.user("admin")
    resolved = store.resolve(session.token)
    assert user is not None and resolved is not None

    user.must_change_password = False
    resolved.must_change_password = False

    assert store.user("admin").must_change_password is True
    assert store.resolve(session.token).must_change_password is True


def test_unknown_token_resolves_to_nothing(store):
    assert store.resolve("not-a-real-token") is None


def test_logout_invalidates_the_token(store):
    session = store.login("admin", store.bootstrap_password)
    store.logout(session.token)
    assert store.resolve(session.token) is None


def test_expired_session_is_not_accepted(store):
    session = store.login("admin", store.bootstrap_password, ttl_seconds=0)
    assert store.resolve(session.token) is None


def test_changing_the_password_clears_the_flag(store):
    store.login("admin", store.bootstrap_password)
    store.change_password("admin", store.bootstrap_password, "a-much-longer-passphrase")
    assert store.user("admin").must_change_password is False
    assert store.login("admin", "a-much-longer-passphrase").must_change_password is False


def test_the_old_password_stops_working_after_a_change(store):
    old = store.bootstrap_password
    store.change_password("admin", old, "a-much-longer-passphrase")
    with pytest.raises(SessionError):
        store.login("admin", old)


def test_a_trivially_short_password_is_refused(store):
    with pytest.raises(SessionError):
        store.change_password("admin", store.bootstrap_password, "short")


def test_changing_the_password_ends_existing_sessions(store):
    """A credential change must not leave older sessions alive."""
    session = store.login("admin", store.bootstrap_password)
    store.change_password("admin", store.bootstrap_password, "a-much-longer-passphrase")
    assert store.resolve(session.token) is None


def test_user_file_never_contains_a_plaintext_password(store):
    store.change_password("admin", store.bootstrap_password, "a-much-longer-passphrase")
    contents = store.path.read_text(encoding="utf-8")
    assert "a-much-longer-passphrase" not in contents
    assert store.bootstrap_password not in contents


def test_sessions_survive_a_store_reload(store):
    """A restart must not silently sign everyone out mid-task."""
    session = store.login("admin", store.bootstrap_password)
    reloaded = SessionStore(path=store.path)
    assert reloaded.resolve(session.token) is not None


def test_failed_store_write_preserves_the_previous_file(store, monkeypatch):
    previous = store.path.read_bytes()

    def fail_replace(source, destination):
        raise OSError("disk full")

    monkeypatch.setattr(sessions.os, "replace", fail_replace)
    with pytest.raises(OSError, match="disk full"):
        store.login("admin", store.bootstrap_password)

    assert store.path.read_bytes() == previous
    assert not list(store.path.parent.glob(f".{store.path.name}.*.tmp"))


def test_store_file_is_private_to_the_operating_system_user(store):
    assert store.path.stat().st_mode & 0o777 == 0o600
