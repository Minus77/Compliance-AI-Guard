"""The initial password must be announced however the app is started.

Found by starting the app the way README documents. ``announce_bootstrap_credential``
was only called from ``desktop/launcher.py``, so ``uvicorn apps.api.main:app`` --
the documented command -- generated the password and printed nothing. With
``DEMO_MODE`` off that is a first-run lockout: the account exists, the password is
unknowable, and the sign-in form cannot be cleared.

The same lockout class as the ``users.json`` reload defect, one layer up: there the
value could not be *re-derived*, here it could not be *seen*. The lesson is the
same either way -- a credential that exists and cannot be obtained is worse than no
credential, because the app looks broken rather than locked.

Announcing belongs with provisioning, not with one particular entry point.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from compliance_guard.security.sessions import SessionStore


@pytest.fixture(autouse=True)
def isolated_rule_store(monkeypatch, tmp_path):
    import apps.api.main as api

    monkeypatch.setattr(
        api,
        "_rule_store_path",
        lambda: tmp_path / "rule_versions.json",
        raising=False,
    )


def test_a_fresh_store_announces_through_the_shared_helper(capsys):
    """The helper is what every entry point should call."""
    from desktop.launcher import announce_bootstrap_credential

    store = SessionStore(path=pathlib.Path(tempfile.mkdtemp()) / "users.json")
    announce_bootstrap_credential("admin", store.bootstrap_password)
    assert store.bootstrap_password in capsys.readouterr().out


def test_production_service_composition_announces(capsys, monkeypatch, tmp_path):
    """The uvicorn path composes services here, so this is where it must happen."""
    import apps.api.main as api

    monkeypatch.setattr(
        api, "_session_store_path", lambda: tmp_path / "users.json", raising=False
    )
    services = api._production_services()
    out = capsys.readouterr().out

    password = services.sessions.bootstrap_password
    assert password, "a fresh store must generate a password"
    assert password in out, "the uvicorn path must print it or the user is locked out"


def test_an_established_account_announces_nothing(capsys, monkeypatch, tmp_path):
    """Silence is correct on every later start; noise trains people to skip it."""
    import apps.api.main as api

    monkeypatch.setattr(
        api, "_session_store_path", lambda: tmp_path / "users.json", raising=False
    )
    first = api._production_services()
    first.sessions.login("admin", first.sessions.bootstrap_password)
    capsys.readouterr()                      # discard the first announcement

    api._production_services()
    assert capsys.readouterr().out.strip() == ""


def test_the_announcement_survives_a_reload_of_an_unused_account(capsys, monkeypatch, tmp_path):
    """A never-used account is re-keyed, so the new value must be shown too."""
    import apps.api.main as api

    monkeypatch.setattr(
        api, "_session_store_path", lambda: tmp_path / "users.json", raising=False
    )
    api._production_services()
    capsys.readouterr()

    second = api._production_services()
    assert second.sessions.bootstrap_password
    assert second.sessions.bootstrap_password in capsys.readouterr().out
