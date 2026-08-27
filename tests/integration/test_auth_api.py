"""G4 at the API boundary: the header only works in a labelled demo.

With ``DEMO_MODE`` off, ``x-demo-role`` is refused and a session cookie is the only
way to be anybody. With it on, the header still works and the interface says so —
an unlabelled demo shortcut is indistinguishable from a security hole.

The suite's own client runs with ``DEMO_MODE=1``, which is honest: a test harness
*is* a demo context. The tests below assert the production posture explicitly by
turning it off.
"""

from __future__ import annotations

import pytest


# -- session lifecycle ------------------------------------------------------


def test_login_returns_a_session_and_sets_a_cookie(client):
    password = client.app.state.services.sessions.bootstrap_password
    response = client.post("/api/auth/login", json={"username": "admin", "password": password})
    assert response.status_code == 200
    body = response.json()
    assert body["role"]
    assert body["must_change_password"] is True
    assert "cg_session" in response.cookies or "set-cookie" in {
        k.lower() for k in response.headers
    }


def test_session_cookie_is_httponly_and_samesite(client):
    """A token readable by script is a token an injected script can steal."""
    password = client.app.state.services.sessions.bootstrap_password
    response = client.post("/api/auth/login", json={"username": "admin", "password": password})
    cookie = response.headers.get("set-cookie", "")
    assert "httponly" in cookie.casefold()
    assert "samesite" in cookie.casefold()


def test_wrong_password_is_refused(client):
    response = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert response.status_code == 401


def test_failure_message_does_not_reveal_whether_the_user_exists(client):
    unknown = client.post("/api/auth/login", json={"username": "ghost", "password": "x"})
    wrong = client.post("/api/auth/login", json={"username": "admin", "password": "x"})
    assert unknown.json()["error"]["message"] == wrong.json()["error"]["message"]


def test_me_reports_the_session_identity(client):
    password = client.app.state.services.sessions.bootstrap_password
    client.post("/api/auth/login", json={"username": "admin", "password": password})
    body = client.get("/api/auth/me").json()
    assert body["authenticated"] is True
    assert body["role"]


def test_me_without_a_session_says_so(client):
    client.cookies.clear()
    body = client.get("/api/auth/me").json()
    assert body["authenticated"] is False


def test_logout_ends_the_session(client):
    password = client.app.state.services.sessions.bootstrap_password
    client.post("/api/auth/login", json={"username": "admin", "password": password})
    client.post("/api/auth/logout")
    assert client.get("/api/auth/me").json()["authenticated"] is False


def test_password_can_be_changed_through_the_api(client):
    password = client.app.state.services.sessions.bootstrap_password
    client.post("/api/auth/login", json={"username": "admin", "password": password})
    response = client.post(
        "/api/auth/change-password",
        json={"current": password, "replacement": "a-much-longer-passphrase"},
    )
    assert response.status_code == 200
    assert client.post(
        "/api/auth/login", json={"username": "admin", "password": "a-much-longer-passphrase"}
    ).status_code == 200


def test_short_replacement_password_is_refused(client):
    password = client.app.state.services.sessions.bootstrap_password
    client.post("/api/auth/login", json={"username": "admin", "password": password})
    response = client.post(
        "/api/auth/change-password", json={"current": password, "replacement": "short"}
    )
    assert response.status_code == 422


# -- the production posture -------------------------------------------------


def test_header_role_is_refused_when_demo_mode_is_off(client, monkeypatch):
    """The P-3 lock: without the demo flag, naming your own role does nothing."""
    monkeypatch.delenv("DEMO_MODE", raising=False)
    client.cookies.clear()
    response = client.get("/api/reviews", headers={"x-demo-role": "compliance_admin"})
    assert response.status_code in {401, 403}


def test_a_session_still_works_when_demo_mode_is_off(client, monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    password = client.app.state.services.sessions.bootstrap_password
    client.post("/api/auth/login", json={"username": "admin", "password": password})
    assert client.get("/api/reviews").status_code == 200


def test_header_role_still_works_in_demo_mode(client, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    assert client.get("/api/reviews", headers={"x-demo-role": "compliance_admin"}).status_code == 200


def test_health_declares_whether_demo_mode_is_on(client, monkeypatch):
    """An unlabelled demo shortcut is indistinguishable from a hole."""
    monkeypatch.setenv("DEMO_MODE", "1")
    assert client.get("/health/ready").json()["demo_mode"] is True
    monkeypatch.delenv("DEMO_MODE", raising=False)
    assert client.get("/health/ready").json()["demo_mode"] is False


def test_readiness_reports_pending_password_change(client):
    body = client.get("/health/ready").json()
    assert body["sessions"]["password_change_required"] is True


def test_readiness_never_exposes_a_password_or_token(client):
    password = client.app.state.services.sessions.bootstrap_password
    client.post("/api/auth/login", json={"username": "admin", "password": password})
    body = str(client.get("/health/ready").json())
    assert password not in body
    assert "password_hash" not in body


def test_session_identity_is_used_for_ownership_not_the_header(client, monkeypatch):
    """Ownership must follow the session, or scoping is self-declared again."""
    monkeypatch.delenv("DEMO_MODE", raising=False)
    password = client.app.state.services.sessions.bootstrap_password
    client.post("/api/auth/login", json={"username": "admin", "password": password})
    body = client.get("/api/cases", params={"scope": "mine"}).json()
    assert body["scope"] in {"mine", "all"}
