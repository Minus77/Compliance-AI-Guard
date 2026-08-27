"""G4 in the browser: the session boundary must be reachable from the UI.

The API now enforces sessions, but the interface had no sign-in path. With
``DEMO_MODE=0`` that combination is the worst of both: the page renders, then every
request 401s, and the user sees an app that appears broken rather than one asking
them to sign in.

Three things are asserted here:

* a sign-in surface exists and is driven by ``GET /api/auth/me``, so the client asks
  the server who it is instead of assuming;
* the demo-role picker is visibly labelled as a demo affordance, because an
  unlabelled shortcut is indistinguishable from a security hole;
* a pending password change is surfaced, since a default credential that keeps
  working is a backdoor with documentation.
"""

from __future__ import annotations


def _html(client) -> str:
    return client.get("/").text


def _js(client) -> str:
    return client.get("/assets/app.js").text


def test_sign_in_surface_exists(client):
    html = _html(client)
    assert 'id="signin"' in html
    assert 'id="signin-username"' in html
    assert 'id="signin-password"' in html
    assert 'id="signin-submit"' in html


def test_identity_comes_from_the_server(client):
    js = _js(client)
    assert "/api/auth/me" in js
    assert "function loadIdentity" in js


def test_login_and_logout_are_wired(client):
    js = _js(client)
    assert "/api/auth/login" in js
    assert "/api/auth/logout" in js


def test_password_field_is_a_password_input(client):
    html = _html(client)
    signin = html.split('id="signin"', 1)[1].split("</section>", 1)[0]
    assert 'type="password"' in signin


def test_forced_password_change_is_surfaced(client):
    html = _html(client)
    assert 'id="password-change"' in html
    js = _js(client)
    assert "/api/auth/change-password" in js
    assert "must_change_password" in js


def test_demo_role_picker_is_labelled_as_a_demo_affordance(client):
    """An unlabelled shortcut is indistinguishable from a hole."""
    html = _html(client)
    assert 'id="demo-role-field"' in html
    js = _js(client)
    assert "demo_mode" in js


def test_signed_in_identity_is_displayed(client):
    html = _html(client)
    assert 'id="identity"' in html
    js = _js(client)
    assert "renderIdentity" in js


def test_unauthenticated_response_reopens_sign_in(client):
    """A 401 mid-session must return the user to sign-in, not to a dead page."""
    js = _js(client)
    assert "401" in js


def test_styles_exist_for_the_sign_in_surface(client):
    css = client.get("/assets/styles.css").text
    assert "signin" in css
