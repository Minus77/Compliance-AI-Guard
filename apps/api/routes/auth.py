from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, Response

from compliance_guard.security.sessions import SessionError
from compliance_guard.workflow.scenario import demo_mode_enabled

from ..errors import ApiError
from ..schemas import ChangePasswordPayload, LoginPayload
from ..security import SESSION_COOKIE


def register_routes(app: FastAPI, services: Any) -> None:
    @app.post("/api/auth/login")
    def login(response: Response, payload: LoginPayload) -> dict[str, Any]:
        """Open a session.

        The failure path returns one message for every cause. Distinguishing
        "no such user" from "wrong password" turns this into an endpoint for
        enumerating accounts.
        """
        try:
            session = services.sessions.login(payload.username, payload.password)
        except SessionError as error:
            raise ApiError("unauthenticated", 401, str(error)) from None

        # HttpOnly: a token readable by script is a token an injected script can
        # steal. SameSite=Strict: this API is same-origin, so there is no reason to
        # let another site drive it. Secure is intentionally *not* set, because the
        # local demo runs on plain http and a Secure cookie would simply be dropped
        # -- a real deployment terminates TLS and should set it.
        response.set_cookie(
            SESSION_COOKIE,
            session.token,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return {
            "authenticated": True,
            "username": session.username,
            "role": session.role.value,
            "expires_at": session.expires_at.isoformat(),
            # Surfaced so the interface can force the change rather than leaving a
            # default credential quietly working.
            "must_change_password": session.must_change_password,
        }

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response) -> dict[str, Any]:
        services.sessions.logout(request.cookies.get(SESSION_COOKIE))
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"authenticated": False}

    @app.get("/api/auth/me")
    def whoami(request: Request) -> dict[str, Any]:
        """Who the server thinks you are.

        Never 401s: the interface calls this before anything else to decide whether
        to show a sign-in form, and an error response would make "not signed in"
        indistinguishable from "something is broken".
        """
        session = request.state.session
        if session is None:
            return {
                "authenticated": False,
                "demo_mode": demo_mode_enabled(),
            }
        return {
            "authenticated": True,
            "username": session.username,
            "role": session.role.value,
            "expires_at": session.expires_at.isoformat(),
            "must_change_password": session.must_change_password,
            "capabilities": services.auth.capabilities(session.actor),
            "demo_mode": demo_mode_enabled(),
        }

    @app.post("/api/auth/change-password")
    def change_password(
        request: Request, response: Response, payload: ChangePasswordPayload
    ) -> dict[str, Any]:
        """Replace the caller's password, which also ends their other sessions."""
        session = request.state.session
        if session is None:
            raise ApiError("unauthenticated", 401, "sign in at /api/auth/login")
        try:
            services.sessions.change_password(
                session.username, payload.current, payload.replacement
            )
        except SessionError as error:
            raise ApiError("invalid_password", 422, str(error)) from None
        # Every session for the account was invalidated, including this one, so the
        # stale cookie is cleared rather than left to fail on the next request.
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"changed": True, "reauthenticate": True}
