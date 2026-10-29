"""Session identity and route permission helpers."""

from __future__ import annotations

import contextvars
from typing import Any

from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import Actor
from compliance_guard.security.authorization import AuthorizationService
from compliance_guard.workflow.scenario import demo_mode_enabled

from .errors import ApiError

_CURRENT_SESSION: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "cg_current_session", default=None
)
SESSION_COOKIE = "cg_session"


def actor_from_header(auth: AuthorizationService, header: str | None) -> Actor:
    session = _CURRENT_SESSION.get()
    if session is not None:
        return session.actor

    if header and demo_mode_enabled():
        try:
            return auth.actor_from_header(header)
        except ValueError:
            raise ApiError("forbidden", 403, "unknown x-demo-role") from None

    if header:
        raise ApiError(
            "unauthenticated",
            401,
            "x-demo-role is only honoured with DEMO_MODE=1; sign in at /api/auth/login",
        )
    raise ApiError("unauthenticated", 401, "sign in at /api/auth/login")


def default_author() -> Actor:
    return AuthorizationService.actor_from_header("author")


def require_config_actor(auth: AuthorizationService, header: str | None) -> Actor:
    actor = actor_from_header(auth, header)
    if not (auth.can(actor, "config_publish") or auth.can(actor, "architecture_review")):
        raise PermissionError(f"config management denied for role {actor.role.value!r}")
    return actor


def require_case_view(auth: AuthorizationService, header: str | None) -> Actor:
    actor = actor_from_header(auth, header)
    if not (auth.can(actor, "view_case_summary") or auth.can(actor, "config_publish")):
        raise PermissionError(f"case read denied for role {actor.role.value!r}")
    return actor


def require_rule_reader(auth: AuthorizationService, header: str | None) -> Actor:
    actor = actor_from_header(auth, header)
    if actor.role not in {Role.AUDITOR, Role.COMPLIANCE_ADMIN}:
        raise PermissionError(f"rule read denied for role {actor.role.value!r}")
    return actor


def require_rule_manager(auth: AuthorizationService, header: str | None) -> Actor:
    actor = actor_from_header(auth, header)
    if actor.role is not Role.COMPLIANCE_ADMIN:
        raise PermissionError(f"rule management denied for role {actor.role.value!r}")
    return actor


def require_owner_scope(actor: Actor, record: dict[str, Any]) -> None:
    author_roles = {Role.AUTHOR, Role.FIELD_REP, Role.REPRESENTATIVE}
    if actor.role in author_roles and record.get("submitted_by") != actor.actor_id:
        raise PermissionError(f"case read denied for role {actor.role.value!r}")


# Compatibility names keep the extracted route bodies readable and preserve
# callers that imported the former private helpers from apps.api.main.
_actor_from_header = actor_from_header
_default_author = default_author
_require_config_actor = require_config_actor
_require_case_view = require_case_view
_require_rule_reader = require_rule_reader
_require_rule_manager = require_rule_manager
_require_owner_scope = require_owner_scope
