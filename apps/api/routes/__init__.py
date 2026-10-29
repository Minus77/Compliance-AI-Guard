"""HTTP route groups, registered in the same order as the original application."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from .audit import register_routes as register_audit_routes
from .auth import register_routes as register_auth_routes
from .cases import register_routes as register_case_routes
from .catalog import register_routes as register_catalog_routes
from .checks import register_routes as register_check_routes
from .config import register_routes as register_config_routes
from .conversations import register_routes as register_conversation_routes
from .feedback import register_routes as register_feedback_routes
from .integrations import register_routes as register_integration_routes
from .observability import register_routes as register_observability_routes
from .reviews import register_routes as register_review_routes
from .rules import register_routes as register_rule_routes
from .system import register_routes as register_system_routes


def register_routes(app: FastAPI, services: Any) -> None:
    register_system_routes(app, services)
    register_auth_routes(app, services)
    register_catalog_routes(app, services)
    register_rule_routes(app, services)
    register_check_routes(app, services)
    register_conversation_routes(app, services)
    register_case_routes(app, services)
    register_review_routes(app, services)
    register_feedback_routes(app, services)
    register_config_routes(app, services)
    register_observability_routes(app, services)
    register_integration_routes(app, services)
    register_audit_routes(app, services)
