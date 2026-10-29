from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, Request

from compliance_guard.workflow.checks import CheckRequest
from compliance_guard.workflow.scenario import demo_mode_enabled

from ..errors import ApiError
from ..security import _actor_from_header, _default_author


def register_routes(app: FastAPI, services: Any) -> None:
    @app.post("/api/checks/precheck")
    def precheck_content(payload: CheckRequest) -> dict[str, Any]:
        try:
            result = services.checks.precheck(payload)
        except ValueError as error:
            raise ApiError("rule_version_conflict", 409, str(error)) from None
        return result.model_dump(mode="json")

    @app.post("/api/checks", status_code=201)
    def submit_content_check(
        request: Request,
        payload: CheckRequest,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if request.state.session is not None or x_demo_role:
            actor = _actor_from_header(services.auth, x_demo_role)
        elif demo_mode_enabled():
            actor = _default_author()
        else:
            raise ApiError("unauthenticated", 401, "sign in at /api/auth/login")
        try:
            result = services.checks.submit(payload, actor)
        except PermissionError as error:
            raise ApiError("forbidden", 403, str(error)) from None
        except ValueError as error:
            raise ApiError("rule_version_conflict", 409, str(error)) from None
        return result.model_dump(mode="json")

    @app.get("/api/checks/{check_id}")
    def get_content_check(
        check_id: str,
        tenant_id: str = "",
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _actor_from_header(services.auth, x_demo_role)
        tenant = tenant_id or actor.tenant_id or ""
        if not tenant:
            raise ApiError("tenant_required", 422, "tenant_id is required")
        try:
            result = services.checks.get(check_id, tenant)
        except KeyError:
            raise KeyError(check_id)
        return result.model_dump(mode="json")
