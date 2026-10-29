from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header

from ..errors import ApiError
from ..schemas import UsabilityPayload
from ..security import _actor_from_header


def register_routes(app: FastAPI, services: Any) -> None:
    @app.get("/api/metrics")
    def get_metrics() -> dict[str, Any]:
        payload = services.metrics.snapshot().model_dump(mode="json")
        # Human-oversight health travels with the metrics, not in a separate
        # place a dashboard might forget to read. A low override rate is a
        # warning, not a success (EU AI Act Art.14(4)(b)).
        payload["oversight"] = services.metrics.oversight_summary().model_dump(mode="json")
        # Abandonment sits beside the safety numbers on purpose: a falling
        # detection count next to a rising abandonment count means the rules got
        # tighter, not that risk went away.
        payload["usability"] = services.metrics.usability_summary().model_dump(mode="json")
        return payload

    @app.post("/api/telemetry/usability")
    def record_usability_event(payload: UsabilityPayload) -> dict[str, Any]:
        """Count a usability event. Never stores content.

        The event this exists for is abandonment: a warning appears, the author
        clears the paragraph, and something blander gets submitted. Nothing is
        blocked and no finding is raised, so without a counter the tool has no way
        to notice it is making the problem it was built to solve worse.

        Recording *what* was abandoned would mean keeping precisely the text the
        author chose not to submit, so the context is restricted to scalar flags
        and anything string-shaped is refused.
        """
        for key, value in (payload.context or {}).items():
            if isinstance(value, str):
                raise ApiError(
                    "invalid_context",
                    422,
                    f"context field {key!r} must be a flag or number, not text; "
                    "narrative content is never accepted here",
                )
        try:
            services.metrics.record_usability_event(payload.event)
        except ValueError as error:
            raise ApiError("unknown_event", 422, str(error)) from None
        return {"recorded": True, "event": payload.event}

    @app.get("/api/permissions")
    def get_permissions(
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Resolve the caller's capability map from the server permission matrix.

        The UI hides modules the role cannot use. This is a usability aid layered
        on top of enforcement, not a replacement for it: every protected route
        still checks permission independently, so hiding a control in the client
        never becomes the only thing standing between a role and an action.
        """
        actor = _actor_from_header(services.auth, x_demo_role)
        return {
            "role": actor.role.value,
            "actor_id": actor.actor_id,
            "capabilities": services.auth.capabilities(actor),
            # Which SOP governs each action, so the UI can cite the controlling
            # procedure instead of showing a bare permission name.
            "sop_refs": services.auth.action_sop_map(),
        }
