from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header

from compliance_guard.domain.models import ModelProfile, TaskRoute
from compliance_guard.llm.types import ModelConstraints, ModelRequest

from ..schemas import DraftPayload, ModelTestPayload
from ..security import _actor_from_header, _require_config_actor


def _masked_profile(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    if out.get("credential_ref"):
        out["credential_ref"] = "****"
    return out


def _masked_profiles(profiles: dict[str, Any]) -> dict[str, Any]:
    return {profile_id: _masked_profile(profile) for profile_id, profile in profiles.items()}


def _record_history(app: FastAPI, version: str, action: str) -> None:
    app.state.config_history.append(
        {
            "version": version,
            "action": action,
            "at": datetime.now(UTC).isoformat(),
            "event_id": f"config-{uuid.uuid4().hex}",
        }
    )


def register_routes(app: FastAPI, services: Any) -> None:
    @app.get("/api/config/models")
    def get_config_models(
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_config_actor(services.auth, x_demo_role)
        snapshot = services.registry.current_snapshot()
        return {
            "version": snapshot.version,
            "profiles": _masked_profiles(
                {k: v.model_dump(mode="json") for k, v in snapshot.profiles.items()}
            ),
            "routes": {k: v.model_dump(mode="json") for k, v in snapshot.routes.items()},
            "redacted": snapshot.redacted,
            "drafts": app.state.config_drafts,
            "history": app.state.config_history,
            "audit": [
                event.model_dump(mode="json") for event in services.registry.audit_events()
            ],
        }

    @app.put("/api/config/models")
    def put_config_models(
        payload: DraftPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_config_actor(services.auth, x_demo_role)
        for raw in payload.profiles:
            services.registry.draft(ModelProfile(**raw))
        for raw in payload.routes:
            services.registry.draft(TaskRoute(**raw))
        messages = services.registry.validate_draft()
        app.state.config_drafts = {
            "profiles": payload.profiles,
            "routes": payload.routes,
        }
        return {
            "status": "draft_staged",
            "messages": messages,
            "drafts": app.state.config_drafts,
        }

    @app.post("/api/config/models/test")
    def test_config_model(
        payload: ModelTestPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_config_actor(services.auth, x_demo_role)
        task_type = payload.task_type
        data_class = payload.data_class or "internal"
        region = payload.region or "CN"
        modality = payload.modality or "text"
        route = services.registry.resolve(task_type, modality, data_class, region)
        model_request = ModelRequest(
            scenario="normal",
            task_type=task_type,
            content=payload.content or "synthetic connectivity test",
            evidence_ids=[],
        )
        constraints = ModelConstraints(
            profile_id=route.primary_profile.profile_id,
            model_id=route.primary_profile.model_id,
            route_version=route.route_version,
            timeout_ms=route.primary_profile.timeout_ms,
            token_budget=route.primary_profile.token_budget,
            data_class=data_class,
            region=region,
        )
        raw = services.gateway.complete(task_type, model_request, constraints, route)
        return {
            "ok": raw.error_category is None,
            "provider": raw.provider,
            "model_id": raw.model_id,
            "profile_id": raw.profile_id,
            "route_version": raw.route_version,
            "fallback_used": raw.fallback_used,
            "latency_ms": raw.latency_ms,
            "error_category": raw.error_category,
        }

    @app.post("/api/config/publish")
    def publish_config(
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _actor_from_header(services.auth, x_demo_role)
        version = services.registry.publish(actor)
        _record_history(app, version, "publish")
        app.state.config_drafts = {"profiles": [], "routes": []}
        return {"status": "published", "version": version}

    @app.post("/api/config/rollback")
    def rollback_config(
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _actor_from_header(services.auth, x_demo_role)
        version = services.registry.rollback(actor)
        _record_history(app, version, "rollback")
        app.state.config_drafts = {"profiles": [], "routes": []}
        return {"status": "rolled_back", "version": version}
