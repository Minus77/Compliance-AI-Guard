from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from compliance_guard.runtime_config import retention_policy, validate_configuration
from compliance_guard.runtime_paths import config_dir, fixtures_dir, web_dir
from compliance_guard.workflow.scenario import demo_mode_enabled

WEB_DIR = web_dir()
DATA_DIR = fixtures_dir().parent


def _model_service_health(mode: str) -> dict[str, Any]:
    """Report whether a live model call could succeed, without leaking secrets."""
    if mode != "live":
        return {"required": False, "ready": True, "reason": "offline_fixtures"}

    from compliance_guard.llm.credentials import CredentialError, resolve_api_key

    try:
        resolve_api_key()
    except CredentialError:
        return {"required": True, "ready": False, "reason": "missing_credential"}

    endpoints_dir = config_dir() / "endpoints"
    if not any(endpoints_dir.glob("*.json")):
        return {"required": True, "ready": False, "reason": "missing_endpoint_mapping"}

    return {"required": True, "ready": True, "reason": "configured"}


def register_routes(app: FastAPI, services: Any) -> None:
    app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/health/live")
    def health_live() -> dict[str, Any]:
        """Is the process running?

        Deliberately touches nothing: no config read, no store, no model probe. A
        liveness check that consults dependencies will restart a healthy process
        because a downstream file was briefly unreadable.
        """
        return {"status": "ok", "check": "live"}

    @app.get("/health/ready")
    def health_ready() -> dict[str, Any]:
        """Can the process actually answer, and on which version of what?

        Reports each dependency separately with its version. "Ready: false" alone
        sends an operator hunting; naming the dependency and its version turns the
        answer into a next step.
        """
        report = validate_configuration()
        mode = os.getenv("LLM_MODE", "mock")
        service = _model_service_health(mode)
        return {
            "check": "ready",
            "ready": bool(report.ok and service.get("ready", True)),
            "mode": mode,
            "dependencies": report.dependency_payload(),
            "problems": list(report.problems),
            "model_service": service,
            "config_version": services.registry.current_snapshot().version,
            # An unlabelled demo shortcut is indistinguishable from a security hole,
            # so the posture is stated rather than inferred.
            "demo_mode": demo_mode_enabled(),
            # Counts and flags only: no username, no hash, no token.
            "sessions": services.sessions.summary(),
            # Declared, not implicit: the audit ledger has no expiry, and that
            # asymmetry is a compliance property worth being able to inspect.
            "retention": retention_policy(),
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        label = services.label_facts_store.current("PRODUCT-001", "CN")
        evidence_path = DATA_DIR / "fixtures" / "evidence.json"
        evidence_count = 0
        try:
            evidence_count = len(json.loads(evidence_path.read_text(encoding="utf-8"))["items"])
        except (OSError, KeyError, json.JSONDecodeError):
            evidence_count = 0
        mode = os.getenv("LLM_MODE", "mock")
        return {
            "status": "ok",
            "mode": mode,
            # Readiness is reported as booleans only. The key itself, its length,
            # and the resolved provider URL are never exposed: this endpoint is
            # unauthenticated so the UI can render a mode badge.
            "model_service": _model_service_health(mode),
            "knowledge_snapshot": {
                "id": "KNOW-2026-08-20",
                "label_version": label.version,
                "evidence_items": evidence_count,
            },
            "config_version": services.registry.current_snapshot().version,
        }
