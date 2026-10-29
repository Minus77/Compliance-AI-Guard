"""FastAPI application factory.

The documented ``uvicorn apps.api.main:app`` entry point lives here. HTTP route
groups are registered from ``apps.api.routes``; this module owns service
composition, session middleware, and the public import compatibility surface.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.audit.metrics import Metrics
from compliance_guard.audit.trace import Tracer
from compliance_guard.integrations import (
    ConnectorRegistry,
    InMemoryContentSource,
    InMemoryReviewExport,
    InMemorySafetyIntake,
    seed_generic_records,
)
from compliance_guard.knowledge.glossary import default_glossary
from compliance_guard.knowledge.label_facts import LabelFactsStore
from compliance_guard.knowledge.retrieval import EvidenceRetriever
from compliance_guard.llm.gateway import ModelGateway
from compliance_guard.llm.registry import ModelRegistry
from compliance_guard.observability import format_log_record
from compliance_guard.policy.bundles import PolicyBundleStore
from compliance_guard.policy.publishing import RuleLifecycleStore
from compliance_guard.policy.workbench import RuleWorkbench
from compliance_guard.review.feedback import FeedbackStore
from compliance_guard.review.lifecycle import LifecycleStore
from compliance_guard.runtime_config import require_valid_configuration
from compliance_guard.runtime_paths import (
    config_dir as _config_dir,
    fixtures_dir as _fixtures_dir,
    runtime_config_path as _runtime_config_path,
    web_dir as _web_dir,
    writable_data_dir as _writable_data_dir,
)
from compliance_guard.security.authorization import AuthorizationService
from compliance_guard.security.sessions import SessionStore, announce_bootstrap_credential
from compliance_guard.workflow.checks import CheckService
from compliance_guard.workflow.conversations import ConversationGuard, ConversationStore
from compliance_guard.workflow.orchestrator import Orchestrator
from compliance_guard.workflow.precheck import PrecheckService

from .errors import ApiError, register_exception_handlers
from .routes import register_routes
from .schemas import *  # noqa: F403 - compatibility surface for apps.api.main callers
from .security import (  # noqa: F401 - compatibility surface
    SESSION_COOKIE,
    _CURRENT_SESSION,
    _actor_from_header,
    _default_author,
    _require_case_view,
    _require_config_actor,
    _require_owner_scope,
    _require_rule_manager,
    _require_rule_reader,
)

# Resolved through runtime_paths so the app works both from source and inside a
# PyInstaller bundle (where resources live under sys._MEIPASS and writable state
# must go to a per-user directory).
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = _config_dir()
DATA_DIR = _fixtures_dir().parent
WEB_DIR = _web_dir()


class _Services:
    """Plain namespace holding the composed service layer for one app instance."""

    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


def _session_store_path():
    """Where local accounts live. Overridable so a test never writes real accounts."""
    return _writable_data_dir() / "users.json"


def _rule_store_path():
    """Where published rule history lives, isolated from tests when overridden."""
    return _writable_data_dir() / "rules" / "rule_versions.json"


def _import_review_queue():
    from compliance_guard.review.tasks import ReviewQueue

    return ReviewQueue


def _import_decisions():
    from compliance_guard.review.decisions import DecisionService

    return DecisionService


def _production_services() -> _Services:
    registry = ModelRegistry(
        profiles_path=CONFIG_DIR / "model_profiles.json",
        routes_path=CONFIG_DIR / "task_routes.json",
        runtime_path=_runtime_config_path(),
        prompts_dir=CONFIG_DIR / "prompts",
    )
    registry.load_defaults()

    # Compose early so a fresh credential is printed before the server listens.
    sessions = SessionStore(path=_session_store_path())
    announce_bootstrap_credential("admin", sessions.bootstrap_password)

    auth = AuthorizationService()
    ledger = AuditLedger()
    tracer = Tracer()
    metrics = Metrics()
    gateway = ModelGateway(prompts_dir=CONFIG_DIR / "prompts")
    review_queue = _import_review_queue()(auth=auth, ledger=ledger, metrics=metrics)
    decisions = _import_decisions()(
        queue=review_queue, auth=auth, ledger=ledger, metrics=metrics
    )
    policy_store = PolicyBundleStore()
    rule_lifecycle = RuleLifecycleStore(path=_rule_store_path())
    policy_store.bind_lifecycle(rule_lifecycle)
    rule_workbench = RuleWorkbench(rule_lifecycle)
    label_facts_store = LabelFactsStore()
    precheck = PrecheckService(
        policy_store=policy_store,
        label_facts_store=label_facts_store,
    )
    orchestrator = Orchestrator(
        gateway=gateway,
        registry=registry,
        policy_store=policy_store,
        label_facts_store=label_facts_store,
        retriever=EvidenceRetriever(),
        auth=auth,
        ledger=ledger,
        tracer=tracer,
        metrics=metrics,
        review_queue=review_queue,
        decisions=decisions,
    )
    checks = CheckService(
        precheck=precheck,
        orchestrator=orchestrator,
        policy_store=policy_store,
        ledger=ledger,
    )
    conversations = ConversationGuard(
        checks=checks,
        store=ConversationStore(),
        policy_store=policy_store,
        gateway=gateway,
        ledger=ledger,
    )
    content_source = InMemoryContentSource()
    seed_generic_records(content_source)
    safety_intake = InMemorySafetyIntake()
    review_export = InMemoryReviewExport()
    connectors = ConnectorRegistry()
    for connector in (content_source, safety_intake, review_export):
        connectors.register(connector)
    return _Services(
        gateway=gateway,
        registry=registry,
        policy_store=policy_store,
        rule_lifecycle=rule_lifecycle,
        rule_workbench=rule_workbench,
        label_facts_store=label_facts_store,
        retriever=EvidenceRetriever(),
        auth=auth,
        ledger=ledger,
        tracer=tracer,
        metrics=metrics,
        review_queue=review_queue,
        decisions=decisions,
        orchestrator=orchestrator,
        checks=checks,
        conversations=conversations,
        connectors=connectors,
        content_source=content_source,
        safety_intake=safety_intake,
        review_export=review_export,
        feedback=FeedbackStore(),
        precheck=precheck,
        glossary=default_glossary(),
        lifecycle=LifecycleStore(),
        sessions=sessions,
    )


def _register_request_correlation(app: FastAPI) -> None:
    """Thread one id through every log line and resolve the session once."""

    @app.middleware("http")
    async def _correlate(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or (
            f"req-{uuid.uuid4().hex[:16]}"
        )
        request.state.request_id = request_id

        services = getattr(request.app.state, "services", None)
        store = getattr(services, "sessions", None)
        session = None
        if store is not None:
            session = store.resolve(request.cookies.get(SESSION_COOKIE))
        request.state.session = session
        token = _CURRENT_SESSION.set(session)
        try:
            path = request.url.path
            if (
                session is not None
                and session.must_change_password
                and path.startswith("/api/")
                and not path.startswith("/api/auth/")
            ):
                response = JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "code": "password_change_required",
                            "message": "change the initial password at /api/auth/change-password",
                        }
                    },
                )
            else:
                response = await call_next(request)
        finally:
            _CURRENT_SESSION.reset(token)
        response.headers["x-request-id"] = request_id
        print(
            format_log_record(
                "http_request",
                request_id=request_id,
                fields={
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                },
            ),
            flush=True,
        )
        return response


def create_app(services: Any | None = None) -> FastAPI:
    # Fail at boot rather than on the first request that touches bad config.
    require_valid_configuration()
    services = services or _production_services()
    app = FastAPI(
        title="Compliance AI Guard",
        version="0.1.0",
        description="Deterministic compliance model gateway demo",
    )
    app.state.services = services
    app.state.cases: dict[str, dict[str, Any]] = {}
    app.state.config_history: list[dict[str, Any]] = [
        {
            "version": services.registry.current_snapshot().version,
            "action": "loaded",
            "at": datetime.now(UTC).isoformat(),
        }
    ]
    app.state.config_drafts: dict[str, Any] = {"profiles": [], "routes": []}

    _register_request_correlation(app)
    register_exception_handlers(app)
    register_routes(app, services)
    return app


app = create_app()
