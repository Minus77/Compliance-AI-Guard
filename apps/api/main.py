"""FastAPI application factory and route registration.

The app exposes the service layer built by Tasks 0-7 (orchestrator, review
queue, decision service, audit ledger, tracer, metrics, model registry) through
JSON routes and a single embedded three-workspace UI.

Identity comes from a **session**, resolved once in middleware. ``x-demo-role``
still works, but only with ``DEMO_MODE=1``, and the readiness endpoint states which
posture is active.

That gating is the point. The header let a caller name their own role, so changing
one request header was enough to publish model policy or read the audit trail: every
route checked permissions faithfully, against an identity the caller had simply
asserted. Scope is deliberately small -- a local session store, no identity provider,
no second factor -- so the trust boundary sits in the right place with a seam an SSO
integration can replace.

Role capabilities, once identity is established:

- Field representatives can submit cases and read their safe result.
- Reviewers can read evidence, review tasks, and decide.
- Admins/architects can draft, test, publish, and roll back model policy.

Security invariants enforced here:

- Errors are structured and never include raw PII or secrets; validation error
  ``input`` values are stripped before returning.
- The representative view receives only safe spans and tokens; raw content is
  never stored server-side and never returned.
- ``credential_ref`` values are masked in every config response; the registry
  rejects plaintext secrets at the source.
- ``LLM_MODE=mock`` remains the default and makes no network calls. With
  ``LLM_MODE=live`` the gateway calls a real provider, but the boundary is
  unchanged: text is masked before it leaves the process, the model only proposes
  candidates, the API key never appears in a response or audit event, and any
  provider failure degrades to human review rather than an approval.
"""

from __future__ import annotations

import contextvars
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.audit.metrics import Metrics
from compliance_guard.audit.trace import Tracer
from compliance_guard.domain.enums import Role, Severity
from compliance_guard.domain.models import (
    Actor,
    AuditEvent,
    CheckCaseRequest,
    ModelProfile,
    TaskRoute,
)
from compliance_guard.agents.icsr_assessment import assess_icsr
from compliance_guard.agents.icsr_followup import build_followup_form, followup_narrative
from compliance_guard.knowledge.glossary import DEFAULT_LOCALE, default_glossary
from compliance_guard.knowledge.label_facts import LabelFactsStore
from compliance_guard.knowledge.retrieval import EvidenceRetriever
from compliance_guard.integrations.source_registry import SourceRegistry
from compliance_guard.integrations.veeva_adapter import StaleVersionError
from compliance_guard.llm.gateway import ModelGateway
from compliance_guard.llm.registry import (
    DraftValidationError,
    ModelRegistry,
    RouteValidationError,
)
from compliance_guard.llm.types import ModelConstraints, ModelRequest
from compliance_guard.policy.bundles import PolicyBundleStore
from compliance_guard.review.feedback import FeedbackKind, FeedbackStore
from compliance_guard.review.lifecycle import LifecycleStore, NotificationKind
from compliance_guard.review.tasks import is_business_review
from compliance_guard.observability import format_log_record
from compliance_guard.runtime_config import (
    require_valid_configuration,
    retention_policy,
    validate_configuration,
)
from compliance_guard.runtime_paths import (
    config_dir as _config_dir,
    fixtures_dir as _fixtures_dir,
    runtime_config_path as _runtime_config_path,
    writable_data_dir as _writable_data_dir,
    web_dir as _web_dir,
)
from compliance_guard.security.authorization import AuthorizationService
from compliance_guard.security.pii_gateway import SanitizeContext, sanitize
from compliance_guard.security.sessions import (
    SessionError,
    SessionStore,
    announce_bootstrap_credential,
)
from compliance_guard.workflow.orchestrator import Orchestrator
from compliance_guard.workflow.checks import CheckRequest, CheckService
from compliance_guard.workflow.precheck import PrecheckService
from compliance_guard.workflow.scenario import demo_mode_enabled

# Resolved through runtime_paths so the app works both from source and inside a
# PyInstaller bundle (where resources live under sys._MEIPASS and writable state
# must go to a per-user directory).
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = _config_dir()
DATA_DIR = _fixtures_dir().parent
WEB_DIR = _web_dir()


# ---------------------------------------------------------------------------
# Application services composition
# ---------------------------------------------------------------------------


class _Services:
    """Plain namespace holding the composed service layer for one app instance."""

    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


def _session_store_path():
    """Where local accounts live. Overridable so a test never writes real accounts."""
    return _writable_data_dir() / "users.json"


def _production_services() -> _Services:
    registry = ModelRegistry(
        profiles_path=CONFIG_DIR / "model_profiles.json",
        routes_path=CONFIG_DIR / "task_routes.json",
        runtime_path=_runtime_config_path(),
        prompts_dir=CONFIG_DIR / "prompts",
    )
    registry.load_defaults()

    # Composed early so the credential is announced before the server starts
    # listening. Only ever announces a *freshly generated* password: an
    # established account returns None and stays silent.
    #
    # This sits in composition rather than in an entry point because the
    # documented `uvicorn apps.api.main:app` command previously generated a
    # password and printed nothing, which is a first-run lockout -- the account
    # exists, the password is unknowable, and the sign-in form cannot be cleared.
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
    )
    return _Services(
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
        orchestrator=orchestrator,
        checks=checks,
        sources=SourceRegistry(ledger=ledger),
        feedback=FeedbackStore(),
        precheck=precheck,
        glossary=default_glossary(),
        lifecycle=LifecycleStore(),
        sessions=sessions,
    )


def _model_service_health(mode: str) -> dict[str, Any]:
    """Report whether a live model call could succeed, without leaking secrets.

    In live mode a missing key or missing endpoint mapping is an operational
    fault the user must see: the system still refuses to release high-risk
    content, but silently degrading to "looks fine" would be worse than an
    honest warning. Only booleans and a stable reason code are returned.
    """
    if mode != "live":
        return {"required": False, "ready": True, "reason": "offline_fixtures"}

    from compliance_guard.llm.credentials import CredentialError, resolve_api_key

    try:
        resolve_api_key()
    except CredentialError:
        return {"required": True, "ready": False, "reason": "missing_credential"}

    endpoints_dir = CONFIG_DIR / "endpoints"
    if not any(endpoints_dir.glob("*.json")):
        return {"required": True, "ready": False, "reason": "missing_endpoint_mapping"}

    return {"required": True, "ready": True, "reason": "configured"}


def _import_review_queue():
    from compliance_guard.review.tasks import ReviewQueue

    return ReviewQueue


def _import_decisions():
    from compliance_guard.review.decisions import DecisionService

    return DecisionService


# ---------------------------------------------------------------------------
# Structured errors
# ---------------------------------------------------------------------------


class ApiError(Exception):
    """Structured, client-safe error with a stable code."""

    def __init__(self, code: str, status: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.message = message


def _error_body(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


def _redact_validation_details(details: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Strip the ``input`` field from validation details (may hold raw PII)."""
    redacted: list[dict[str, Any]] = []
    for item in details:
        redacted.append({key: value for key, value in item.items() if key != "input"})
    return redacted


def _register_request_correlation(app: FastAPI) -> None:
    """Thread one id through every log line for a request, and return it.

    A single submission touches masking, resolution, retrieval, the model, the
    policy engine and the review queue. Without a shared id, answering "what
    happened to this one" means comparing timestamps and guessing.

    A caller-supplied ``x-request-id`` is preserved so a trace can span the
    browser and the server; otherwise one is minted. It is echoed on the response
    so the value is available to whoever is looking at a problem.
    """

    @app.middleware("http")
    async def _correlate(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or f"req-{uuid.uuid4().hex[:16]}"
        request.state.request_id = request_id

        # Resolve the session here, once, rather than in each route. A route that
        # forgets to check is an unauthenticated route, and there are ~30 of them.
        services = getattr(request.app.state, "services", None)
        store = getattr(services, "sessions", None)
        session = None
        if store is not None:
            session = store.resolve(request.cookies.get(SESSION_COOKIE))
        request.state.session = session
        token = _CURRENT_SESSION.set(session)
        try:
            response = await call_next(request)
        finally:
            # Always reset: a leaked context variable would let one request's
            # identity surface in the next one served on the same task.
            _CURRENT_SESSION.reset(token)
        response.headers["x-request-id"] = request_id
        # Path and status only. Query strings and bodies can carry narrative text,
        # and an access log is not a place to accumulate it.
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


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def _on_request_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = _redact_validation_details(exc.errors())
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "request validation failed",
                    "details": details,
                }
            },
        )

    @app.exception_handler(ValidationError)
    async def _on_model_validation(request: Request, exc: ValidationError) -> JSONResponse:
        details = _redact_validation_details(exc.errors())
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "payload validation failed",
                    "details": details,
                }
            },
        )

    @app.exception_handler(ApiError)
    async def _on_api_error(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content=_error_body(exc.code, exc.message))

    @app.exception_handler(PermissionError)
    async def _on_permission(request: Request, exc: PermissionError) -> JSONResponse:
        return JSONResponse(status_code=403, content=_error_body("forbidden", str(exc)))

    @app.exception_handler(KeyError)
    async def _on_key_error(request: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(status_code=404, content=_error_body("not_found", "resource not found"))

    @app.exception_handler(ValueError)
    async def _on_value_error(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content=_error_body("bad_request", str(exc)))

    @app.exception_handler(DraftValidationError)
    async def _on_draft_error(request: Request, exc: DraftValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=400, content=_error_body("draft_validation_error", str(exc))
        )

    @app.exception_handler(RouteValidationError)
    async def _on_route_error(request: Request, exc: RouteValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=400, content=_error_body("route_validation_error", str(exc))
        )

    @app.exception_handler(StaleVersionError)
    async def _on_stale_version(request: Request, exc: StaleVersionError) -> JSONResponse:
        # A stale source version is a caller/upstream-ordering problem, not an
        # internal fault: the adapter refused to trust an outdated event version.
        return JSONResponse(
            status_code=409, content=_error_body("stale_source_version", str(exc))
        )

    @app.exception_handler(StarletteHTTPException)
    async def _on_http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body("http_error", str(exc.detail)),
        )

    @app.exception_handler(Exception)
    async def _on_unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Never echo the exception message: it may contain request content.
        return JSONResponse(
            status_code=500,
            content=_error_body("internal_error", "unexpected internal error"),
        )


# ---------------------------------------------------------------------------
# Demo role helpers
# ---------------------------------------------------------------------------


# The session resolved for the current request, set by middleware.
#
# A context variable rather than a parameter because ~30 routes already take the
# role as a header argument. Threading a new parameter through all of them would
# be a large mechanical diff with a real chance of missing one -- and a missed
# route is an unauthenticated route. Resolving once in middleware means a route
# cannot forget.
_CURRENT_SESSION: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "cg_current_session", default=None
)

SESSION_COOKIE = "cg_session"


def _actor_from_header(auth: AuthorizationService, header: str | None) -> Actor:
    """Resolve who is calling: session first, header only in a labelled demo.

    ``x-demo-role`` let a caller name their own role, so one changed header was
    enough to publish model policy or read the audit trail (defect P-3). Every
    route checked permissions faithfully -- against an identity the caller had
    simply asserted.

    The header still works with ``DEMO_MODE=1``, because a walkthrough that needs
    a login for each of four roles is a worse demo. Outside that flag it does
    nothing at all.
    """
    session = _CURRENT_SESSION.get()
    if session is not None:
        return session.actor

    if header and demo_mode_enabled():
        try:
            return auth.actor_from_header(header)
        except ValueError:
            raise ApiError("forbidden", 403, "unknown x-demo-role") from None

    if header and not demo_mode_enabled():
        # Say precisely why, so an operator does not spend an afternoon on it.
        raise ApiError(
            "unauthenticated",
            401,
            "x-demo-role is only honoured with DEMO_MODE=1; sign in at /api/auth/login",
        )

    raise ApiError("unauthenticated", 401, "sign in at /api/auth/login")


def _default_field_rep() -> Actor:
    return AuthorizationService.actor_from_header("field_rep")


def _require_config_actor(auth: AuthorizationService, header: str | None) -> Actor:
    actor = _actor_from_header(auth, header)
    if not (auth.can(actor, "config_publish") or auth.can(actor, "architecture_review")):
        raise PermissionError(f"config management denied for role {actor.role.value!r}")
    return actor


def _require_case_view(auth: AuthorizationService, header: str | None) -> Actor:
    """Resolve the demo actor and require case-read permission.

    Any role that can view a case summary may read case detail; admins
    (config managers) may also read any case.
    """
    actor = _actor_from_header(auth, header)
    if not (auth.can(actor, "view_case_summary") or auth.can(actor, "config_publish")):
        raise PermissionError(f"case read denied for role {actor.role.value!r}")
    return actor


def _require_owner_scope(actor: Actor, record: dict[str, Any]) -> None:
    """Field representatives may only read records they submitted.

    Reviewer/admin roles pass through and may read any case.
    """
    if actor.role is Role.FIELD_REP and record.get("submitted_by") != actor.actor_id:
        raise PermissionError(f"case read denied for role {actor.role.value!r}")


# ---------------------------------------------------------------------------
# Config masking helpers
# ---------------------------------------------------------------------------


def _masked_profile(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    if out.get("credential_ref"):
        out["credential_ref"] = "****"
    return out


def _masked_profiles(profiles: dict[str, Any]) -> dict[str, Any]:
    return {profile_id: _masked_profile(profile) for profile_id, profile in profiles.items()}


# ---------------------------------------------------------------------------
# Request payloads
# ---------------------------------------------------------------------------


class DecisionPayload(BaseModel):
    decision: str
    reason: str = ""


class LoginPayload(BaseModel):
    username: str = ""
    password: str = ""


class ChangePasswordPayload(BaseModel):
    current: str = ""
    replacement: str = ""


class PrecheckPayload(BaseModel):
    """Draft text submitted for a deterministic pre-check.

    Deliberately smaller than ``CheckCaseRequest``: a draft in progress has no
    case id, no idempotency key and no source version, because it is not a
    submission and must not become a record.
    """

    tenant_id: str = "TENANT-CN"
    content: str = ""
    market: str = "CN"
    language: str = "zh-CN"
    product_id: str = ""
    source: str = "call_report"
    content_type: str = "customer_interaction_note"
    content_subtype: str = ""
    therapeutic_area: str = ""
    client_content_version: str = ""
    structured_fields: dict[str, Any] = Field(default_factory=dict)
    locale: str = DEFAULT_LOCALE


class RevisePayload(BaseModel):
    """A follow-up version of a case the author already submitted."""

    content: str
    structured_fields: dict[str, Any] = Field(default_factory=dict)


class AppealPayload(BaseModel):
    """A disagreement with a decision. The reason is mandatory."""

    reason: str = ""


class AppealResolutionPayload(BaseModel):
    upheld: bool = True
    reason: str = ""


class FollowupPayload(BaseModel):
    """Answers to the outstanding ICSR questions.

    Free-form strings on purpose: the questions ask for a description ("成年男性，
    60-65岁"), never for an identifier, so there is no structured identity to
    validate against.
    """

    answers: dict[str, Any] = Field(default_factory=dict)


class BatchDecisionPayload(BaseModel):
    task_ids: list[str] = Field(default_factory=list)
    decision: str = ""
    reason: str = ""


class UsabilityPayload(BaseModel):
    """One usability event.

    ``context`` accepts only small scalar flags. It exists so a rate can be split
    by "was a warning showing at the time", not as a general-purpose bag: a
    telemetry endpoint that accepts arbitrary strings is a place narrative text
    eventually lands.
    """

    event: str
    context: dict[str, Any] = Field(default_factory=dict)


class FeedbackPayload(BaseModel):
    """A reviewer's report that the system got one case wrong."""

    kind: str
    reason: str = ""


class DraftPayload(BaseModel):
    profiles: list[dict[str, Any]] = Field(default_factory=list)
    routes: list[dict[str, Any]] = Field(default_factory=list)
    draft: list[Any] | None = None


class ModelTestPayload(BaseModel):
    task_type: str
    modality: str | None = None
    data_class: str | None = None
    region: str | None = None
    content: str | None = None


class AttachmentPayload(BaseModel):
    """Register an image/audio reference as a content part.

    Only metadata is accepted. The binary is never uploaded or stored: a
    call-report attachment can carry PHI, and this demo's invariant is that raw
    content never lands server-side. The returned ``mock://`` ref is what the
    multimodal extraction route would dereference in a real deployment.
    """

    kind: str  # "image" | "audio"
    filename: str
    mime_type: str = ""
    size_bytes: int = Field(default=0, ge=0)
    duration_seconds: float | None = Field(default=None, ge=0)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(services: Any | None = None) -> FastAPI:
    # Validate before composing anything. A malformed policy bundle or an expired
    # validity window used to surface on the first request that needed the file,
    # which means the first *user* discovers it mid-sentence as an opaque error.
    # Failing here instead makes the problem the operator's, at boot, with the
    # filename in the message.
    require_valid_configuration()
    services = services or _production_services()
    app = FastAPI(
        title="Compliance AI Guard",
        version="0.1.0",
        description="Deterministic compliance model gateway demo",
    )
    app.state.services = services
    app.state.cases: dict[str, dict[str, Any]] = {}
    initial_version = services.registry.current_snapshot().version
    app.state.config_history: list[dict[str, Any]] = [
        {
            "version": initial_version,
            "action": "loaded",
            "at": datetime.now(UTC).isoformat(),
        }
    ]
    app.state.config_drafts: dict[str, Any] = {"profiles": [], "routes": []}

    _register_request_correlation(app)
    _register_exception_handlers(app)

    # -- UI ------------------------------------------------------------------

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")

    # -- health --------------------------------------------------------------

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

    # -- authentication ------------------------------------------------------

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

    # -- glossary ------------------------------------------------------------

    @app.get("/api/glossary")
    def get_glossary(locale: str = DEFAULT_LOCALE) -> dict[str, Any]:
        """Plain-language vocabulary for every finding type, decision and term.

        Unauthenticated on purpose: it is static explanatory text with no case
        data in it, and the UI needs it before a user has done anything. Served
        from one file so the interface, the API and any report cannot drift into
        explaining the same term three different ways.
        """
        return services.glossary.payload(locale)

    # -- shared content checks -----------------------------------------------

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
            actor = _default_field_rep()
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

    # -- cases ---------------------------------------------------------------

    @app.post("/api/cases/precheck")
    def precheck_case(payload: PrecheckPayload) -> dict[str, Any]:
        """Deterministic pre-check for text still being written.

        No model call, no case, no stored narrative. Findings are a subset of what
        submission would report, phrased in plain language, so a hint can never
        contradict the final answer.
        """
        result = services.checks.precheck_preview(
            CheckRequest(
                tenant_id=payload.tenant_id,
                content=payload.content,
                market=payload.market,
                language=payload.language,
                product_id=payload.product_id,
                content_type=payload.content_type,
                content_subtype=payload.content_subtype,
                therapeutic_area=payload.therapeutic_area,
                business_fields=payload.structured_fields,
                client_content_version=payload.client_content_version,
            ),
            locale=payload.locale,
        )
        return result.model_dump(mode="json")



    @app.get("/api/cases")
    def list_cases(
        request: Request,
        scope: str = "mine",
        decision: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """List submitted cases, newest first.

        Submitting used to be the end of the road: no list, no way to look back at
        what you sent. Work you cannot see is work you stop trusting, and a
        representative who does not trust the tool writes shorter notes.

        ``scope=all`` is *narrowed* rather than refused for a field representative.
        Returning an error would tell them the wider set exists; returning their own
        records answers the question they can legitimately ask.
        """
        actor = _require_case_view(services.auth, x_demo_role)
        records = list(request.app.state.cases.values())

        if actor.role is Role.FIELD_REP or scope == "mine":
            records = [r for r in records if r.get("submitted_by") == actor.actor_id]
        if decision:
            wanted = str(decision).strip().casefold()
            records = [
                r for r in records if str(r["response"].get("decision", "")).casefold() == wanted
            ]

        records.sort(key=lambda r: r.get("created_at", ""), reverse=True)

        # Opaque cursor over a stable ordering. An offset would silently skip a
        # record whenever a new case lands between two pages.
        start = 0
        if cursor:
            for index, record in enumerate(records):
                if record["case_id"] == cursor:
                    start = index
                    break
        bounded = max(1, min(limit, 100))
        page = records[start : start + bounded]
        remaining = records[start + bounded :]

        rows = []
        for record in page:
            response_body = record["response"]
            decision_value = str(response_body.get("decision", ""))
            card = services.glossary.explain_decision(decision_value)
            rows.append(
                {
                    "case_id": record["case_id"],
                    "decision": decision_value,
                    "decision_label": card.label,
                    "next_step": card.next_step,
                    "status": response_body.get("status"),
                    "product_id": (response_body.get("product") or {}).get("product_id"),
                    "market": response_body.get("market"),
                    "finding_types": [
                        f.get("type") for f in response_body.get("findings", [])
                    ],
                    "parent_case_id": record.get("parent_case_id"),
                    "submitted_by": record.get("submitted_by"),
                    "created_at": record.get("created_at"),
                }
            )
        return {
            "scope": "mine" if (actor.role is Role.FIELD_REP or scope == "mine") else "all",
            "count": len(rows),
            "total": len(records),
            "cases": rows,
            "next_cursor": remaining[0]["case_id"] if remaining else None,
        }

    # -- master data ---------------------------------------------------------

    @app.get("/api/master-data/products")
    def list_products(market: str | None = None) -> dict[str, Any]:
        """Products with the label version currently in force.

        Only the current version is offered. A picker that lists a retired label
        would let someone write against approval terms that no longer apply, which
        is an off-label claim the tool itself created.

        Unauthenticated like ``/api/glossary``: this is product reference data with
        no case content in it, and the editor needs it before anything is typed.
        """
        products = services.label_facts_store.products(market=market)
        return {
            "count": len(products),
            "markets": services.label_facts_store.markets(),
            "products": [
                {
                    "product_id": label.product_id,
                    "market": label.market,
                    "label_version": label.version,
                    "indication": label.indication,
                    "indication_id": label.indication_id,
                    "population": label.population,
                    "dose": label.dose,
                    "route": label.route,
                    "effective_from": (
                        label.effective_from.isoformat() if label.effective_from else None
                    ),
                }
                for label in products
            ],
        }

    # -- notifications -------------------------------------------------------

    @app.get("/api/notifications")
    def list_notifications(
        unread: int = 0,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Outcomes addressed to the caller.

        Only outcomes that need the author to act are pushed here. A clean release
        updates their list silently: notifying on every state change teaches people
        to dismiss without reading, and then the one that matters is dismissed too.
        """
        actor = _actor_from_header(services.auth, x_demo_role)
        # Sweep opportunistically rather than on a timer. This is a single local
        # process with no scheduler, and a background thread whose only job is to
        # delete things is a poor trade: the sweep is cheap, and the moment someone
        # reads their notifications is exactly when a stale one would be visible.
        #
        # `keep_unread` protects an outcome the author has not seen: expiring that
        # would lose the result silently, which is the dead end notifications exist
        # to prevent.
        services.lifecycle.purge_expired(keep_unread=True)
        items = services.lifecycle.notifications(actor.actor_id, unread_only=bool(unread))
        return {
            "count": len(items),
            "unread_count": services.lifecycle.unread_count(actor.actor_id),
            "notifications": [item.model_dump(mode="json") for item in items],
        }

    @app.post("/api/notifications/{notification_id}/read")
    def mark_notification_read(
        notification_id: str,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _actor_from_header(services.auth, x_demo_role)
        note = services.lifecycle.mark_read(notification_id, recipient_id=actor.actor_id)
        return note.model_dump(mode="json")

    @app.post("/api/cases/check")
    def check_case(
        request: Request,
        payload: CheckCaseRequest,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        # An anonymous submission is allowed only in a labelled demo; otherwise the
        # author of a compliance record must be a known person.
        if request.state.session is not None or x_demo_role:
            actor = _actor_from_header(services.auth, x_demo_role)
        elif demo_mode_enabled():
            actor = _default_field_rep()
        else:
            raise ApiError("unauthenticated", 401, "sign in at /api/auth/login")
        response = services.checks.submit_case(payload, actor)
        safe = sanitize(payload.content, SanitizeContext(tenant_id=payload.tenant_id))
        stored = {
            "case_id": response.case_id,
            "response": response.model_dump(mode="json"),
            "safe_view": {"tokenized_text": safe.model_text, "spans": safe.spans},
            "submitted_by": actor.actor_id,
            "created_at": datetime.now(UTC).isoformat(),
        }
        request.app.state.cases[response.case_id] = stored
        body = dict(stored["response"])
        body["safe_view"] = stored["safe_view"]
        return body

    @app.get("/api/cases/{case_id}")
    def get_case(
        request: Request,
        case_id: str,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _require_case_view(services.auth, x_demo_role)
        record = request.app.state.cases.get(case_id)
        if record is None:
            raise KeyError(case_id)
        _require_owner_scope(actor, record)
        body = dict(record["response"])
        body["safe_view"] = record["safe_view"]
        return body

    @app.post("/api/cases/{case_id}/revise")
    def revise_case(
        request: Request,
        case_id: str,
        payload: RevisePayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Submit a follow-up version of a case, keeping the original intact.

        Being blocked used to mean retyping from nothing, which is the fastest way
        to teach someone to write less. The revision is a *new* case pointing at its
        parent, so the reviewer sees "version 2, previous one returned because X"
        and the original keeps its own decision forever (21 CFR Part 11 §11.10(e)).
        """
        actor = _require_case_view(services.auth, x_demo_role)
        parent = request.app.state.cases.get(case_id)
        if parent is None:
            raise KeyError(case_id)
        # Only the author revises their own narrative. A reviewer who disagrees has
        # the decision path; rewriting someone else's account is not a review action.
        if parent.get("submitted_by") != actor.actor_id:
            raise PermissionError("only the author of a case may revise it")

        parent_body = parent["response"]
        revision = CheckCaseRequest(
            case_id=f"req-revision-{uuid.uuid4().hex[:12]}",
            tenant_id=parent.get("tenant_id") or "TENANT-CN",
            content=payload.content,
            content_parts=[],
            source=str(parent.get("source") or "call_report"),
            source_record_id=str(parent.get("source_record_id") or f"SR-{case_id}"),
            source_version="v1",
            market=str(parent_body.get("market") or "CN"),
            language=str(parent_body.get("language") or "zh-CN"),
            product_id=str((parent_body.get("product") or {}).get("product_id") or ""),
            channel="call_report",
            received_at=datetime.now(UTC),
            idempotency_key=f"idem-revision-{uuid.uuid4().hex[:12]}",
            extensions={
                "entities": [],
                "structured_fields": dict(payload.structured_fields),
            },
        )
        response = services.orchestrator.run_check_case(revision)
        safe = sanitize(payload.content, SanitizeContext(tenant_id=revision.tenant_id))
        stored = {
            "case_id": response.case_id,
            "response": response.model_dump(mode="json"),
            "safe_view": {"tokenized_text": safe.model_text, "spans": safe.spans},
            "submitted_by": actor.actor_id,
            "created_at": datetime.now(UTC).isoformat(),
            "parent_case_id": case_id,
            "tenant_id": revision.tenant_id,
        }
        request.app.state.cases[response.case_id] = stored

        services.ledger.append(
            AuditEvent(
                event_id=f"audit-{uuid.uuid4().hex}",
                case_id=response.case_id,
                trace_id=response.trace_id,
                event_type="case_revised",
                occurred_at=datetime.now(UTC),
                actor=actor,
                payload={
                    "parent_case_id": case_id,
                    "parent_decision": str(parent_body.get("decision", "")),
                    "revision_decision": response.decision.value,
                },
            )
        )
        body = dict(stored["response"])
        body["safe_view"] = stored["safe_view"]
        body["parent_case_id"] = case_id
        return body

    @app.post("/api/cases/{case_id}/appeal")
    def appeal_case(
        request: Request,
        case_id: str,
        payload: AppealPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Disagree with a decision. Deliberately does not change it.

        Without a channel to disagree, the only route past a false positive is to
        write less. But an appeal that lifts its own block is a bypass with a polite
        name, so this creates work for a person and leaves the decision standing
        until someone with authority signs a change.
        """
        actor = _require_case_view(services.auth, x_demo_role)
        record = request.app.state.cases.get(case_id)
        if record is None:
            raise KeyError(case_id)
        _require_owner_scope(actor, record)
        try:
            appeal = services.lifecycle.raise_appeal(
                case_id=case_id,
                reason=payload.reason,
                actor=actor,
                decision_at_appeal=str(record["response"].get("decision", "")),
            )
        except ValueError as error:
            raise ApiError("invalid_appeal", 422, str(error)) from None

        services.ledger.append(
            AuditEvent(
                event_id=f"audit-{uuid.uuid4().hex}",
                case_id=case_id,
                trace_id=str(record["response"].get("trace_id", "")),
                event_type="case_appealed",
                occurred_at=datetime.now(UTC),
                actor=actor,
                payload={
                    "appeal_id": appeal.appeal_id,
                    "decision_at_appeal": appeal.decision_at_appeal,
                    "reason": appeal.reason,
                    # Stated explicitly so the record shows the block was not lifted.
                    "decision_unchanged": True,
                },
            )
        )
        return appeal.model_dump(mode="json")

    @app.get("/api/appeals")
    def list_appeals(
        pending: int = 0,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Open appeals plus the rate, which is a signal about the rules.

        A sustained high overturn rate is not a story about appeals; it says the
        rules are too tight and should be fixed at the rule rather than absorbed
        case by case by whoever is on the queue.
        """
        actor = _actor_from_header(services.auth, x_demo_role)
        services.auth.require(actor, "review_case")
        appeals = services.lifecycle.appeals(pending_only=bool(pending))
        return {
            "count": len(appeals),
            "appeals": [item.model_dump(mode="json") for item in appeals],
            "summary": services.lifecycle.appeal_summary(),
        }

    @app.post("/api/appeals/{appeal_id}/resolve")
    def resolve_appeal(
        appeal_id: str,
        payload: AppealResolutionPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Close an appeal with a reason, and tell the author the outcome."""
        actor = _actor_from_header(services.auth, x_demo_role)
        services.auth.require(actor, "review_case")
        try:
            appeal = services.lifecycle.resolve_appeal(
                appeal_id, actor=actor, upheld=payload.upheld, reason=payload.reason
            )
        except ValueError as error:
            raise ApiError("invalid_appeal_resolution", 422, str(error)) from None

        outcome = "维持原判定" if payload.upheld else "已改判，请查看最新结论"
        services.lifecycle.notify(
            case_id=appeal.case_id,
            recipient_id=appeal.raised_by,
            kind=NotificationKind.APPEAL_RESOLVED,
            title=f"你的申诉有结论了：{outcome}",
            body=appeal.resolution_reason,
            next_step=(
                "如仍有疑问，请联系合规同事。" if payload.upheld else "请在「我的记录」中查看更新后的结论。"
            ),
            decision=appeal.decision_at_appeal,
        )
        services.ledger.append(
            AuditEvent(
                event_id=f"audit-{uuid.uuid4().hex}",
                case_id=appeal.case_id,
                trace_id="",
                event_type="appeal_resolved",
                occurred_at=datetime.now(UTC),
                actor=actor,
                payload={
                    "appeal_id": appeal.appeal_id,
                    "status": appeal.status.value,
                    "reason": appeal.resolution_reason,
                },
            )
        )
        return appeal.model_dump(mode="json")

    @app.post("/api/cases/{case_id}/followup")
    def submit_followup(
        request: Request,
        case_id: str,
        payload: FollowupPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Supply the missing ICSR elements and re-run the assessment.

        The answers are folded into the narrative and the *same* deterministic
        assessment runs again. One code path matters here: a separate structured
        path would let the four criteria be satisfied one way on submission and
        another way on follow-up, and the two would drift.
        """
        actor = _require_case_view(services.auth, x_demo_role)
        record = request.app.state.cases.get(case_id)
        if record is None:
            raise KeyError(case_id)
        _require_owner_scope(actor, record)

        addition = followup_narrative(payload.answers)
        if not addition:
            raise ApiError("empty_followup", 422, "no answers were provided")

        response_body = record["response"]
        merged = f"{record['safe_view']['tokenized_text']}。{addition}"
        assessment = assess_icsr(
            merged,
            received_at=datetime.now(UTC),
            product_id=str((response_body.get("product") or {}).get("product_id") or ""),
            reporter_known=True,
            patient_entity_present=bool(response_body.get("entities")),
        )
        icsr_payload = assessment.model_dump(mode="json")
        # Preserve the cross-check flags computed at submission: they describe the
        # policy/assessment relationship, which follow-up answers do not change.
        icsr_payload["policy_flagged_safety"] = (response_body.get("icsr") or {}).get(
            "policy_flagged_safety", False
        )
        icsr_payload["assessment_conflict"] = (response_body.get("icsr") or {}).get(
            "assessment_conflict", False
        )

        response_body["icsr"] = icsr_payload
        response_body["followup"] = build_followup_form(icsr_payload).model_dump(mode="json")
        record["followup_answers"] = dict(payload.answers)

        services.ledger.append(
            AuditEvent(
                event_id=f"audit-{uuid.uuid4().hex}",
                case_id=case_id,
                trace_id=str(response_body.get("trace_id", "")),
                event_type="icsr_followup",
                occurred_at=datetime.now(UTC),
                actor=actor,
                payload={
                    # Which questions were answered, never the answers: an audit
                    # payload is not a place for a patient description to settle.
                    "answered_fields": sorted(payload.answers),
                    "criteria_met_count": assessment.criteria_met_count,
                    "valid_icsr": assessment.valid_icsr,
                    "missing_criteria": list(assessment.missing_criteria),
                },
            )
        )
        return {
            "case_id": case_id,
            "icsr": icsr_payload,
            "followup": response_body["followup"],
        }

    @app.get("/api/cases/{case_id}/export")
    def export_case(
        request: Request,
        case_id: str,
        format: str = "json",  # noqa: A002 - the query parameter is named `format`
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Export one case's full evidence chain for inspection.

        Restricted to ``audit_export``: this is the inspection artefact, and it
        names who decided what. It carries the chain verification result inline so
        the export and its integrity statement cannot be separated.

        A PDF request degrades to JSON when the optional renderer is absent rather
        than failing. An inspector asking for a record should never be told "no"
        because of a missing local dependency.
        """
        actor = _actor_from_header(services.auth, x_demo_role)
        services.auth.require(actor, "audit_export")
        record = request.app.state.cases.get(case_id)
        if record is None:
            raise KeyError(case_id)

        response_body = record["response"]
        events = [
            event.model_dump(mode="json") for event in services.ledger.for_case(case_id)
        ]
        requested = str(format or "json").strip().casefold()
        degraded_reason = ""
        resolved_format = "json"
        if requested == "pdf":
            try:
                import reportlab  # noqa: F401
            except ImportError:
                degraded_reason = (
                    "PDF 渲染组件（reportlab）未安装，已改为提供同等内容的 JSON 导出。"
                )
            else:
                resolved_format = "pdf"

        payload = {
            "case_id": case_id,
            "format": resolved_format,
            "degraded_reason": degraded_reason,
            "exported_at": datetime.now(UTC).isoformat(),
            "exported_by": actor.actor_id,
            "input_hash": next(
                (
                    event["payload"].get("input_hash")
                    for event in events
                    if event.get("event_type") == "case_received"
                ),
                "",
            ),
            # The masked narrative only. The original text is never stored server
            # side, so there is nothing rawer that could be exported by mistake.
            "masked_text": record["safe_view"]["tokenized_text"],
            "decision": response_body.get("decision"),
            "guidance": response_body.get("guidance", {}),
            "findings": response_body.get("findings", []),
            "evidence": response_body.get("evidence", []),
            "icsr": response_body.get("icsr", {}),
            "versions": {
                "policy_version": response_body.get("policy_version"),
                "knowledge_snapshot_id": response_body.get("knowledge_snapshot_id"),
                "route_version": response_body.get("route_version"),
                "prompt_version": response_body.get("prompt_version"),
                "model_profile_id": response_body.get("model_profile_id"),
                "model_version": response_body.get("model_version"),
            },
            "audit_events": events,
            "chain_verification": services.ledger.verify().model_dump(mode="json"),
        }

        services.ledger.append(
            AuditEvent(
                event_id=f"audit-{uuid.uuid4().hex}",
                case_id=case_id,
                trace_id=str(response_body.get("trace_id", "")),
                event_type="case_exported",
                occurred_at=datetime.now(UTC),
                actor=actor,
                payload={
                    "format": resolved_format,
                    "requested_format": requested,
                    "degraded": bool(degraded_reason),
                    "event_count": len(events),
                },
            )
        )
        return payload

    @app.get("/api/cases/{case_id}/trace")
    def get_case_trace(
        request: Request,
        case_id: str,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _require_case_view(services.auth, x_demo_role)
        record = request.app.state.cases.get(case_id)
        if record is None:
            raise KeyError(case_id)
        _require_owner_scope(actor, record)
        spans = [span.model_dump(mode="json") for span in services.tracer.spans(case_id=case_id)]
        events = [
            event.model_dump(mode="json") for event in services.ledger.for_case(case_id)
        ]
        return {
            "case_id": case_id,
            "trace_id": record["response"]["trace_id"],
            "spans": spans,
            "audit_events": events,
        }

    # -- reviews -------------------------------------------------------------

    @app.get("/api/reviews")
    def list_reviews(
        scope: str = "business",
        severity: str | None = None,
        required_role: str | None = None,
        sla_breach: int = 0,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _actor_from_header(services.auth, x_demo_role)
        services.auth.require(actor, "review_case")
        pending = services.review_queue.pending()
        # The professional review queue is for medical/compliance business
        # judgement. Platform-security items (prompt injection, permission
        # failure, irreversible write) route to security/admin and are excluded
        # by default: a medical reviewer cannot act on them. Nothing is
        # suppressed -- the decision stays blocked, the finding stays on the
        # case, and ?scope=all still returns them for security/audit use.
        business = [task for task in pending if is_business_review(task)]
        selected = pending if scope == "all" else business

        if severity:
            wanted = str(severity).strip().upper()
            selected = [t for t in selected if (t.severity.value if t.severity else "") == wanted]
        if required_role:
            wanted_role = str(required_role).strip().casefold()
            selected = [t for t in selected if t.required_role.value == wanted_role]

        now = datetime.now(UTC)
        rows = []
        for task in selected:
            row = task.model_dump(mode="json")
            # Whether this item is already past its SLA. Computed here rather than
            # stored so it cannot go stale while sitting in the queue.
            row["sla_breached"] = bool(
                task.sla_deadline is not None and task.sla_deadline < now
            )
            row["batch_eligible"] = (
                task.severity is not None and task.severity in {Severity.S2, Severity.S3}
            )
            rows.append(row)

        if sla_breach:
            rows = [row for row in rows if row["sla_breached"]]
        # Overdue items first: the queue's default ordering is by severity, which
        # is right until something has actually missed its deadline.
        rows.sort(key=lambda row: (not row["sla_breached"],))

        return {
            "count": len(rows),
            "scope": "all" if scope == "all" else "business",
            "business_count": len(business),
            "technical_count": len(pending) - len(business),
            "breached_count": sum(1 for row in rows if row["sla_breached"]),
            "tasks": rows,
        }

    @app.post("/api/reviews/batch-decision")
    def decide_reviews_in_batch(
        request: Request,
        payload: BatchDecisionPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Decide several low-severity items at once.

        S0/S1 items are refused outright. Batch-signing the gravest cases is how
        meaningful oversight decays into clicking, which is the automation-bias
        failure EU AI Act Art.14 asks to be guarded against -- and it would also
        make the override-rate metric meaningless, since a batch produces one
        gesture and many identical outcomes.
        """
        actor = _actor_from_header(services.auth, x_demo_role)
        services.auth.require(actor, "review_case")
        if not payload.task_ids:
            raise ApiError("empty_batch", 422, "no review tasks were selected")
        if not payload.reason or not payload.reason.strip():
            raise ApiError("missing_reason", 422, "a batch decision requires a reason")

        blocked: list[str] = []
        for task_id in payload.task_ids:
            task = services.review_queue.get(task_id)
            if task is None:
                raise KeyError(task_id)
            if task.severity in {Severity.S0, Severity.S1}:
                blocked.append(task_id)
        if blocked:
            raise ApiError(
                "batch_not_allowed",
                422,
                (
                    f"{len(blocked)} 项属于 S0/S1 高风险，必须逐条签名确认，"
                    "不能批量处理。"
                ),
            )

        decided = []
        for task_id in payload.task_ids:
            record = services.decisions.record(
                task_id, payload.decision, payload.reason, actor
            )
            case = request.app.state.cases.get(record.case_id)
            author = (case or {}).get("submitted_by")
            if author:
                card = services.glossary.explain_decision(record.after_decision)
                services.lifecycle.notify(
                    case_id=record.case_id,
                    recipient_id=author,
                    kind=NotificationKind.REVIEW_DECIDED,
                    title=f"你的记录有结论了：{card.label or record.after_decision}",
                    body=record.override_reason,
                    next_step=card.next_step,
                    decision=record.after_decision,
                )
            decided.append(record.model_dump(mode="json"))
        return {"decided": len(decided), "decisions": decided}

    @app.post("/api/reviews/{task_id}/decision")
    def decide_review(
        request: Request,
        task_id: str,
        payload: DecisionPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _actor_from_header(services.auth, x_demo_role)
        record = services.decisions.record(task_id, payload.decision, payload.reason, actor)

        # Tell the author. A decision that stays with the reviewer reads, from the
        # other side, as "the tool ate my report" -- and the next report gets
        # written blander to avoid the silence.
        case = request.app.state.cases.get(record.case_id)
        author = (case or {}).get("submitted_by")
        if author:
            card = services.glossary.explain_decision(record.after_decision)
            services.lifecycle.notify(
                case_id=record.case_id,
                recipient_id=author,
                kind=NotificationKind.REVIEW_DECIDED,
                title=f"你的记录有结论了：{card.label or record.after_decision}",
                # The reviewer's reason, which is theirs to write and never PII by
                # convention; the narrative itself is not repeated here.
                body=record.override_reason,
                next_step=card.next_step,
                decision=record.after_decision,
            )
        return record.model_dump(mode="json")

    # -- misclassification feedback ------------------------------------------

    @app.post("/api/cases/{case_id}/feedback")
    def report_feedback(
        request: Request,
        case_id: str,
        payload: FeedbackPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Report a false positive or a missed risk on a decided case.

        Restricted to ``review_case``: a regression candidate eventually changes
        the release gate, so the people who can report one are the people
        accountable for review. The stored content is the masked view, never the
        original narrative.
        """
        actor = _actor_from_header(services.auth, x_demo_role)
        services.auth.require(actor, "review_case")
        record = request.app.state.cases.get(case_id)
        if record is None:
            raise KeyError(case_id)
        try:
            kind = FeedbackKind(str(payload.kind).strip().casefold())
        except ValueError:
            raise ApiError(
                "invalid_feedback_kind",
                422,
                "kind must be 'false_positive' or 'false_negative'",
            ) from None

        response_body = record["response"]
        try:
            entry = services.feedback.record(
                case_id=case_id,
                kind=kind,
                reason=payload.reason,
                actor=actor,
                masked_text=record["safe_view"]["tokenized_text"],
                observed_decision=str(response_body.get("decision", "")),
                observed_findings=[
                    str(finding.get("type", ""))
                    for finding in response_body.get("findings", [])
                ],
            )
        except ValueError as error:
            raise ApiError("invalid_feedback", 422, str(error)) from None

        services.ledger.append(
            AuditEvent(
                event_id=f"audit-{uuid.uuid4().hex}",
                case_id=case_id,
                trace_id=str(response_body.get("trace_id", "")),
                event_type="feedback_reported",
                occurred_at=datetime.now(UTC),
                actor=actor,
                payload={
                    "entry_id": entry.entry_id,
                    "kind": entry.kind.value,
                    "observed_decision": entry.observed_decision,
                    "expected_decision": entry.expected_decision,
                    "reason": entry.reason,
                },
            )
        )
        return entry.model_dump(mode="json")

    @app.get("/api/feedback")
    def list_feedback(
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Candidate regression cases awaiting a second confirmation."""
        actor = _actor_from_header(services.auth, x_demo_role)
        services.auth.require(actor, "review_case")
        return {
            "entries": [entry.model_dump(mode="json") for entry in services.feedback.pending()],
            "confirmed": [
                entry.model_dump(mode="json") for entry in services.feedback.confirmed()
            ],
            "summary": services.feedback.summary(),
        }

    @app.post("/api/feedback/{entry_id}/confirm")
    def confirm_feedback(
        entry_id: str,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Confirm a candidate, which requires someone other than its reporter."""
        actor = _actor_from_header(services.auth, x_demo_role)
        services.auth.require(actor, "review_case")
        entry = services.feedback.confirm(entry_id, actor=actor)
        services.ledger.append(
            AuditEvent(
                event_id=f"audit-{uuid.uuid4().hex}",
                case_id=entry.case_id,
                trace_id="",
                event_type="feedback_confirmed",
                occurred_at=datetime.now(UTC),
                actor=actor,
                payload={
                    "entry_id": entry.entry_id,
                    "kind": entry.kind.value,
                    "confirmed_by": entry.confirmed_by,
                },
            )
        )
        return entry.model_dump(mode="json")

    # -- model policy --------------------------------------------------------

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

    # -- metrics -------------------------------------------------------------

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

    # -- permissions ---------------------------------------------------------

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

    # -- pluggable sources ---------------------------------------------------

    @app.get("/api/sources")
    def list_sources(
        connector_id: str | None = None,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Enumerate source connectors and their available upstream records."""
        _actor_from_header(services.auth, x_demo_role)
        return {
            "connectors": [
                connector.model_dump(mode="json")
                for connector in services.sources.connectors()
            ],
            "records": services.sources.records(connector_id),
        }

    @app.get("/api/sources/{connector_id}/records/{record_id}")
    def fetch_source_record(
        connector_id: str,
        record_id: str,
        version: str | None = None,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Re-read one authoritative record through its connector adapter.

        Stale event versions are rejected by the adapter, which surfaces as a
        400 rather than silently trusting the caller-supplied version.
        """
        _actor_from_header(services.auth, x_demo_role)
        return services.sources.fetch(connector_id, record_id, version=version)

    # -- attachments ---------------------------------------------------------

    @app.post("/api/attachments")
    def register_attachment(
        payload: AttachmentPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Register an image/audio reference and return a content part.

        Metadata only: no binary is accepted or stored. The response is shaped
        as a ``ContentPart`` so the caller can append it to ``content_parts``,
        which is what drives multimodal task classification.
        """
        _actor_from_header(services.auth, x_demo_role)
        kind = payload.kind.strip().lower()
        if kind not in {"image", "audio"}:
            raise ApiError("bad_request", 400, "kind must be 'image' or 'audio'")
        part_type = "image_ref" if kind == "image" else "audio_ref"
        digest = uuid.uuid4().hex
        metadata: dict[str, Any] = {
            "filename": payload.filename,
            "mime_type": payload.mime_type,
            "size_bytes": payload.size_bytes,
            "stored": False,
        }
        if payload.duration_seconds is not None:
            metadata["duration_seconds"] = payload.duration_seconds
        return {
            "content_part": {
                "type": part_type,
                "ref": f"mock://attachment/{kind}/{digest}",
                "metadata": metadata,
            }
        }

    # -- audit trail (inspection readiness) ----------------------------------

    @app.get("/api/audit-trail")
    def get_audit_trail(
        case_id: str | None = None,
        limit: int = 200,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Export the append-only audit trail with ALCOA+ attribution.

        Restricted to ``audit_export`` (auditor, security, QA, regulatory
        affairs, compliance admin): an audit trail names who did what, so it is
        not readable by every role.
        """
        actor = _actor_from_header(services.auth, x_demo_role)
        services.auth.require(actor, "audit_export")
        events = (
            services.ledger.for_case(case_id) if case_id else services.ledger.all()
        )
        bounded = events[-max(1, min(limit, 1000)):]
        return {
            "case_id": case_id,
            "count": len(bounded),
            "total": len(events),
            "ledger_path": str(services.ledger.path),
            # Append-only is a promise about this program; the chain is what makes
            # an outside edit detectable. Reported inline so an export and its
            # integrity statement cannot drift apart.
            "chain": services.ledger.verify().model_dump(mode="json"),
            # ALCOA+ is the data-integrity expectation an inspector applies.
            "integrity_model": {
                "attributable": (
                    "every event carries case/trace ids; human actions also carry "
                    "the acting user, and automated pipeline steps are attributed "
                    "to the system rather than to a person"
                ),
                "legible": "JSON Lines, one immutable event per line",
                "contemporaneous": "occurred_at is set when the step executes",
                "original": "append-only; events are never rewritten or deleted",
                "accurate": "server-controlled values, model output cannot overwrite",
                "complete_consistent_enduring_available": (
                    "full state transitions persisted and replayable per case"
                ),
            },
            "events": [event.model_dump(mode="json") for event in bounded],
        }

    @app.get("/api/audit-trail/verify")
    def verify_audit_trail(
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Report whether the audit chain is intact, and where it first is not.

        Restricted to ``audit_export`` for the same reason the trail itself is:
        the answer is a statement about records that name who did what.

        ``first_broken_seq`` is the first position that cannot be trusted, i.e.
        one past the last verified entry. It is not read from the offending line,
        because that field is exactly what an editor would adjust.
        """
        actor = _actor_from_header(services.auth, x_demo_role)
        services.auth.require(actor, "audit_export")
        result = services.ledger.verify()
        return {
            "ok": result.ok,
            "checked": result.checked,
            "first_broken_seq": result.first_broken_seq,
            "reason": result.reason,
            # Entries written before the chain existed. Reported rather than
            # hidden: the chain can only attest to what came after it was enabled,
            # and an integrity claim that overstates its own scope is worse than
            # no claim at all.
            "legacy_entries": result.legacy_entries,
            "note": result.note,
            "ledger_path": str(services.ledger.path),
            "head_hash": services.ledger.head_hash(),
            "method": (
                "each entry carries sha256(prev_hash + canonical JSON of the entry "
                "without its own hash), so an edit, deletion, insertion or reorder "
                "breaks the chain at a locatable position"
            ),
            "standard_ref": "21 CFR Part 11 §11.10(e) — record changes must not obscure prior records",
        }

    @app.get("/api/connectors")
    def get_connectors(
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Connector governance view: ownership, auth mode, residency, CSV status."""
        _actor_from_header(services.auth, x_demo_role)
        return {
            "connectors": [
                connector.model_dump(mode="json")
                for connector in services.sources.connectors()
            ],
            "note": (
                "Contract-only mocks. No live Veeva/Vault/PV tenant, credential, "
                "or network call is used; validation_status is 'not_validated' "
                "because this demo makes no CSV/GxP claim."
            ),
        }

    return app


def _record_history(app: FastAPI, version: str, action: str) -> None:
    app.state.config_history.append(
        {
            "version": version,
            "action": action,
            "at": datetime.now(UTC).isoformat(),
            "event_id": f"config-{uuid.uuid4().hex}",
        }
    )


app = create_app()
