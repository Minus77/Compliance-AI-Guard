"""End-to-end case orchestration.

The :class:`Orchestrator` composes intake, security (PII sanitization and
injection scanning), context, deterministic task classification, registry
routing, knowledge retrieval, the model gateway, evidence-constrained
evaluation, the server-controlled policy engine, review queueing, the append-
only audit ledger, correlated tracing, and metrics. Every state transition,
model call, evidence reference, and human override is recorded with
``case_id`` and ``trace_id``. Model output remains a candidate; final decision,
severity, routing, approval status, and tool permissions are server-controlled.

Replay re-runs the deterministic server side using recorded immutable
snapshot IDs (knowledge snapshot, policy version, route version, model profile
version, prompt version) and never performs an external write.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from compliance_guard.agents.classifier import classify_task
from compliance_guard.agents.evaluator import evaluate_with_evidence
from compliance_guard.agents.explainer import explain_policy_result
from compliance_guard.agents.extractor import ExtractorAgent
from compliance_guard.agents.icsr_assessment import assess_icsr
from compliance_guard.agents.icsr_followup import build_followup_form
from compliance_guard.agents.rewrite import RewriteService
from compliance_guard.domain.enums import (
    CaseState,
    Decision,
    ErrorCategory,
    Role,
    Severity,
    WorkflowEvent,
)
from compliance_guard.domain.models import (
    AuditEvent,
    CaseContext,
    CheckCaseRequest,
    CheckCaseResponse,
    DomainModel,
    Entity,
    ExtractedData,
    Finding,
    KnowledgeFilter,
    ProductContext,
    ReviewTask,
)
from compliance_guard.knowledge.evidence_pack import EvidencePack
from compliance_guard.knowledge.field_resolver import FieldResolution, FieldResolver
from compliance_guard.knowledge.glossary import DEFAULT_LOCALE, default_glossary
from compliance_guard.llm.types import ModelConstraints, RawModelResult
from compliance_guard.policy.engine import PolicyEngine, PolicyResult
from compliance_guard.policy.routing import ReviewPlan
from compliance_guard.security.injection_scan import scan_untrusted_content
from compliance_guard.security.pii_gateway import KnownIdentifier, PiiGateway, SanitizeContext
from compliance_guard.workflow.scenario import infer_scenario
from compliance_guard.workflow.state_machine import StateMachine, TransitionContext

# Per-excerpt character ceiling for evidence sent to a model. Keeps one oversized
# record from crowding out the rest of the pack or exhausting the token budget.
_MAX_EVIDENCE_EXCERPT_CHARS = 600

_RESERVED_FORM_KEYS = frozenset(
    {
        "decision",
        "severity",
        "approval_status",
        "routing",
        "tool_permissions",
    }
)

_OUTCOME_EVENTS = {
    Decision.ALLOW: WorkflowEvent.ALLOW,
    Decision.NEEDS_INFO: WorkflowEvent.NEEDS_INFO,
    Decision.HUMAN_REVIEW: WorkflowEvent.HUMAN_REVIEW,
    Decision.BLOCKED: WorkflowEvent.BLOCK,
    Decision.REFUSED: WorkflowEvent.REFUSE,
}


class ReplayResult(DomainModel):
    """Outcome of a deterministic replay against recorded snapshot IDs."""

    case_id: str
    policy_version: str
    knowledge_snapshot_id: str
    decision: Decision
    severity: Severity
    route_version: str | None = None
    model_profile_id: str | None = None
    prompt_version: str | None = None
    input_hash: str | None = None
    replayed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    consistent: bool = True
    detail: str = ""


class Orchestrator:
    """Composes the end-to-end compliance workflow for one case."""

    def __init__(
        self,
        *,
        gateway,
        registry,
        policy_store,
        label_facts_store,
        retriever,
        auth=None,
        ledger=None,
        tracer=None,
        metrics=None,
        review_queue=None,
        decisions=None,
        machine=None,
        now=None,
        prompt_version: str = "compliance-evaluator-v2",
    ) -> None:
        self._gateway = gateway
        self._registry = registry
        self._policy_store = policy_store
        self._label_facts_store = label_facts_store
        self._retriever = retriever
        self._auth = auth
        self._ledger = ledger
        self._tracer = tracer
        self._metrics = metrics
        self._review_queue = review_queue
        self._decisions = decisions
        self._machine = machine or StateMachine()
        self._now = now
        self._prompt_version = prompt_version
        self._extractor = ExtractorAgent()
        self._pii = PiiGateway()
        self._field_resolver = FieldResolver()
        self._rewrite = RewriteService()

    def _clock(self) -> datetime:
        return self._now() if self._now is not None else datetime.now(UTC)

    @staticmethod
    def _digest(text: str) -> str:
        return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _data_class(security_findings: list[Any], request: Any | None = None) -> str:
        types = {finding.type.casefold() for finding in security_findings}
        if any("phi" in finding_type for finding_type in types):
            return "phi_tokenized"
        if any("pii" in finding_type for finding_type in types):
            return "pii_tokenized"
        # An image/audio attachment is never opened server-side, so its contents
        # are unknown and may carry personal data (a photographed chart, a
        # recorded patient name). Classify conservatively as tokenized rather
        # than 'internal': the multimodal route deliberately refuses untokenized
        # data classes, so calling this 'internal' would fail every attachment
        # case safe instead of routing it.
        for part in getattr(request, "content_parts", None) or []:
            part_type = getattr(part, "type", None)
            value = getattr(part_type, "value", part_type)
            if value in {"image_ref", "audio_ref"}:
                return "pii_tokenized"
        return "internal"

    # The fields that travel to a model as reference context. Deliberately short
    # values only: contraindication and warning prose stays server-side, so the
    # request size is decoupled from label length and product count.
    _LABEL_FACT_FIELDS = (
        "product_id",
        "market",
        "version",
        "indication",
        "indication_id",
        "population",
        "line",
        "dose",
        "route",
        "duration",
        "combination",
    )

    @classmethod
    def _label_fact_fields(cls, label_facts: Any) -> dict[str, Any]:
        """One product's approved label as structured values, or an empty dict."""
        if label_facts is None:
            return {}
        selected: dict[str, Any] = {}
        for field in cls._LABEL_FACT_FIELDS:
            value = getattr(label_facts, field, None)
            if value not in (None, ""):
                selected[field] = value
        return selected

    @staticmethod
    def _roster(request: Any) -> list[KnownIdentifier]:
        """Master-data subjects whose raw identifiers may appear in the content.

        Client-supplied roster entries are accepted here for one reason only:
        they can add masking coverage and stable identity for people the local
        detector would otherwise only guess at. They cannot reduce masking — the
        gateway still runs its own detection — and they never reach the policy
        decision, so a forged roster cannot make a case look compliant.
        """
        raw = request.extensions.get("known_identifiers") or []
        roster: list[KnownIdentifier] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            entity_type = str(item.get("entity_type") or item.get("type") or "").strip()
            canonical_id = str(item.get("canonical_id") or "").strip()
            values = [str(value) for value in (item.get("values") or []) if str(value).strip()]
            if entity_type not in {"patient", "hcp"} or not canonical_id or not values:
                continue
            roster.append(
                KnownIdentifier(entity_type=entity_type, canonical_id=canonical_id, values=values)
            )
        return roster

    # -- audit / trace helpers -------------------------------------------------

    def _record(
        self,
        case_id: str,
        trace_id: str,
        event_type: str,
        from_state,
        to_state,
        component: str,
        *,
        payload: dict | None = None,
        versions: dict | None = None,
        actor=None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=f"audit-{uuid.uuid4().hex}",
            case_id=case_id,
            trace_id=trace_id,
            event_type=event_type,
            occurred_at=self._clock(),
            from_state=from_state,
            to_state=to_state,
            actor=actor,
            payload={**(payload or {}), "component": component},
            configuration_versions=versions or {},
        )
        if self._ledger is not None:
            return self._ledger.append(event)
        return event

    def _advance(
        self,
        state: CaseState,
        event: WorkflowEvent,
        case_id: str,
        trace_id: str,
        component: str,
        *,
        payload: dict | None = None,
        versions: dict | None = None,
    ) -> tuple[CaseState, str]:
        span = None
        if self._tracer is not None:
            span = self._tracer.start(component, case_id=case_id, trace_id=trace_id)
        ctx = TransitionContext(case_id=case_id, trace_id=trace_id)
        from_state = state
        to_state = self._machine.transition(state, event, ctx)
        audit = self._record(
            case_id,
            trace_id,
            f"transition.{event.value}",
            from_state,
            to_state,
            component,
            payload=payload,
            versions=versions,
        )
        if self._tracer is not None and span is not None:
            self._tracer.finish(
                span,
                attributes={
                    "event": event.value,
                    "from": from_state.value if from_state is not None else None,
                    "to": to_state.value if to_state is not None else None,
                    "audit_event_id": audit.event_id,
                },
            )
        return to_state, audit.event_id

    # -- public API ------------------------------------------------------------

    def run_check_case(self, request: CheckCaseRequest) -> CheckCaseResponse:
        """Run one case through the shared workflow and return the response."""
        case_id = f"CASE-{uuid.uuid4().hex}"
        trace_id = self._tracer.new_trace() if self._tracer is not None else f"trace-{uuid.uuid4().hex}"
        state = CaseState.RECEIVED
        root = None
        if self._tracer is not None:
            root = self._tracer.start("run_check_case", case_id=case_id, trace_id=trace_id)
        if self._metrics is not None:
            self._metrics.increment("cases_received")
        self._record(
            case_id,
            trace_id,
            "case_received",
            CaseState.RECEIVED,
            None,
            "intake",
            payload={"input_hash": self._digest(request.content)},
        )

        try:
            # intake authorization
            state, _ = self._advance(state, WorkflowEvent.AUTHORIZE, case_id, trace_id, "intake.authorize")

            # security preprocessing: sanitize PII, scan for injection
            state, _ = self._advance(state, WorkflowEvent.PREPROCESS, case_id, trace_id, "security.preprocess")
            sanitized = self._pii.sanitize(
                request.content,
                SanitizeContext(
                    tenant_id=request.tenant_id,
                    known_identifiers=self._roster(request),
                    case_id=case_id,
                ),
            )
            security_findings = list(sanitized.findings) + scan_untrusted_content(request.content)
            self._record(
                case_id,
                trace_id,
                "security_findings",
                None,
                None,
                "security.preprocess",
                payload={
                    "types": [finding.type for finding in security_findings],
                    "severities": [finding.severity.value for finding in security_findings],
                },
            )
            # Entity resolution is auditable on its own terms: a reviewer needs to
            # see how mentions were grouped to be able to challenge it. The payload
            # carries bases, offsets and counts only -- never the names.
            self._record(
                case_id,
                trace_id,
                "entity_resolution",
                None,
                None,
                "security.resolve_entities",
                payload=dict(sanitized.resolution),
            )

            # context preparation
            state, _ = self._advance(state, WorkflowEvent.PREPARE_CONTEXT, case_id, trace_id, "context.prepare")
            bundle = self._policy_store.load()
            label_facts = self._label_facts_store.current(request.product_id, request.market)
            context = CaseContext(
                case_id=case_id,
                trace_id=trace_id,
                tenant_id=request.tenant_id,
                market=request.market,
                language=request.language,
                product_id=request.product_id,
                channel=request.channel,
                source=request.source,
                source_version=request.source_version,
                policy_version=bundle.policy_version,
            )

            # deterministic task classification and registry routing
            state, _ = self._advance(state, WorkflowEvent.CLASSIFY, case_id, trace_id, "task.classify")
            classification = classify_task(request, security_findings)
            data_class = self._data_class(security_findings, request)
            route = self._registry.resolve(
                classification.task_type,
                classification.modality,
                data_class,
                request.market,
            )

            # knowledge retrieval -> evidence pack with immutable snapshot id
            state, _ = self._advance(state, WorkflowEvent.RETRIEVE_EVIDENCE, case_id, trace_id, "knowledge.retrieve")
            filters = KnowledgeFilter(
                tenant_id=request.tenant_id,
                market=request.market,
                product_id=request.product_id,
                language=request.language,
                as_of=request.received_at,
                purpose="compliance_check",
            )
            query = sanitized.model_text or request.content
            evidence_pack = self._retriever.search_evidence(query, filters)
            self._record(
                case_id,
                trace_id,
                "evidence_retrieved",
                None,
                None,
                "knowledge.retrieve",
                payload={
                    "knowledge_snapshot_id": evidence_pack.snapshot_id,
                    "evidence_ids": [item.evidence_id for item in evidence_pack.items],
                    "evidence_gap": evidence_pack.evidence_gap,
                },
            )

            # model evaluation (candidate output only)
            state, _ = self._advance(state, WorkflowEvent.EVALUATE, case_id, trace_id, "model.evaluate")
            raw = self._call_model(
                case_id,
                trace_id,
                classification.task_type.value,
                query,
                request,
                route,
                evidence_pack,
                data_class,
                label_facts=label_facts,
            )
            if raw.error_category is not None:
                return self._fail_safe(case_id, trace_id, state, request, route, raw)

            extracted = self._extractor.parse(raw)
            # Facts are derived from the narrative on the server. The model's
            # candidates may fill a gap the patterns missed, but they cannot
            # overwrite a server-derived field and never carry a decision.
            field_resolution = self._field_resolver.resolve(
                request.content,
                market=request.market,
                as_of=request.received_at,
                claimed_fields=request.extensions.get("structured_fields") or {},
                model_fields=extracted.extracted_fields,
            )
            self._record(
                case_id,
                trace_id,
                "field_resolution",
                None,
                None,
                "knowledge.resolve_fields",
                payload=field_resolution.audit_payload(),
            )
            candidate = self._overlay_intake(extracted, request, field_resolution=field_resolution)
            evaluated = evaluate_with_evidence(candidate, evidence_pack, policy_result=None)
            candidate = ExtractedData(
                entities=candidate.entities,
                findings=evaluated.findings,
                extracted_fields=candidate.extracted_fields,
                claimed_fields=candidate.claimed_fields,
                resolved_fields=candidate.resolved_fields,
                field_discrepancies=candidate.field_discrepancies,
                evidence_refs=candidate.evidence_refs,
                missing_information=evaluated.missing_information or candidate.missing_information,
                confidence=evaluated.confidence,
            )

            # server-controlled policy evaluation (validation)
            state, _ = self._advance(state, WorkflowEvent.VALIDATE, case_id, trace_id, "policy.validate")
            engine = PolicyEngine(bundle, label_facts=label_facts, route_version=route.route_version, now=self._clock())
            policy_result = engine.evaluate(
                context,
                candidate,
                security_findings,
                evidence_pack,
                entity_resolution=sanitized.resolution,
            )

            # decide
            state, _ = self._advance(state, WorkflowEvent.DECIDE, case_id, trace_id, "policy.decide")
            outcome_event = _OUTCOME_EVENTS[policy_result.decision]
            state, _ = self._advance(
                state,
                outcome_event,
                case_id,
                trace_id,
                f"decision.{policy_result.decision.value}",
                payload={"severity": policy_result.severity.value, "rule_ids": list(policy_result.rule_ids)},
            )

            # professional review queueing
            self._enqueue_review(case_id, trace_id, policy_result, request.market)

            # A block must offer a way forward: "no" with no next step is what
            # teaches people to write shorter, blander notes. The suggestion is
            # re-checked against the same deterministic rules before it can be
            # shown, so the tool never proposes the violation it just blocked.
            rewrite = self._rewrite.suggest(
                request.content,
                finding_types=[finding.type for finding in policy_result.findings],
            )
            self._record(
                case_id,
                trace_id,
                "rewrite_offered",
                None,
                None,
                "guidance.rewrite",
                payload=rewrite.audit_payload(),
            )

            # finalize: audit, response, complete
            final_audit = self._record_finalized(
                case_id, trace_id, state, query, filters, evidence_pack, policy_result, route, raw
            )
            state, _ = self._advance(state, WorkflowEvent.AUDIT, case_id, trace_id, "audit.finalize")
            state, _ = self._advance(state, WorkflowEvent.COMPLETE, case_id, trace_id, "workflow.complete")

            response = self._build_response(
                request,
                case_id,
                trace_id,
                final_audit.event_id,
                state,
                policy_result,
                evidence_pack,
                candidate,
                route,
                security_findings,
                raw,
                rewrite=rewrite,
            )
            response.validate_business_invariants()

            if self._metrics is not None:
                self._metrics.increment("cases_completed")
                self._metrics.increment(f"decisions.{policy_result.decision.value}")
            if self._tracer is not None and root is not None:
                self._tracer.finish(
                    root,
                    attributes={
                        "case_id": case_id,
                        "decision": policy_result.decision.value,
                        "severity": policy_result.severity.value,
                        "status": state.value,
                    },
                )
            return response
        except Exception as exc:  # noqa: BLE001 - unsafe errors must fail safe
            return self._handle_unsafe_error(case_id, trace_id, request, exc)

    def replay_case(self, case_id: str, knowledge_snapshot_id: str, policy_version: str) -> ReplayResult:
        """Replay a completed case using its recorded immutable snapshot IDs.

        Replay re-derives the evidence snapshot from recorded query+filters,
        loads the recorded policy version, and reuses the recorded decision
        metadata. It never calls the model gateway and never performs an
        external write.
        """
        if self._ledger is None:
            raise RuntimeError("replay requires an audit ledger")
        events = self._ledger.for_case(case_id)
        finalized = next((event for event in events if event.event_type == "case_finalized"), None)
        if finalized is None:
            raise KeyError(f"no finalized record for case {case_id!r}")
        payload = finalized.payload or {}
        filters = KnowledgeFilter(**payload.get("filters", {}))
        query = payload.get("query", "")
        replayed_pack = self._retriever.search_evidence(query, filters)
        snapshot_consistent = replayed_pack.snapshot_id == knowledge_snapshot_id
        bundle = self._policy_store.load(policy_version)
        versions = finalized.configuration_versions or {}
        return ReplayResult(
            case_id=case_id,
            policy_version=policy_version,
            knowledge_snapshot_id=knowledge_snapshot_id,
            decision=Decision(payload.get("decision", "human_review")),
            severity=Severity(payload.get("severity", "S3")),
            route_version=versions.get("route"),
            model_profile_id=versions.get("model_profile"),
            prompt_version=versions.get("prompt"),
            input_hash=payload.get("input_hash"),
            replayed_at=self._clock(),
            consistent=snapshot_consistent and bundle.policy_version == policy_version,
            detail="replayed recorded snapshot and policy version without an external write",
        )

    # -- internals -------------------------------------------------------------

    def _call_model(
        self,
        case_id: str,
        trace_id: str,
        task_type: str,
        query: str,
        request: CheckCaseRequest,
        route,
        evidence_pack: EvidencePack,
        data_class: str,
        label_facts=None,
    ) -> RawModelResult:
        model_request = self._extractor.build_request(
            task_type=task_type,
            sanitized_text=query,
            structured_fields=request.extensions.get("structured_fields") or {},
            evidence_ids=[item.evidence_id for item in evidence_pack.items],
            evidence_excerpts=self._evidence_excerpts(evidence_pack),
            label_facts=self._label_fact_fields(label_facts),
        )
        # The scenario selects how the content is examined, so the caller does not
        # get to choose it (defect P-2). Inference is server-side; a claim is only
        # honoured in the explicitly labelled demo mode, and that is recorded.
        scenario_decision = infer_scenario(
            request.content, claimed=request.extensions.get("scenario")
        )
        model_request.scenario = scenario_decision.scenario
        self._record(
            case_id,
            trace_id,
            "scenario_inferred",
            None,
            None,
            "task.scenario",
            payload=scenario_decision.audit_payload(),
        )
        constraints = ModelConstraints(
            profile_id=route.primary_profile.profile_id,
            model_id=route.primary_profile.model_id,
            route_version=route.route_version,
            timeout_ms=route.primary_profile.timeout_ms,
            token_budget=route.primary_profile.token_budget,
            data_class=data_class,
            region=route.region,
        )
        if self._metrics is not None:
            self._metrics.increment("model_calls")
        raw = self._gateway.complete(task_type, model_request, constraints, route)
        if self._metrics is not None:
            self._metrics.record("model_call_latency_ms", float(raw.latency_ms))
        self._record(
            case_id,
            trace_id,
            "model_call",
            None,
            None,
            "model.gateway",
            payload={
                "profile_id": raw.profile_id,
                "model_id": raw.model_id,
                # Provider-specific model that answered; empty in offline mode.
                "model_upstream": raw.upstream_model,
                "provider": raw.provider,
                "route_version": raw.route_version,
                "error_category": raw.error_category,
                "fallback_used": raw.fallback_used,
                "latency_ms": raw.latency_ms,
            },
            versions={"route": raw.route_version},
        )
        return raw

    @staticmethod
    def _evidence_excerpts(evidence_pack: EvidencePack) -> list[dict[str, Any]]:
        """Build the evidence the model is allowed to reason from.

        Only curated knowledge-base content travels here: the approved excerpt,
        its id and version, and the retrieval stance. Sending bare ids asked the
        model to reason from facts it could not see, and a live model correctly
        refused the task rather than guessing -- which then surfaced as a case
        with no candidate findings.

        Stance is included because "supporting" and "contradicting" evidence must
        not look alike to the model. The excerpt is truncated so one oversized
        record cannot crowd out the rest of the pack or blow the token budget.
        """
        stance_by_id: dict[str, str] = {}
        for item in evidence_pack.supporting:
            stance_by_id[item.evidence_id] = "supports"
        for item in evidence_pack.contradictions:
            stance_by_id[item.evidence_id] = "contradicts"

        excerpts: list[dict[str, Any]] = []
        for item in evidence_pack.items:
            quote = (item.quote or "").strip()
            if not quote:
                continue
            excerpts.append(
                {
                    "evidence_id": item.evidence_id,
                    "version": item.version,
                    "source_type": item.source_type,
                    "stance": stance_by_id.get(item.evidence_id, "retrieved"),
                    "excerpt": quote[:_MAX_EVIDENCE_EXCERPT_CHARS],
                }
            )
        return excerpts

    def _overlay_intake(
        self,
        extracted: ExtractedData,
        request: CheckCaseRequest,
        *,
        field_resolution: FieldResolution | None = None,
    ) -> ExtractedData:
        """Separate what the client claimed from what the server established.

        The previous implementation merged client form fields over the server's
        own extraction, which made the client the authority on off-label status:
        declaring ``indication_id=IND-001`` removed the off-label finding from a
        narrative promoting a different disease (defect P-1). Claims now stay in
        their own compartment and the decision reads ``resolved_fields``.
        """
        form_fields = request.extensions.get("structured_fields") or {}
        claimed_fields = {
            key: value
            for key, value in form_fields.items()
            if key.casefold() not in _RESERVED_FORM_KEYS
        }
        form_entities = [
            Entity(type=str(item.get("type", "entity")), token=str(item.get("token", "")))
            for item in (request.extensions.get("entities") or [])
            if isinstance(item, dict)
        ]
        resolved_fields = dict(field_resolution.resolved_fields) if field_resolution else {}
        discrepancies = list(field_resolution.discrepancies) if field_resolution else []
        return ExtractedData(
            entities=list(extracted.entities) + form_entities,
            findings=extracted.findings,
            extracted_fields=dict(extracted.extracted_fields),
            claimed_fields=claimed_fields,
            resolved_fields=resolved_fields,
            field_discrepancies=discrepancies,
            evidence_refs=list(extracted.evidence_refs),
            missing_information=list(extracted.missing_information),
            confidence=extracted.confidence,
        )

    def _enqueue_review(self, case_id: str, trace_id: str, policy_result: PolicyResult, market: str) -> None:
        if self._review_queue is None or policy_result.routing is None:
            return
        if not policy_result.routing.review_tasks:
            return
        self._review_queue.create(
            policy_result.routing,
            case_decision=policy_result.decision,
            case_severity=policy_result.severity,
            market=market,
        )

    def _manual_review_plan(self, case_id: str, trace_id: str, *, basis: str) -> ReviewPlan:
        """Build a degraded-path ReviewPlan routing to the generic reviewer.

        Model evaluation never ran, so there are no findings to derive a role
        from; the manual-degraded case still needs a human to pick it up, so it
        routes to the generic reviewer role instead of being dropped.
        """
        task = ReviewTask(
            task_id=f"review-{uuid.uuid4().hex}",
            case_id=case_id,
            trace_id=trace_id,
            required_role=Role.REVIEWER,
            finding_ids=[],
        )
        return ReviewPlan(
            review_tasks=[task],
            required_roles=[Role.REVIEWER],
            sla_label="24h",
            next_actions=["manual review after degraded or unsafe workflow"],
            routing_basis=basis,
            route_version="routing-v1",
            immutable=True,
        )

    def _enqueue_manual_review(
        self,
        case_id: str,
        trace_id: str,
        market: str,
        *,
        decision: Decision,
        severity: Severity,
        basis: str,
    ) -> None:
        """Mirror the normal-path review enqueue for degraded/unsafe handoff."""
        if self._review_queue is None:
            return
        self._review_queue.create(
            self._manual_review_plan(case_id, trace_id, basis=basis),
            case_decision=decision,
            case_severity=severity,
            market=market,
        )

    def _record_finalized(
        self,
        case_id: str,
        trace_id: str,
        state: CaseState,
        query: str,
        filters: KnowledgeFilter,
        evidence_pack: EvidencePack,
        policy_result: PolicyResult,
        route,
        raw: RawModelResult | None = None,
    ) -> AuditEvent:
        routing_roles = (
            [role.value for role in policy_result.routing.required_roles]
            if policy_result.routing is not None
            else []
        )
        payload = {
            "input_hash": self._digest(query),
            "output_hash": self._digest(
                f"{policy_result.decision.value}|{policy_result.severity.value}|"
                f"{','.join(policy_result.rule_ids)}"
            ),
            "knowledge_snapshot_id": evidence_pack.snapshot_id,
            "query": query,
            "filters": filters.model_dump(mode="json"),
            "decision": policy_result.decision.value,
            "severity": policy_result.severity.value,
            "rule_ids": list(policy_result.rule_ids),
            "reasons": list(policy_result.reasons),
            "routing_roles": routing_roles,
            "routing_sla": policy_result.routing.sla_label if policy_result.routing is not None else None,
            "explanation": explain_policy_result(policy_result, evidence_pack),
            "evidence_ids": [item.evidence_id for item in evidence_pack.items],
            "evidence_gap": evidence_pack.evidence_gap,
        }
        # Record the profile that actually answered, not the one that was
        # configured. With a live provider the primary can fail and the published
        # fallback can answer instead; an audit trail naming the wrong model
        # would make a case unreproducible.
        versions = {
            "policy": policy_result.policy_version,
            "route": route.route_version,
            "model_profile": (raw.profile_id if raw is not None and raw.profile_id else route.primary_profile.profile_id),
            "model": (raw.model_id if raw is not None and raw.model_id else route.primary_profile.model_id),
            "prompt": self._prompt_version,
        }
        if raw is not None:
            payload["model_provider"] = raw.provider
            payload["model_fallback_used"] = raw.fallback_used
            payload["model_latency_ms"] = raw.latency_ms
            # The provider-specific model that actually answered. Without it the
            # trail would name only the business routing label, and a case could
            # not be reproduced after the endpoint mapping is repointed.
            if raw.upstream_model:
                payload["model_upstream"] = raw.upstream_model
        return self._record(
            case_id,
            trace_id,
            "case_finalized",
            state,
            state,
            "audit.finalize",
            payload=payload,
            versions=versions,
        )

    def _label_version(self, request: CheckCaseRequest, evidence_pack: EvidencePack | None) -> str:
        try:
            facts = self._label_facts_store.current(request.product_id, request.market)
            return facts.version
        except Exception:  # noqa: BLE001 - fall back to evidence or a stable default
            pass
        if evidence_pack is not None and evidence_pack.items:
            return evidence_pack.items[0].version
        return "CN-PI-2026-01"

    @staticmethod
    def _map_finding(finding: Any) -> Finding:
        return Finding(
            finding_id=finding.finding_id,
            type=finding.type,
            severity=finding.severity,
            decision=finding.decision,
            confidence=finding.confidence,
            reason=finding.reason,
            evidence_refs=list(finding.evidence_refs),
            missing_information=list(finding.missing_information),
            required_role=finding.required_role,
            next_action=finding.next_action,
            evidence_gap=finding.evidence_gap,
            # Rule provenance for the UI's natural-language explanation.
            rule_id=getattr(finding, "rule_id", None) or None,
            matched_terms=list(getattr(finding, "matched_terms", []) or []),
            sla_label=getattr(finding, "sla_label", None),
            required_roles=list(getattr(finding, "required_roles", []) or []),
        )

    @staticmethod
    def _normalize_finding_gaps(findings: list[Finding]) -> list[Finding]:
        """Conservatively mark high-risk findings without evidence as a gap.

        The response invariant requires every S0/S1 finding to carry
        evidence references or an explicit evidence gap. The policy engine
        already attaches refs/gaps for evidence-required rules; for S0/S1
        outcomes where evidence is not applicable (e.g. injection) the
        response composition records a conservative evidence gap so the
        domain safety invariant remains satisfied without weakening it.
        """
        high_risk = {Severity.S0, Severity.S1}
        for finding in findings:
            if finding.severity in high_risk and not finding.evidence_refs:
                has_gap = finding.evidence_gap or "evidence_gap" in (
                    item.lower() for item in finding.missing_information
                )
                if not has_gap:
                    finding.evidence_gap = True
                    if "evidence_gap" not in finding.missing_information:
                        finding.missing_information.append("evidence_gap")
        return findings

    def _build_response(
        self,
        request: CheckCaseRequest,
        case_id: str,
        trace_id: str,
        audit_event_id: str,
        state: CaseState,
        policy_result: PolicyResult,
        evidence_pack: EvidencePack,
        candidate: ExtractedData,
        route,
        security_findings: list[Any],
        raw: RawModelResult | None = None,
        rewrite: Any | None = None,
    ) -> CheckCaseResponse:
        findings = self._normalize_finding_gaps([self._map_finding(f) for f in policy_result.findings])
        evidence = [item.model_copy(deep=True) for item in evidence_pack.items]
        icsr_payload = self._icsr_payload(request, evidence_pack, candidate, findings)
        guidance_payload = self._guidance_payload(
            request, policy_result, findings, rewrite=rewrite
        )
        response = CheckCaseResponse(
            case_id=case_id,
            decision=policy_result.decision,
            status=state,
            market=request.market,
            language=request.language,
            product=ProductContext(
                product_id=request.product_id,
                label_version=self._label_version(request, evidence_pack),
            ),
            entities=list(candidate.entities),
            findings=findings,
            evidence=evidence,
            security_findings=[finding.model_copy(deep=True) for finding in security_findings],
            policy_version=policy_result.policy_version,
            knowledge_snapshot_id=evidence_pack.snapshot_id,
            # Provenance follows the answering profile; see _record_finalized.
            model_profile_id=(raw.profile_id if raw is not None and raw.profile_id else route.primary_profile.profile_id),
            model_version=(raw.model_id if raw is not None and raw.model_id else route.primary_profile.model_id),
            route_version=route.route_version,
            prompt_version=self._prompt_version,
            trace_id=trace_id,
            audit_event_id=audit_event_id,
            retrieval={
                "query": evidence_pack.query,
                "query_tokens": list(evidence_pack.query_tokens),
                "filters_applied": dict(evidence_pack.filters_applied),
                "snapshot_id": evidence_pack.snapshot_id,
                "stages": [stage.model_dump(mode="json") for stage in evidence_pack.stages],
                "chunks": [chunk.model_dump(mode="json") for chunk in evidence_pack.chunks],
                "gaps": [gap.model_dump(mode="json") for gap in evidence_pack.gaps],
                "supporting_count": len(evidence_pack.supporting),
                "contradiction_count": len(evidence_pack.contradictions),
                "evidence_gap": evidence_pack.evidence_gap,
            },
            icsr=icsr_payload,
            guidance=guidance_payload,
            followup=build_followup_form(icsr_payload).model_dump(mode="json"),
        )
        return response

    def _guidance_payload(
        self,
        request: CheckCaseRequest,
        policy_result: PolicyResult,
        findings: list[Finding],
        rewrite: Any | None = None,
    ) -> dict[str, Any]:
        """Plain-language reading of the result, plus the codes for the record.

        Two audiences, one response. A representative needs to know what happened
        and what to do; a reviewer reconciling the case needs the exact rule ids.
        Splitting them means neither has to read around the other, and the reader
        never meets a bare ``S1``.

        Wording comes from the glossary rather than from rule strings, so the
        pre-check panel, this result and the glossary endpoint cannot drift apart.
        """
        locale = DEFAULT_LOCALE
        if str(request.language or "").casefold().startswith("en"):
            locale = "en"
        glossary = default_glossary()

        decision_card = glossary.explain_decision(policy_result.decision.value, locale)
        cards: list[dict[str, Any]] = []
        seen: set[str] = set()
        for finding in findings:
            if finding.type in seen:
                continue
            seen.add(finding.type)
            card = glossary.explain_finding(finding.type, locale, rule_id=finding.rule_id)
            payload = card.model_dump(mode="json")
            payload["type"] = finding.type
            payload["severity_label"] = glossary.explain_severity(
                finding.severity.value, locale
            )["label"]
            cards.append(payload)

        # Computed in the main flow so its audit event lands before the terminal
        # transition; recomputed here only if a caller built a response directly.
        if rewrite is None:
            rewrite = self._rewrite.suggest(
                request.content, finding_types=[finding.type for finding in findings]
            )

        routing = policy_result.routing
        review_roles = (
            [role.value for role in getattr(routing, "required_roles", [])] if routing else []
        )
        return {
            "rewrite": rewrite.model_dump(mode="json"),
            "locale": locale,
            "glossary_version": glossary.version,
            "decision_label": decision_card.label,
            "decision_plain": decision_card.plain,
            "next_step": decision_card.next_step,
            "findings": cards,
            "review_roles": review_roles,
            "sla_label": getattr(routing, "sla_label", None) if routing else None,
            # Kept for reconciliation, deliberately out of the headline.
            "technical": {
                "decision": policy_result.decision.value,
                "severity": policy_result.severity.value,
                "policy_version": policy_result.policy_version,
                "rule_ids": [f.rule_id for f in findings if f.rule_id],
                "finding_types": [f.type for f in findings],
            },
        }

    @staticmethod
    def _icsr_payload(
        request: CheckCaseRequest,
        evidence_pack: EvidencePack,
        candidate: ExtractedData,
        findings: list[Finding],
    ) -> dict[str, Any]:
        """Assess ICSR minimum criteria on the tokenized narrative.

        The tokenized query is used deliberately: the criteria ask whether an
        identifiable patient/reporter exists, never that we hold identifiers.
        """
        safety_types = {
            "potential_adverse_event",
            "serious_adverse_event",
            "ae",
            "sae",
        }
        has_safety_finding = any(
            str(finding.type).casefold() in safety_types for finding in findings
        )
        patient_entity = any(
            str(getattr(entity, "type", "")).casefold() == "patient"
            for entity in (candidate.entities or [])
        )
        assessment = assess_icsr(
            evidence_pack.query or request.content,
            received_at=request.received_at,
            product_id=request.product_id,
            # In a call report the submitting representative is the reporter.
            reporter_known=True,
            patient_entity_present=patient_entity,
        )
        payload = assessment.model_dump(mode="json")
        # Cross-check: a safety finding without a safety-relevant ICSR read is a
        # discrepancy a PV reviewer must see rather than a silent disagreement.
        payload["policy_flagged_safety"] = has_safety_finding
        payload["assessment_conflict"] = bool(
            has_safety_finding and not assessment.is_safety_relevant
        )
        return payload

    def _fail_safe(
        self,
        case_id: str,
        trace_id: str,
        state: CaseState,
        request: CheckCaseRequest,
        route,
        raw: RawModelResult,
    ) -> CheckCaseResponse:
        try:
            category = ErrorCategory(raw.error_category)
        except (TypeError, ValueError):
            category = ErrorCategory.UNKNOWN
        ctx = TransitionContext(
            case_id=case_id,
            trace_id=trace_id,
            retryable=True,
            requires_human=route.requires_human_on_failure,
            failure_category=category,
        )
        to_state = self._machine.transition(state, WorkflowEvent.MODEL_FAILURE, ctx)
        decision = Decision.HUMAN_REVIEW if to_state is CaseState.MANUAL_DEGRADED else Decision.REFUSED
        if decision is Decision.HUMAN_REVIEW:
            self._enqueue_manual_review(
                case_id,
                trace_id,
                request.market,
                decision=decision,
                severity=Severity.S1,
                basis=f"model failure {raw.error_category} requires human review",
            )
        audit = self._record(
            case_id,
            trace_id,
            f"model_failure.{raw.error_category}",
            state,
            to_state,
            "model.gateway",
            payload={
                "error_category": raw.error_category,
                "profile_id": raw.profile_id,
                "route_version": raw.route_version,
                "requires_human": route.requires_human_on_failure,
            },
            versions={"route": raw.route_version},
        )
        if self._metrics is not None:
            self._metrics.increment("model_failures")
            self._metrics.increment(f"decisions.{decision.value}")
        return CheckCaseResponse(
            case_id=case_id,
            decision=decision,
            status=to_state,
            market=request.market,
            language=request.language,
            product=ProductContext(
                product_id=request.product_id,
                label_version=self._label_version(request, None),
            ),
            trace_id=trace_id,
            audit_event_id=audit.event_id,
        )

    def _handle_unsafe_error(
        self, case_id: str, trace_id: str, request: CheckCaseRequest, exc: Exception
    ) -> CheckCaseResponse:
        self._enqueue_manual_review(
            case_id,
            trace_id,
            request.market,
            decision=Decision.REFUSED,
            severity=Severity.S1,
            basis=f"unsafe error {type(exc).__name__} requires human review",
        )
        audit = self._record(
            case_id,
            trace_id,
            "case_unsafe_error",
            None,
            None,
            "orchestrator.safety",
            payload={"error": type(exc).__name__, "message": str(exc)},
        )
        if self._metrics is not None:
            self._metrics.increment("unsafe_errors")
        return CheckCaseResponse(
            case_id=case_id,
            decision=Decision.REFUSED,
            status=CaseState.FAILED_SAFE,
            market=request.market,
            language=request.language,
            product=ProductContext(
                product_id=request.product_id,
                label_version=self._label_version(request, None),
            ),
            trace_id=trace_id,
            audit_event_id=audit.event_id,
        )


__all__ = ["Orchestrator", "ReplayResult"]
