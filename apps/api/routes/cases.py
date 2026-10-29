from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, Request

from compliance_guard.agents.icsr_assessment import assess_icsr
from compliance_guard.agents.icsr_followup import build_followup_form, followup_narrative
from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import AuditEvent, CheckCaseRequest
from compliance_guard.review.lifecycle import NotificationKind
from compliance_guard.security.pii_gateway import SanitizeContext, sanitize
from compliance_guard.workflow.checks import CheckRequest
from compliance_guard.workflow.scenario import demo_mode_enabled

from ..errors import ApiError
from ..schemas import (
    AppealPayload,
    AppealResolutionPayload,
    FollowupPayload,
    PrecheckPayload,
    RevisePayload,
)
from ..security import (
    _actor_from_header,
    _default_author,
    _require_case_view,
    _require_owner_scope,
)


def register_routes(app: FastAPI, services: Any) -> None:
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
        what you sent. Work you cannot see is work you stop trusting, and an
        author who does not trust the tool writes shorter notes.

        ``scope=all`` is *narrowed* rather than refused for an author.
        Returning an error would tell them the wider set exists; returning their own
        records answers the question they can legitimately ask.
        """
        actor = _require_case_view(services.auth, x_demo_role)
        records = list(request.app.state.cases.values())

        author_roles = {Role.AUTHOR, Role.FIELD_REP, Role.REPRESENTATIVE}
        if actor.role in author_roles or scope == "mine":
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
            "scope": "mine" if (actor.role in author_roles or scope == "mine") else "all",
            "count": len(rows),
            "total": len(records),
            "cases": rows,
            "next_cursor": remaining[0]["case_id"] if remaining else None,
        }

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
            actor = _default_author()
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
            source=str(parent.get("source") or "customer_interaction_note"),
            source_record_id=str(parent.get("source_record_id") or f"SR-{case_id}"),
            source_version="v1",
            market=str(parent_body.get("market") or "CN"),
            language=str(parent_body.get("language") or "zh-CN"),
            product_id=str((parent_body.get("product") or {}).get("product_id") or ""),
            channel="customer_interaction_note",
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
