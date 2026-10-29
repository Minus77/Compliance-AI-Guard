from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, Request

from compliance_guard.agents.icsr_assessment import assess_icsr
from compliance_guard.agents.icsr_followup import build_followup_form, followup_narrative
from compliance_guard.domain.models import AuditEvent, CheckCaseRequest
from compliance_guard.review.lifecycle import NotificationKind
from compliance_guard.security.pii_gateway import SanitizeContext, sanitize

from ..errors import ApiError
from ..schemas import (
    AppealPayload,
    AppealResolutionPayload,
    FollowupPayload,
    RevisePayload,
)
from ..security import _actor_from_header, _require_case_view, _require_owner_scope


def register_routes(app: FastAPI, services: Any) -> None:
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
