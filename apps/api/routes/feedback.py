from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, Request

from compliance_guard.domain.models import AuditEvent
from compliance_guard.review.feedback import FeedbackKind

from ..errors import ApiError
from ..schemas import FeedbackPayload
from ..security import _actor_from_header


def register_routes(app: FastAPI, services: Any) -> None:
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
