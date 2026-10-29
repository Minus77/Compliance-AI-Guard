from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, Request

from compliance_guard.domain.enums import Severity
from compliance_guard.review.lifecycle import NotificationKind
from compliance_guard.review.tasks import is_business_review

from ..errors import ApiError
from ..schemas import BatchDecisionPayload, DecisionPayload
from ..security import _actor_from_header


def register_routes(app: FastAPI, services: Any) -> None:
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
