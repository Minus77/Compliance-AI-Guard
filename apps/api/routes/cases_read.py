from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, Request

from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import CheckCaseRequest
from compliance_guard.security.pii_gateway import SanitizeContext, sanitize
from compliance_guard.workflow.checks import CheckRequest
from compliance_guard.workflow.scenario import demo_mode_enabled

from ..errors import ApiError
from ..schemas import PrecheckPayload
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
