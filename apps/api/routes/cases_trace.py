from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, Request

from compliance_guard.domain.models import AuditEvent

from ..security import _actor_from_header, _require_case_view, _require_owner_scope


def register_routes(app: FastAPI, services: Any) -> None:
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
