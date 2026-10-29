from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header

from ..security import _actor_from_header


def register_routes(app: FastAPI, services: Any) -> None:
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
