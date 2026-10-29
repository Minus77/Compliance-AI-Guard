"""Authorized review decision overrides with before/after recording.

A review override requires an authorized actor and a non-empty reason. The
system's server-controlled decision is preserved as the "before" value and the
override outcome is recorded as the "after" value, together with severity and
routing, and every override is written to the audit ledger.
"""

from __future__ import annotations

from datetime import UTC, datetime

from compliance_guard.domain.enums import Decision, ReviewTaskStatus, Severity
from compliance_guard.domain.models import Actor, AuditEvent
from compliance_guard.audit.signature import sign_record
from compliance_guard.review.decision_contracts import DecisionRecord

_REVIEW_ACTION_TO_DECISION = {
    "accepted": Decision.ALLOW,
    "approved": Decision.ALLOW,
    "rejected": Decision.BLOCKED,
    "denied": Decision.BLOCKED,
    "escalated": Decision.HUMAN_REVIEW,
    "needs_info": Decision.NEEDS_INFO,
}


class DecisionService:
    """Records review overrides only for authorized actors with a reason."""

    def __init__(self, *, queue=None, auth=None, ledger=None, metrics=None) -> None:
        self._queue = queue
        self._auth = auth
        self._ledger = ledger
        self._metrics = metrics

    def record(self, task_id: str, decision: str, reason: str, actor: Actor) -> DecisionRecord:
        if self._queue is None:
            raise RuntimeError("DecisionService requires a ReviewQueue")
        with self._queue.lock:
            task = self._queue.get(task_id)
            if task is None:
                raise KeyError(f"unknown review task {task_id!r}")
            if task.status is ReviewTaskStatus.COMPLETED:
                raise ValueError(f"review task {task_id!r} is already completed")
            if not reason or not str(reason).strip():
                raise ValueError("review override requires a non-empty reason")
            if self._auth is not None and not self._auth.can(actor, "review_case"):
                raise PermissionError(
                    f"action 'review_case' denied for role {actor.role.value!r}"
                )

            before_decision = task.system_decision or task.decision
            after_decision = _REVIEW_ACTION_TO_DECISION.get(str(decision).casefold())
            if after_decision is None:
                after_decision = Decision.HUMAN_REVIEW
            if task.severity in (Severity.S0, Severity.S1) and after_decision is Decision.ALLOW:
                raise ValueError(
                    f"an S0/S1 task ({task.severity.value}) cannot be overridden to allow; "
                    "reject or escalate instead"
                )
            before_severity = task.severity
            after_severity = task.severity
            before_routing = [task.required_role.value]
            after_routing = [task.required_role.value]

            now = datetime.now(UTC)
            record = DecisionRecord(
                task_id=task.task_id,
                case_id=task.case_id,
                trace_id=task.trace_id,
                actor=actor,
                decision=str(decision),
                override_reason=str(reason),
                before_decision=(
                    before_decision.value if before_decision is not None else ""
                ),
                after_decision=after_decision.value,
                before_severity=(
                    before_severity.value if before_severity is not None else None
                ),
                after_severity=(
                    after_severity.value if after_severity is not None else None
                ),
                before_routing=before_routing,
                after_routing=after_routing,
                purpose="professional review override",
                recorded_at=now,
            )

            task.decision = after_decision
            task.reason = str(reason)
            task.actor = actor
            task.status = ReviewTaskStatus.COMPLETED
            task.completed_at = now

            # Sign the decision. The bound fields are exactly what the signer is
            # attesting to; any later edit to them invalidates the digest.
            record.signature = sign_record(
                actor=actor,
                action=str(decision),
                reason=str(reason),
                record_type="review_decision",
                record_id=record.record_id,
                signed_at=now,
                bound_fields={
                    "task_id": task.task_id,
                    "case_id": task.case_id,
                    "before_decision": record.before_decision,
                    "after_decision": record.after_decision,
                    "before_severity": record.before_severity,
                    "after_severity": record.after_severity,
                    "reason": str(reason),
                    "signer_id": actor.actor_id,
                    "signed_at": now.isoformat(),
                },
            )

            if self._ledger is not None:
                event = self._ledger.append(
                    AuditEvent(
                        event_id=record.audit_event_id,
                        case_id=task.case_id,
                        trace_id=task.trace_id,
                        event_type="review_override",
                        occurred_at=now,
                        actor=actor,
                        payload={
                            "task_id": task.task_id,
                            "decision": str(decision),
                            "before_decision": record.before_decision,
                            "after_decision": record.after_decision,
                            "before_severity": record.before_severity,
                            "after_severity": record.after_severity,
                            "before_routing": before_routing,
                            "after_routing": after_routing,
                            "reason": str(reason),
                            "purpose": "professional review override",
                            "signature_id": record.signature.signature_id,
                            "signature_meaning": record.signature.meaning,
                            "content_digest": record.signature.content_digest,
                            "signature_kind": record.signature.signature_kind,
                        },
                    )
                )
                record.audit_event_id = event.event_id

            if self._metrics is not None:
                self._metrics.increment(f"review_decisions.{str(decision).casefold()}")
                # Whether the reviewer departed from what the system proposed. Used to
                # detect rubber-stamping, so it is derived from the recorded before /
                # after values rather than from the reviewer's own description.
                self._metrics.record_review_outcome(
                    overridden=record.before_decision != record.after_decision
                )
            return record

__all__ = ["DecisionRecord", "DecisionService"]
