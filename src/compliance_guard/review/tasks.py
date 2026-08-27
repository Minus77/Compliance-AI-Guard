"""Professional review queue ordered by severity and SLA.

Tasks are created from a policy ``ReviewPlan`` and ordered by S0/S1 severity,
SLA deadline, market, and required role. Creation is traceable and audited;
the queue itself never changes a decision - overrides belong to
:class:`compliance_guard.review.decisions.DecisionService`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from compliance_guard.domain.enums import Role, ReviewTaskStatus, Severity
from compliance_guard.domain.models import AuditEvent, ReviewTask
from compliance_guard.security.authorization import AuthorizationService

_SLA_RANK = {"immediate": 0, "4h": 1, "8h": 2, "24h": 3, "72h": 4}
_SLA_TIMEDELTA = {
    "immediate": timedelta(minutes=15),
    "4h": timedelta(hours=4),
    "8h": timedelta(hours=8),
    "24h": timedelta(hours=24),
    "72h": timedelta(hours=72),
}
_SEVERITY_RANK = {Severity.S0: 0, Severity.S1: 1, Severity.S2: 2, Severity.S3: 3}

# Roles whose queue items are technical / platform-security work rather than
# medical-business review. They are still created, still audited, and the case
# stays blocked; they are simply not part of the professional (medical /
# compliance) review queue, which exists for business judgement.
_TECHNICAL_REVIEW_ROLES = frozenset({Role.SECURITY, Role.ADMIN})


def is_business_review(task: ReviewTask) -> bool:
    """True when a task needs medical/compliance business judgement.

    Prompt injection, permission failures, and irreversible-write blocks route to
    security/admin. Those are platform findings: a medical reviewer cannot act on
    them, so surfacing them in the professional queue is noise. Suppressing the
    *queue row* never suppresses the finding -- the decision stays ``blocked``,
    the finding stays on the case, and the audit trail keeps the full record.
    """
    return task.required_role not in _TECHNICAL_REVIEW_ROLES


class ReviewQueue:
    """In-memory review queue with deterministic severity/SLA ordering."""

    def __init__(self, *, auth=None, ledger=None, metrics=None, now=None) -> None:
        self._auth = auth or AuthorizationService()
        self._ledger = ledger
        self._metrics = metrics
        self._now = now
        self._tasks: list[ReviewTask] = []

    def _clock(self) -> datetime:
        return self._now() if self._now is not None else datetime.now(UTC)

    def create(
        self,
        plan,
        *,
        case_decision=None,
        case_severity=None,
        market=None,
    ) -> ReviewTask | None:
        """Create review tasks from a policy plan; returns the first task."""
        now = self._clock()
        created: list[ReviewTask] = []
        deadline = now + _SLA_TIMEDELTA.get(plan.sla_label, timedelta(hours=72))
        for template in plan.review_tasks:
            task = ReviewTask(
                task_id=template.task_id,
                case_id=template.case_id,
                trace_id=template.trace_id,
                required_role=template.required_role,
                finding_ids=list(template.finding_ids),
                severity=case_severity,
                sla_label=plan.sla_label or "72h",
                sla_deadline=deadline,
                market=market or "CN",
                system_decision=case_decision,
                created_at=now,
            )
            self._tasks.append(task)
            if self._ledger is not None:
                self._ledger.append(
                    AuditEvent(
                        event_id=f"audit-{uuid.uuid4().hex}",
                        case_id=task.case_id,
                        trace_id=task.trace_id,
                        event_type="review_task_created",
                        occurred_at=now,
                        payload={
                            "task_id": task.task_id,
                            "required_role": task.required_role.value,
                            "sla_label": task.sla_label,
                            "severity": task.severity.value if task.severity else None,
                            "market": task.market,
                        },
                    )
                )
            if self._metrics is not None:
                self._metrics.increment("review_tasks_created")
            created.append(task)
        return created[0] if created else None

    def get(self, task_id: str) -> ReviewTask | None:
        for task in self._tasks:
            if task.task_id == task_id:
                return task
        return None

    def for_case(self, case_id: str) -> list[ReviewTask]:
        tasks = [task for task in self._tasks if task.case_id == case_id]
        return sorted(tasks, key=self._sort_key)

    def pending(self) -> list[ReviewTask]:
        return sorted(
            (task for task in self._tasks if task.status is ReviewTaskStatus.PENDING),
            key=self._sort_key,
        )

    def all(self) -> list[ReviewTask]:
        return list(self._tasks)

    @staticmethod
    def _sort_key(task: ReviewTask):
        severity_rank = _SEVERITY_RANK.get(task.severity, 3)
        sla_rank = _SLA_RANK.get(task.sla_label or "72h", 5)
        return (severity_rank, sla_rank, task.market or "", task.required_role.value)


__all__ = ["ReviewQueue"]
