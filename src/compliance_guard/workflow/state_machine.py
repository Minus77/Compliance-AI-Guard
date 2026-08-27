"""Finite, code-controlled case workflow transitions."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from uuid import uuid4

from compliance_guard.domain.enums import CaseState, ErrorCategory, WorkflowEvent


@dataclass(frozen=True, slots=True)
class TransitionContext:
    """Server-side facts used when choosing a failure-safe transition."""

    case_id: str = field(default_factory=lambda: f"case-{uuid4().hex}")
    trace_id: str = field(default_factory=lambda: f"trace-{uuid4().hex}")
    audit_event_id: str = field(default_factory=lambda: f"audit-{uuid4().hex}")
    retryable: bool = True
    requires_human: bool = False
    failure_category: ErrorCategory | None = None

    def __post_init__(self) -> None:
        for field_name in ("case_id", "trace_id", "audit_event_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")


class StateTransitionError(RuntimeError):
    """Raised when an event is not legal from the current state."""

    def __init__(
        self,
        current: CaseState | object,
        event: WorkflowEvent | object,
        context: TransitionContext,
    ) -> None:
        self.current = current
        self.event = event
        self.context = context
        current_value = getattr(current, "value", repr(current))
        event_value = getattr(event, "value", repr(event))
        super().__init__(
            f"illegal workflow transition: {current_value} + {event_value}"
        )


_NORMAL_TRANSITIONS: dict[tuple[CaseState, WorkflowEvent], CaseState] = {
    (CaseState.RECEIVED, WorkflowEvent.AUTHORIZE): CaseState.AUTHORIZED,
    (CaseState.AUTHORIZED, WorkflowEvent.PREPROCESS): CaseState.PREPROCESSED,
    (CaseState.PREPROCESSED, WorkflowEvent.PREPARE_CONTEXT): CaseState.CONTEXT_READY,
    (CaseState.CONTEXT_READY, WorkflowEvent.CLASSIFY): CaseState.CLASSIFIED,
    (CaseState.CLASSIFIED, WorkflowEvent.RETRIEVE_EVIDENCE): CaseState.EVIDENCE_READY,
    (CaseState.EVIDENCE_READY, WorkflowEvent.EVALUATE): CaseState.EVALUATED,
    (CaseState.EVALUATED, WorkflowEvent.VALIDATE): CaseState.VALIDATED,
    (CaseState.VALIDATED, WorkflowEvent.DECIDE): CaseState.DECISIONED,
    (CaseState.DECISIONED, WorkflowEvent.ALLOW): CaseState.ALLOWED,
    (CaseState.DECISIONED, WorkflowEvent.NEEDS_INFO): CaseState.NEEDS_INFO,
    (CaseState.DECISIONED, WorkflowEvent.HUMAN_REVIEW): CaseState.HUMAN_REVIEW,
    (CaseState.DECISIONED, WorkflowEvent.BLOCK): CaseState.BLOCKED,
    (CaseState.DECISIONED, WorkflowEvent.REFUSE): CaseState.REFUSED,
    (CaseState.ALLOWED, WorkflowEvent.AUDIT): CaseState.AUDITED,
    (CaseState.NEEDS_INFO, WorkflowEvent.AUDIT): CaseState.AUDITED,
    (CaseState.HUMAN_REVIEW, WorkflowEvent.AUDIT): CaseState.AUDITED,
    (CaseState.BLOCKED, WorkflowEvent.AUDIT): CaseState.AUDITED,
    (CaseState.REFUSED, WorkflowEvent.AUDIT): CaseState.AUDITED,
    (CaseState.AUDITED, WorkflowEvent.COMPLETE): CaseState.COMPLETED,
    (CaseState.MANUAL_DEGRADED, WorkflowEvent.HUMAN_REVIEW): CaseState.HUMAN_REVIEW,
    (CaseState.MANUAL_DEGRADED, WorkflowEvent.BLOCK): CaseState.BLOCKED,
}

_SAFE_FAILURE_CATEGORIES = frozenset(
    {
        ErrorCategory.AUDIT,
        ErrorCategory.PERMISSION,
        ErrorCategory.POLICY,
        ErrorCategory.SCHEMA,
    }
)
_MANUAL_FAILURE_CATEGORIES = frozenset({ErrorCategory.MODEL_UNAVAILABLE})
_MODEL_FAILURE_SOURCE_STATES = frozenset(
    {
        CaseState.RECEIVED,
        CaseState.AUTHORIZED,
        CaseState.PREPROCESSED,
        CaseState.CONTEXT_READY,
        CaseState.CLASSIFIED,
        CaseState.EVIDENCE_READY,
        CaseState.EVALUATED,
        CaseState.VALIDATED,
        CaseState.DECISIONED,
    }
)
_FAILURE_SOURCE_STATES = frozenset(CaseState) - {
    CaseState.COMPLETED,
    CaseState.FAILED_RETRYABLE,
    CaseState.FAILED_SAFE,
    CaseState.MANUAL_DEGRADED,
}


class StateMachine:
    """Reduce explicit events through a finite state transition table."""

    def transition(
        self,
        current: CaseState,
        event: WorkflowEvent,
        context: TransitionContext,
    ) -> CaseState:
        original_current = current
        original_event = event
        try:
            current = CaseState(current)
            event = WorkflowEvent(event)
        except (TypeError, ValueError) as exc:
            raise StateTransitionError(original_current, original_event, context) from exc

        if event is WorkflowEvent.MODEL_FAILURE:
            if current not in _MODEL_FAILURE_SOURCE_STATES:
                raise StateTransitionError(current, event, context)
            if (
                context.requires_human
                or context.failure_category in _MANUAL_FAILURE_CATEGORIES
            ):
                return CaseState.MANUAL_DEGRADED
            if context.failure_category in _SAFE_FAILURE_CATEGORIES:
                return CaseState.FAILED_SAFE
            if context.retryable:
                return CaseState.FAILED_RETRYABLE
            return CaseState.FAILED_SAFE

        if event is WorkflowEvent.RETRY_COMPLETE:
            if current in {CaseState.FAILED_SAFE, CaseState.FAILED_RETRYABLE}:
                return CaseState.MANUAL_DEGRADED
            raise StateTransitionError(current, event, context)

        if event is WorkflowEvent.FAIL_RETRYABLE:
            if current not in _FAILURE_SOURCE_STATES:
                raise StateTransitionError(current, event, context)
            return CaseState.FAILED_RETRYABLE

        if event is WorkflowEvent.FAIL_SAFE:
            if current not in _FAILURE_SOURCE_STATES | {CaseState.FAILED_RETRYABLE}:
                raise StateTransitionError(current, event, context)
            return CaseState.FAILED_SAFE

        if event is WorkflowEvent.MANUAL_DEGRADE:
            if current not in _FAILURE_SOURCE_STATES | {CaseState.FAILED_RETRYABLE}:
                raise StateTransitionError(current, event, context)
            return CaseState.MANUAL_DEGRADED

        next_state = _NORMAL_TRANSITIONS.get((current, event))
        if next_state is None:
            raise StateTransitionError(current, event, context)
        return next_state


__all__ = ["StateMachine", "StateTransitionError", "TransitionContext"]
