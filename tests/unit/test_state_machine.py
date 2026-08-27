import pytest

from compliance_guard.domain.enums import CaseState, ErrorCategory, WorkflowEvent
from compliance_guard.workflow.state_machine import (
    StateMachine,
    StateTransitionError,
    TransitionContext,
)


def reduce_events(machine, events):
    state = CaseState.RECEIVED
    for event in events:
        state = machine.transition(state, event, TransitionContext())
    return state


def normal_case_events():
    return [
        WorkflowEvent.AUTHORIZE,
        WorkflowEvent.PREPROCESS,
        WorkflowEvent.PREPARE_CONTEXT,
        WorkflowEvent.CLASSIFY,
        WorkflowEvent.RETRIEVE_EVIDENCE,
        WorkflowEvent.EVALUATE,
        WorkflowEvent.VALIDATE,
        WorkflowEvent.DECIDE,
        WorkflowEvent.ALLOW,
        WorkflowEvent.AUDIT,
        WorkflowEvent.COMPLETE,
    ]


def test_failed_safe_never_transitions_to_allowed():
    machine = StateMachine()

    assert machine.transition(
        CaseState.FAILED_SAFE,
        WorkflowEvent.RETRY_COMPLETE,
        TransitionContext(),
    ) == CaseState.MANUAL_DEGRADED

    with pytest.raises(StateTransitionError):
        machine.transition(
            CaseState.FAILED_SAFE,
            WorkflowEvent.ALLOW,
            TransitionContext(),
        )


def test_normal_case_reaches_completed():
    machine = StateMachine()

    assert reduce_events(machine, normal_case_events()) == CaseState.COMPLETED


def test_illegal_transition_raises_typed_error():
    with pytest.raises(StateTransitionError):
        StateMachine().transition(
            CaseState.RECEIVED,
            WorkflowEvent.COMPLETE,
            TransitionContext(),
        )


def test_model_failure_without_retry_becomes_failed_safe():
    state = StateMachine().transition(
        CaseState.EVALUATED,
        WorkflowEvent.MODEL_FAILURE,
        TransitionContext(retryable=False),
    )

    assert state == CaseState.FAILED_SAFE


def test_model_failure_requiring_human_becomes_manual_degraded():
    state = StateMachine().transition(
        CaseState.EVALUATED,
        WorkflowEvent.MODEL_FAILURE,
        TransitionContext(retryable=False, requires_human=True),
    )

    assert state == CaseState.MANUAL_DEGRADED


def test_invalid_state_or_event_raises_typed_error():
    with pytest.raises(StateTransitionError):
        StateMachine().transition(
            "NOT_A_STATE",
            WorkflowEvent.COMPLETE,
            TransitionContext(),
        )


def test_schema_failure_is_failed_safe_even_if_retryable_flag_is_set():
    state = StateMachine().transition(
        CaseState.EVALUATED,
        WorkflowEvent.MODEL_FAILURE,
        TransitionContext(
            retryable=True,
            failure_category=ErrorCategory.SCHEMA,
        ),
    )

    assert state == CaseState.FAILED_SAFE


def test_model_unavailable_failure_becomes_manual_degraded():
    state = StateMachine().transition(
        CaseState.EVALUATED,
        WorkflowEvent.MODEL_FAILURE,
        TransitionContext(
            retryable=True,
            failure_category=ErrorCategory.MODEL_UNAVAILABLE,
        ),
    )

    assert state == CaseState.MANUAL_DEGRADED


@pytest.mark.parametrize(
    "current",
    [CaseState.COMPLETED, CaseState.FAILED_SAFE, CaseState.MANUAL_DEGRADED],
)
def test_model_failure_rejects_terminal_or_failed_source_states(current):
    with pytest.raises(StateTransitionError):
        StateMachine().transition(
            current,
            WorkflowEvent.MODEL_FAILURE,
            TransitionContext(),
        )


def test_transition_context_requires_traceable_ids():
    with pytest.raises(ValueError):
        TransitionContext(trace_id="")
