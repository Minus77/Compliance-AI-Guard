"""End-to-end case workflow: shared state machine, safe outcomes, review queue."""

import pytest

from compliance_guard.domain.enums import CaseState, Decision, Role, Severity

EXPECTED_OUTCOMES = {
    "normal": (Decision.ALLOW, Severity.S3, []),
    "ae": (Decision.HUMAN_REVIEW, Severity.S1, [Role.PHARMACOVIGILANCE, Role.MEDICAL_REVIEW]),
    "pii": (Decision.BLOCKED, Severity.S1, [Role.SECURITY]),
    "off_label": (Decision.HUMAN_REVIEW, Severity.S1, [Role.COMPLIANCE, Role.MEDICAL_REVIEW]),
    "redline": (Decision.HUMAN_REVIEW, Severity.S0, [Role.PHARMACOVIGILANCE, Role.MEDICAL_REVIEW]),
    "injection": (Decision.BLOCKED, Severity.S0, [Role.SECURITY]),
}


@pytest.mark.parametrize("scenario", ["normal", "ae", "pii", "off_label", "redline", "injection"])
def test_scenario_runs_through_shared_workflow(app_services, sample_request, scenario):
    response = app_services.orchestrator.run_check_case(sample_request(scenario))
    assert response.case_id.startswith("CASE-")
    assert response.trace_id
    assert response.audit_event_id
    assert response.status == CaseState.COMPLETED


@pytest.mark.parametrize("scenario", list(EXPECTED_OUTCOMES))
def test_scenario_reaches_expected_decision_severity_routing(app_services, sample_request, scenario):
    expected_decision, expected_severity, expected_roles = EXPECTED_OUTCOMES[scenario]
    response = app_services.orchestrator.run_check_case(sample_request(scenario))
    assert response.decision == expected_decision
    severity = min(
        (finding.severity for finding in response.findings),
        default=Severity.S3,
        key=lambda sev: {Severity.S0: 0, Severity.S1: 1, Severity.S2: 2, Severity.S3: 3}[sev],
    )
    assert severity == expected_severity
    tasks = app_services.review_queue.for_case(response.case_id)
    routed_roles = {task.required_role for task in tasks}
    for role in expected_roles:
        assert role in routed_roles, f"expected role {role} in routing for {scenario}"


def test_model_timeout_is_not_allow(app_services, timeout_gateway, sample_request):
    response = app_services.with_gateway(timeout_gateway).orchestrator.run_check_case(
        sample_request("normal")
    )
    assert response.decision != "allow"
    assert response.status in {
        CaseState.FAILED_SAFE,
        CaseState.MANUAL_DEGRADED,
        CaseState.COMPLETED,
    }


def test_model_timeout_degrades_to_review_task(app_services, timeout_gateway, sample_request):
    services = app_services.with_gateway(timeout_gateway)
    response = services.orchestrator.run_check_case(sample_request("normal"))
    assert response.decision == Decision.HUMAN_REVIEW
    assert response.status == CaseState.MANUAL_DEGRADED
    tasks = services.review_queue.for_case(response.case_id)
    assert tasks, "a timeout-degraded case must produce a review task"
    assert {task.required_role for task in tasks} == {Role.REVIEWER}
    for task in tasks:
        assert task.case_id == response.case_id
        assert task.trace_id == response.trace_id
        assert task.system_decision == Decision.HUMAN_REVIEW


def test_unsafe_error_returns_safe_route_never_allow(app_services, sample_request):
    from compliance_guard.llm.adapters import MockAdapter
    from compliance_guard.llm.gateway import ModelGateway
    from compliance_guard.llm.types import RawModelResult

    class ExplodingAdapter(MockAdapter):
        def complete(self, task_type, request, constraints):
            raise RuntimeError("simulated provider outage")

    services = app_services.with_gateway(ModelGateway(mock_adapter=ExplodingAdapter()))
    response = services.orchestrator.run_check_case(sample_request("normal"))
    assert response.decision == Decision.REFUSED
    assert response.status == CaseState.FAILED_SAFE
    assert response.case_id.startswith("CASE-")
    assert response.trace_id
    assert response.audit_event_id
    events = services.ledger.for_case(response.case_id)
    assert any(event.event_type == "case_unsafe_error" for event in events)


def test_unsafe_error_produces_review_task(app_services, sample_request):
    from compliance_guard.llm.adapters import MockAdapter
    from compliance_guard.llm.gateway import ModelGateway

    class ExplodingAdapter(MockAdapter):
        def complete(self, task_type, request, constraints):
            raise RuntimeError("simulated provider outage")

    services = app_services.with_gateway(ModelGateway(mock_adapter=ExplodingAdapter()))
    response = services.orchestrator.run_check_case(sample_request("normal"))
    assert response.decision == Decision.REFUSED
    assert response.status == CaseState.FAILED_SAFE
    tasks = services.review_queue.for_case(response.case_id)
    assert tasks, "an unsafe error must produce a review task for human investigation"
    assert {task.required_role for task in tasks} == {Role.REVIEWER}
    assert all(task.case_id == response.case_id for task in tasks)


def test_review_override_has_actor_reason_and_before_after(app_services, sample_request, reviewer_actor):
    response = app_services.orchestrator.run_check_case(sample_request("ae"))
    task = app_services.review_queue.for_case(response.case_id)[0]
    decision = app_services.decisions.record(
        task.task_id, "escalated", "PV reviewer confirmed follow-up", reviewer_actor
    )
    assert decision.override_reason
    assert decision.before_decision
    assert decision.after_decision


def test_review_queue_orders_by_severity_and_sla(app_services, sample_request):
    inj = app_services.orchestrator.run_check_case(sample_request("injection"))  # S0 immediate
    red = app_services.orchestrator.run_check_case(sample_request("redline"))  # S0 4h
    app_services.orchestrator.run_check_case(sample_request("ae"))  # S1 8h

    pending = app_services.review_queue.pending()
    assert pending, "expected pending review tasks"
    assert pending[0].case_id == inj.case_id
    assert pending[0].severity == Severity.S0
    assert pending[0].sla_label == "immediate"

    severities = [task.severity for task in pending]
    ranked = [0 if sev == Severity.S0 else 1 for sev in severities]
    assert ranked == sorted(ranked), "S0 tasks must be ordered before S1 tasks"


def test_review_decision_denied_without_reason(app_services, sample_request, reviewer_actor):
    response = app_services.orchestrator.run_check_case(sample_request("ae"))
    task = app_services.review_queue.for_case(response.case_id)[0]
    with pytest.raises(ValueError):
        app_services.decisions.record(task.task_id, "accepted", "  ", reviewer_actor)


def test_review_decision_denied_without_authorized_role(app_services, sample_request):
    from compliance_guard.domain.models import Actor

    response = app_services.orchestrator.run_check_case(sample_request("ae"))
    task = app_services.review_queue.for_case(response.case_id)[0]
    field_rep = Actor(actor_id="demo-field-rep", role=Role.FIELD_REP)
    with pytest.raises(PermissionError):
        app_services.decisions.record(task.task_id, "accepted", "not authorized", field_rep)


def test_audit_events_contain_before_after_for_overrides(app_services, sample_request, reviewer_actor):
    response = app_services.orchestrator.run_check_case(sample_request("ae"))
    task = app_services.review_queue.for_case(response.case_id)[0]
    app_services.decisions.record(task.task_id, "escalated", "PV confirmed", reviewer_actor)
    events = app_services.ledger.for_case(response.case_id)
    overrides = [event for event in events if event.event_type == "review_override"]
    assert overrides
    event = overrides[0]
    assert event.payload["before_decision"]
    assert event.payload["after_decision"]
    assert event.trace_id == response.trace_id


def test_retrieval_gap_never_allows(app_services):
    from datetime import UTC, datetime

    from compliance_guard.domain.models import CheckCaseRequest

    request = CheckCaseRequest(
        case_id="req-gap",
        tenant_id="TENANT-CN",
        content="完全不存在的化合物XQZ99的疗效主张",
        content_parts=[],
        source="call_report",
        market="CN",
        language="zh-CN",
        product_id="PRODUCT-001",
        channel="call_report",
        received_at=datetime(2026, 8, 20, tzinfo=UTC),
        idempotency_key="idem-gap-1",
        extensions={
            "scenario": "normal",
            "entities": [{"type": "patient", "token": "患者"}],
            "structured_fields": dict(
                indication_id="IND-001",
                population="成人",
                line="一线",
                dose="80mg",
                route="口服",
                duration="长期",
                combination="单药",
            ),
        },
    )
    response = app_services.orchestrator.run_check_case(request)
    assert response.decision != Decision.ALLOW
    assert response.status == CaseState.COMPLETED
    assert response.knowledge_snapshot_id


def test_injection_never_allows(app_services, sample_request):
    response = app_services.orchestrator.run_check_case(sample_request("injection"))
    assert response.decision != Decision.ALLOW
    assert response.decision == Decision.BLOCKED
    assert response.findings
    assert any(finding.severity == Severity.S0 for finding in response.findings)


def test_normal_allows_without_review_task(app_services, sample_request):
    response = app_services.orchestrator.run_check_case(sample_request("normal"))
    assert response.decision == Decision.ALLOW
    assert app_services.review_queue.for_case(response.case_id) == []


def test_every_state_transition_records_audit_event(app_services, sample_request):
    response = app_services.orchestrator.run_check_case(sample_request("off_label"))
    events = app_services.ledger.for_case(response.case_id)
    transition_events = [
        event
        for event in events
        if event.event_type.startswith("transition.") and event.from_state is not None and event.to_state is not None
    ]
    assert len(transition_events) >= 9
    for event in transition_events:
        assert event.case_id == response.case_id
        assert event.trace_id == response.trace_id
