"""Review decision allow-guard: an S0/S1 task can never be flipped to allow.

A professional reviewer may still reject, escalate, or request more
information on an S0/S1 task; only an allow-producing override (accepted or
approved) is rejected at the service layer so a dangerous false allow cannot
be recorded by an override. Non-S0/S1 tasks keep the full override range.
"""

import pytest

from compliance_guard.domain.enums import Decision, Role, Severity
from compliance_guard.domain.models import ReviewTask
from compliance_guard.policy.routing import ReviewPlan


def test_s0_task_cannot_be_allowed_by_override(app_services, sample_request, reviewer_actor):
    response = app_services.orchestrator.run_check_case(sample_request("redline"))
    task = app_services.review_queue.for_case(response.case_id)[0]
    assert task.severity == Severity.S0
    with pytest.raises(ValueError):
        app_services.decisions.record(task.task_id, "accepted", "reviewer overrides to allow", reviewer_actor)


def test_s1_task_cannot_be_allowed_by_override(app_services, sample_request, reviewer_actor):
    response = app_services.orchestrator.run_check_case(sample_request("ae"))
    task = app_services.review_queue.for_case(response.case_id)[0]
    assert task.severity == Severity.S1
    with pytest.raises(ValueError):
        app_services.decisions.record(task.task_id, "approved", "reviewer approves to allow", reviewer_actor)


def test_s0_s1_task_still_allows_non_allow_decisions(app_services, sample_request, reviewer_actor):
    response = app_services.orchestrator.run_check_case(sample_request("redline"))
    task = app_services.review_queue.for_case(response.case_id)[0]
    assert task.severity == Severity.S0
    record = app_services.decisions.record(task.task_id, "rejected", "PV confirmed block", reviewer_actor)
    assert record.after_decision == Decision.BLOCKED.value

    response = app_services.orchestrator.run_check_case(sample_request("ae"))
    task = app_services.review_queue.for_case(response.case_id)[0]
    assert task.severity == Severity.S1
    record = app_services.decisions.record(task.task_id, "escalated", "needs medical follow-up", reviewer_actor)
    assert record.after_decision == Decision.HUMAN_REVIEW.value


def test_non_s0_s1_task_can_still_be_allowed_by_override(app_services, reviewer_actor):
    plan = ReviewPlan(
        review_tasks=[
            ReviewTask(
                task_id="review-s3-1",
                case_id="case-s3",
                trace_id="trace-s3",
                required_role=Role.REVIEWER,
                finding_ids=[],
            )
        ],
        required_roles=[Role.REVIEWER],
        sla_label="72h",
        next_actions=["low-risk guidance"],
        routing_basis="low-risk manual follow-up",
    )
    task = app_services.review_queue.create(plan, case_severity=Severity.S3, market="CN")
    assert task is not None
    record = app_services.decisions.record(task.task_id, "accepted", "low-risk case cleared", reviewer_actor)
    assert record.after_decision == Decision.ALLOW.value
