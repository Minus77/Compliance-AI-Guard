"""D3: what the ontology could not place must produce a question, not a verdict.

Three outcomes, three different behaviours:

* concept matches the label      -> on-label, no finding
* concept differs from the label -> off-label (the existing CN-009 path)
* concept unknown to the ontology -> ``needs_info``, because guessing here is the
  one failure mode that is both silent and wrong
* only a broader category matched -> human review, since "cardiovascular disease"
  is too coarse to establish that a specific approval was respected
"""

from __future__ import annotations

from datetime import UTC, datetime

from compliance_guard.domain.enums import Decision
from compliance_guard.domain.models import CheckCaseRequest


def _request(content: str, *, case_id: str) -> CheckCaseRequest:
    return CheckCaseRequest(
        case_id=case_id,
        tenant_id="TENANT-CN",
        content=content,
        content_parts=[],
        source="call_report",
        source_record_id="SR-ind",
        source_version="v1",
        market="CN",
        language="zh-CN",
        product_id="PRODUCT-001",
        channel="call_report",
        received_at=datetime(2026, 8, 20, tzinfo=UTC),
        idempotency_key=f"idem-{case_id}",
        extensions={"entities": [], "structured_fields": {}},
    )


def _types(response) -> set[str]:
    return {finding.type for finding in response.findings}


def test_colloquial_on_label_wording_is_not_flagged_off_label(app_services):
    """血压高 must reach IND-001 rather than looking like a different disease."""
    response = app_services.orchestrator.run_check_case(
        _request("患者血压高，按说明书每天80mg口服，长期单药使用。", case_id="req-ind-1")
    )
    assert "off_label" not in _types(response)


def test_different_disease_is_flagged_off_label(app_services):
    response = app_services.orchestrator.run_check_case(
        _request("本品对糖尿病也很有效，推荐给糖尿病患者使用。", case_id="req-ind-2")
    )
    assert "off_label" in _types(response)


def test_unknown_indication_asks_instead_of_concluding(app_services):
    response = app_services.orchestrator.run_check_case(
        _request("本品对这种罕见代谢异常也有帮助。", case_id="req-ind-3")
    )
    assert response.decision != Decision.ALLOW


def test_broader_category_goes_to_human_review(app_services):
    """A category-level claim cannot establish that a specific approval holds."""
    response = app_services.orchestrator.run_check_case(
        _request("本品适用于心血管疾病的治疗。", case_id="req-ind-4")
    )
    assert response.decision in {Decision.HUMAN_REVIEW, Decision.BLOCKED, Decision.NEEDS_INFO}


def test_resolution_basis_is_recorded_for_replay(app_services):
    response = app_services.orchestrator.run_check_case(
        _request("患者血压高，建议规律服药。", case_id="req-ind-5")
    )
    events = [
        event
        for event in app_services.ledger.for_case(response.case_id)
        if event.event_type == "field_resolution"
    ]
    assert events
    indication = events[0].payload["indication"]
    assert indication["indication_id"] == "IND-001"
    assert indication["ontology_version"] == "CN-IND-2026-01"
    assert indication["basis"] == "synonym"


def test_paediatric_population_is_not_covered_by_an_adult_label(app_services):
    """Same disease, different population, different approval question."""
    response = app_services.orchestrator.run_check_case(
        _request("本品也可以用于儿童高血压的治疗。", case_id="req-ind-6")
    )
    assert response.decision != Decision.ALLOW
