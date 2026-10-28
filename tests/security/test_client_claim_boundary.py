"""G1: a client declaration is a hint, never a fact the decision depends on.

Reproduced on the pre-fix code: the same narrative about 糖尿病 produced an
``off_label`` finding when the client declared nothing, and *no* off-label
finding when the client declared ``indication_id=IND-001``. Structured form
fields were merged over the server's own extraction, so content could vouch for
itself (defect P-1).

The boundary this file pins:

* judgment reads ``resolved_fields`` — what the server derived from the text;
* ``claimed_fields`` may fill forms and be cross-checked, nothing more;
* a claim that contradicts the narrative is itself a signal, not a silent win.
"""

from __future__ import annotations

from datetime import UTC, datetime

from compliance_guard.domain.enums import Decision
from compliance_guard.domain.models import CheckCaseRequest

OFF_LABEL_NARRATIVE = "本品对糖尿病患者也很有效，可以放心推荐给糖尿病人使用。"

ON_LABEL_CLAIM = {
    "indication": "成人原发性高血压",
    "indication_id": "IND-001",
    "population": "成人",
    "line": "一线",
    "dose": "80mg",
    "route": "口服",
    "duration": "长期",
    "combination": "单药",
}


def _request(content: str, *, fields: dict | None = None, case_id: str = "req-claim") -> CheckCaseRequest:
    return CheckCaseRequest(
        case_id=case_id,
        tenant_id="TENANT-CN",
        content=content,
        content_parts=[],
        source="customer_interaction_note",
        source_record_id="SR-claim",
        source_version="v1",
        market="CN",
        language="zh-CN",
        product_id="PRODUCT-001",
        channel="customer_interaction_note",
        received_at=datetime(2026, 8, 20, tzinfo=UTC),
        idempotency_key=f"idem-{case_id}",
        extensions={
            "scenario": "off_label",
            "entities": [],
            "structured_fields": dict(fields or {}),
        },
    )


def _types(response) -> set[str]:
    return {finding.type for finding in response.findings}


def test_off_label_is_detected_when_client_declares_nothing(app_services):
    response = app_services.orchestrator.run_check_case(
        _request(OFF_LABEL_NARRATIVE, case_id="req-claim-honest")
    )
    assert "off_label" in _types(response)


def test_forged_on_label_claim_cannot_hide_off_label_content(app_services):
    """The regression lock for P-1."""
    response = app_services.orchestrator.run_check_case(
        _request(OFF_LABEL_NARRATIVE, fields=ON_LABEL_CLAIM, case_id="req-claim-forged")
    )
    assert "off_label" in _types(response)
    assert response.decision != Decision.ALLOW


def test_declaring_on_label_does_not_change_the_decision(app_services):
    honest = app_services.orchestrator.run_check_case(
        _request(OFF_LABEL_NARRATIVE, case_id="req-claim-a")
    )
    forged = app_services.orchestrator.run_check_case(
        _request(OFF_LABEL_NARRATIVE, fields=ON_LABEL_CLAIM, case_id="req-claim-b")
    )
    assert forged.decision == honest.decision


def test_contradicting_the_narrative_raises_a_discrepancy(app_services):
    response = app_services.orchestrator.run_check_case(
        _request(OFF_LABEL_NARRATIVE, fields=ON_LABEL_CLAIM, case_id="req-claim-disc")
    )
    assert "claim_discrepancy" in _types(response)


def test_agreeing_with_the_narrative_raises_no_discrepancy(app_services):
    response = app_services.orchestrator.run_check_case(
        _request(
            "本品适用于成人原发性高血压的治疗，应遵医嘱规律服用。",
            fields=ON_LABEL_CLAIM,
            case_id="req-claim-agree",
        )
    )
    assert "claim_discrepancy" not in _types(response)


def test_discrepancy_is_recorded_in_the_audit_trail(app_services):
    response = app_services.orchestrator.run_check_case(
        _request(OFF_LABEL_NARRATIVE, fields=ON_LABEL_CLAIM, case_id="req-claim-audit")
    )
    events = app_services.ledger.for_case(response.case_id)
    assert any(event.event_type == "field_resolution" for event in events)


def test_resolved_fields_are_reported_separately_from_claims(app_services):
    response = app_services.orchestrator.run_check_case(
        _request(OFF_LABEL_NARRATIVE, fields=ON_LABEL_CLAIM, case_id="req-claim-split")
    )
    events = [
        event
        for event in app_services.ledger.for_case(response.case_id)
        if event.event_type == "field_resolution"
    ]
    payload = events[0].payload
    assert payload["resolved"]["indication_id"] == "IND-002"
    assert payload["claimed"]["indication_id"] == "IND-001"
    assert payload["discrepancies"]
