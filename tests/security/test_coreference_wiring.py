"""B3: resolution results reach the audit trail, and ambiguity asks a question.

Two properties are load-bearing here:

* the ledger records *how* a cluster was resolved, never the names themselves —
  an audit trail that leaks raw identifiers defeats the gateway upstream of it;
* two same-surname doctors in one narrative produce ``needs_info`` rather than a
  silent guess, because wrongly merging them misattributes clinical opinion.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from compliance_guard.domain.enums import Decision
from compliance_guard.domain.models import CheckCaseRequest


def _request(content: str, *, case_id: str = "req-coref", scenario: str = "normal") -> CheckCaseRequest:
    return CheckCaseRequest(
        case_id=case_id,
        tenant_id="TENANT-CN",
        content=content,
        content_parts=[],
        source="customer_interaction_note",
        source_record_id="SR-coref",
        source_version="v1",
        market="CN",
        language="zh-CN",
        product_id="PRODUCT-001",
        channel="customer_interaction_note",
        received_at=datetime(2026, 8, 20, tzinfo=UTC),
        idempotency_key=f"idem-{case_id}",
        extensions={"scenario": scenario, "entities": [], "structured_fields": {}},
    )


def _sanitize_events(app_services, case_id: str) -> list[dict]:
    return [
        event.payload
        for event in app_services.ledger.for_case(case_id)
        if event.event_type == "entity_resolution"
    ]


def test_resolution_is_recorded_in_the_audit_ledger(app_services):
    response = app_services.orchestrator.run_check_case(
        _request("今天拜访了章三，章医生对本品很认可。", case_id="req-coref-1")
    )
    payloads = _sanitize_events(app_services, response.case_id)
    assert payloads, "entity resolution must leave an audit event"
    assert payloads[0]["cluster_count"] >= 1
    assert payloads[0]["clusters"][0]["resolution_basis"]


def test_audit_payload_never_carries_raw_names(app_services):
    response = app_services.orchestrator.run_check_case(
        _request("今天拜访了章三，章医生对本品很认可。", case_id="req-coref-2")
    )
    events = app_services.ledger.for_case(response.case_id)
    assert events
    for event in events:
        blob = json.dumps(event.payload, ensure_ascii=False)
        assert "章三" not in blob
        assert "章医生" not in blob


def test_two_same_surname_doctors_ask_instead_of_guessing(app_services):
    response = app_services.orchestrator.run_check_case(
        _request("今天拜访了章三和章丽，章三很认可本品。", case_id="req-coref-3")
    )
    assert any(f.type == "ambiguous_entity" for f in response.findings)
    assert response.decision in {Decision.NEEDS_INFO, Decision.HUMAN_REVIEW, Decision.BLOCKED}


def test_ambiguity_finding_explains_what_to_confirm(app_services):
    response = app_services.orchestrator.run_check_case(
        _request("今天拜访了章三和章丽。", case_id="req-coref-4")
    )
    finding = next(f for f in response.findings if f.type == "ambiguous_entity")
    assert finding.missing_information
    assert not any(
        marker in json.dumps(finding.model_dump(mode="json"), ensure_ascii=False)
        for marker in ("章三", "章丽")
    )


def test_single_doctor_does_not_trigger_ambiguity(app_services):
    response = app_services.orchestrator.run_check_case(
        _request("今天拜访了章三，章医生对本品很认可。", case_id="req-coref-5")
    )
    assert not any(f.type == "ambiguous_entity" for f in response.findings)
