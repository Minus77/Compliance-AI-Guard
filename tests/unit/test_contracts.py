from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from compliance_guard.domain.enums import CaseState, Decision, Severity
from compliance_guard.domain.models import (
    CheckCaseRequest,
    CheckCaseResponse,
    Evidence,
    ExtractedData,
    Finding,
    ModelProfile,
    ReviewTask,
    SecurityFinding,
    TraceSpan,
)


def make_request(**overrides):
    payload = {
        "case_id": "C-1",
        "tenant_id": "TENANT-1",
        "content": "Synthetic compliance content",
        "content_parts": [],
        "source": "web",
        "source_record_id": "R-1",
        "source_version": "1",
        "market": "CN",
        "language": "zh-CN",
        "product_id": "PRODUCT-1",
        "channel": "field",
        "received_at": "2026-08-20T12:00:00Z",
        "idempotency_key": "idem-1",
        "extensions": {},
    }
    payload.update(overrides)
    return CheckCaseRequest.model_validate(payload)


def make_response(**overrides):
    payload = {
        "case_id": "C-1",
        "decision": "needs_info",
        "status": CaseState.COMPLETED,
        "market": "CN",
        "language": "zh-CN",
        "product": {"product_id": "PRODUCT-1", "label_version": "LABEL-1"},
        "findings": [],
        "evidence": [],
        "policy_version": "policy-1",
        "knowledge_snapshot_id": "knowledge-1",
        "model_profile_id": "profile-1",
        "model_version": "model-1",
        "route_version": "route-1",
        "prompt_version": "prompt-1",
        "trace_id": "trace-1",
        "audit_event_id": "audit-1",
    }
    payload.update(overrides)
    return CheckCaseResponse.model_validate(payload)


def make_evidence(**overrides):
    payload = {
        "evidence_id": "E-1",
        "source_id": "SOURCE-1",
        "version": "LABEL-1",
        "market": "CN",
        "product_id": "PRODUCT-1",
        "language": "zh-CN",
        "status": "active",
        "effective_at": "2026-08-19T00:00:00Z",
        "location": "char:0-10",
        "quote": "Synthetic evidence",
        "hash": "hash-1",
        "source_type": "label",
    }
    payload.update(overrides)
    return Evidence.model_validate(payload)


def test_response_rejects_unknown_decision():
    with pytest.raises(ValidationError):
        CheckCaseResponse.model_validate({"case_id": "C-1", "decision": "maybe"})


def test_request_rejects_missing_case_id():
    payload = {
        "tenant_id": "TENANT-1",
        "content": "Synthetic compliance content",
        "market": "CN",
        "language": "zh-CN",
        "product_id": "PRODUCT-1",
        "channel": "field",
        "received_at": "2026-08-20T12:00:00Z",
        "idempotency_key": "idem-1",
    }

    with pytest.raises(ValidationError):
        CheckCaseRequest.model_validate(payload)


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValidationError):
        Finding(type="off_label", severity="S4", decision="human_review")


def test_high_risk_finding_cannot_allow_without_evidence():
    response = make_response(
        decision="allow",
        findings=[
            Finding(
                type="off_label",
                severity="S1",
                decision="allow",
                evidence_refs=[],
            )
        ],
    )

    with pytest.raises(ValidationError):
        response.validate_business_invariants()


def test_high_risk_finding_requires_evidence_or_explicit_evidence_gap():
    response = make_response(
        findings=[
            Finding(
                type="off_label",
                severity=Severity.S1,
                decision=Decision.HUMAN_REVIEW,
                missing_information=["evidence_gap"],
            )
        ]
    )

    assert response.validate_business_invariants() is response


def test_response_rejects_orphan_evidence_reference():
    response = make_response(
        findings=[
            Finding(
                type="comparative_claim",
                severity="S2",
                decision="human_review",
                evidence_refs=["E-404"],
            )
        ]
    )

    with pytest.raises(ValidationError):
        response.validate_business_invariants()


def test_sensitive_finding_cannot_produce_top_level_allow():
    response = make_response(
        decision="allow",
        findings=[
            Finding(
                type="off_label",
                severity="S2",
                decision="human_review",
                evidence_refs=["E-1"],
            )
        ],
        evidence=[make_evidence()],
    )

    with pytest.raises(ValidationError):
        response.validate_business_invariants()


@pytest.mark.parametrize(
    "finding_type",
    [
        "AE/SAE",
        "PII/PHI",
        "bribery",
        "evidence conflict",
        "injection",
        "permission failure",
        "irreversible writes",
    ],
)
def test_named_sensitive_finding_types_are_human_safe(finding_type):
    response = make_response(
        decision="allow",
        findings=[
            Finding(
                type=finding_type,
                severity="S2",
                decision="human_review",
                evidence_refs=["E-1"],
            )
        ],
        evidence=[make_evidence()],
    )

    with pytest.raises(ValidationError):
        response.validate_business_invariants()


def test_response_rejects_evidence_from_another_market_or_product():
    response = make_response(
        findings=[
            Finding(
                type="comparative_claim",
                severity="S2",
                decision="human_review",
                evidence_refs=["E-1"],
            )
        ],
        evidence=[make_evidence(market="US", product_id="OTHER")],
    )

    with pytest.raises(ValidationError):
        response.validate_business_invariants()


def test_response_rejects_mixed_evidence_versions():
    response = make_response(
        findings=[
            Finding(
                type="comparative_claim",
                severity="S2",
                decision="human_review",
                evidence_refs=["E-1", "E-2"],
            )
        ],
        evidence=[
            make_evidence(evidence_id="E-1", version="LABEL-1"),
            make_evidence(evidence_id="E-2", version="LABEL-2"),
        ],
    )

    with pytest.raises(ValidationError):
        response.validate_business_invariants()


def test_regulated_response_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        CheckCaseResponse.model_validate(
            {"case_id": "C-1", "decision": "allow", "unexpected": True}
        )


def test_extensions_preserve_unknown_source_fields():
    request = make_request(extensions={"legacy_status": "pending", "source_flag": 1})

    assert request.extensions == {"legacy_status": "pending", "source_flag": 1}


def test_timestamps_are_normalized_and_evidence_span_is_preserved():
    request = make_request(received_at="2026-08-20T12:00:00+00:00")
    evidence = make_evidence(
        location="char:2-10",
        effective_at="2026-08-19T00:00:00Z",
    )

    assert request.received_at == datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
    assert evidence.effective_at == datetime(2026, 8, 19, tzinfo=UTC)
    assert evidence.location == "char:2-10"


def test_candidate_data_rejects_final_decision_and_severity_fields():
    with pytest.raises(ValidationError):
        ExtractedData.model_validate({"decision": "allow"})

    with pytest.raises(ValidationError):
        ExtractedData.model_validate(
            {
                "findings": [
                    {
                        "type": "off_label",
                        "severity": "S1",
                        "decision": "allow",
                    }
                ]
            }
        )

    with pytest.raises(ValidationError):
        ExtractedData.model_validate(
            {"extracted_fields": {"nested": {"routing": "untrusted-model-route"}}}
        )


@pytest.mark.parametrize(
    "failure_state",
    [CaseState.FAILED_SAFE, CaseState.MANUAL_DEGRADED],
)
def test_allow_is_invalid_in_failure_or_manual_state(failure_state):
    response = make_response(decision="allow", status=failure_state)

    with pytest.raises(ValidationError):
        response.validate_business_invariants()


def test_decision_must_match_terminal_outcome_state():
    response = make_response(decision="needs_info", status=CaseState.ALLOWED)

    with pytest.raises(ValidationError):
        response.validate_business_invariants()


def test_response_requires_trace_and_audit_ids():
    payload = make_response().model_dump()
    payload.pop("trace_id")
    payload.pop("audit_event_id")

    with pytest.raises(ValidationError):
        CheckCaseResponse.model_validate(payload)


def test_evidence_requires_non_empty_scope_and_version():
    with pytest.raises(ValidationError):
        Evidence(
            evidence_id="E-1",
            source_id="SOURCE-1",
            language="zh-CN",
            status="active",
            location="char:0-10",
            quote="Synthetic evidence",
            hash="hash-1",
            source_type="label",
        )


def test_evidence_must_match_response_label_version():
    response = make_response(
        findings=[
            Finding(
                type="comparative_claim",
                severity="S2",
                decision="human_review",
                evidence_refs=["E-1"],
            )
        ],
        evidence=[make_evidence(version="LABEL-2")],
    )

    with pytest.raises(ValidationError):
        response.validate_business_invariants()


def test_security_finding_is_part_of_response_and_cannot_allow():
    with pytest.raises(ValidationError):
        response = make_response(
            decision="allow",
            security_findings=[
                SecurityFinding(
                    type="security",
                    severity="S2",
                    action="block",
                    evidence_refs=["E-1"],
                )
            ],
            evidence=[make_evidence()],
        )
        response.validate_business_invariants()


@pytest.mark.parametrize("finding_type", ["security", "security_finding", "safety"])
def test_generic_security_findings_cannot_allow(finding_type):
    response = make_response(
        decision="allow",
        findings=[
            Finding(
                type=finding_type,
                severity="S2",
                decision="human_review",
                evidence_refs=["E-1"],
            )
        ],
        evidence=[make_evidence()],
    )

    with pytest.raises(ValidationError):
        response.validate_business_invariants()


def test_controlled_statuses_reject_unknown_values():
    with pytest.raises(ValidationError):
        make_evidence(status="not-a-status")

    with pytest.raises(ValidationError):
        ReviewTask(
            case_id="C-1",
            trace_id="T-1",
            required_role="compliance",
            status="not-a-status",
        )

    with pytest.raises(ValidationError):
        TraceSpan(
            span_id="SPAN-1",
            trace_id="T-1",
            case_id="C-1",
            operation="policy",
            status="not-a-status",
            started_at="2026-08-20T12:00:00Z",
        )

    with pytest.raises(ValidationError):
        ModelProfile(
            profile_id="PROFILE-1",
            provider="mock",
            display_name="Mock",
            model_id="mock-1",
            adapter_type="not-an-adapter",
        )
