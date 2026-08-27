"""Model output normalization: candidates can never override policy; fail-safe handling."""

from datetime import UTC, datetime

import pytest

from compliance_guard.agents.evaluator import CandidateFindings, evaluate_with_evidence, validate_and_normalize
from compliance_guard.domain.enums import Decision, Severity, TaskType
from compliance_guard.domain.models import (
    CandidateFinding,
    Entity,
    Evidence,
    ExtractedData,
)
from compliance_guard.knowledge.evidence_pack import EvidencePack
from compliance_guard.llm.adapters import MockAdapter
from compliance_guard.llm.gateway import ModelGateway
from compliance_guard.llm.registry import ModelRegistry
from compliance_guard.llm.types import ModelConstraints, ModelRequest, RawModelResult
from compliance_guard.policy.engine import PolicyResult

VALID_EVIDENCE_ID = "EV-CN-2026-001"


def high_risk_policy_result() -> PolicyResult:
    return PolicyResult(
        decision=Decision.BLOCKED,
        severity=Severity.S1,
        policy_version="CN-COMPLIANCE-2026-01",
        reasons=["high-risk server-controlled decision"],
    )


def raw_model_result(
    decision=None,
    severity=None,
    evidence_refs=None,
    findings=None,
    **extra,
) -> RawModelResult:
    payload: dict = {}
    if decision is not None:
        payload["decision"] = decision
    if severity is not None:
        payload["severity"] = severity
    if evidence_refs is not None:
        payload["evidence_refs"] = evidence_refs
    if findings is not None:
        payload["findings"] = findings
    payload.update(extra)
    return RawModelResult(
        provider="mock",
        model_id="DeepSeek V4 Flash",
        profile_id="deepseek-routine",
        raw_json=payload,
    )


def _evidence(evidence_id: str = VALID_EVIDENCE_ID) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        source_id="CN-PI-2026-01",
        version="CN-PI-2026-01",
        market="CN",
        product_id="PRODUCT-001",
        language="zh-CN",
    )


def test_model_output_cannot_override_policy(policy_result, evidence_pack):
    raw = raw_model_result(decision="allow", severity="S3", evidence_refs=[])
    result = validate_and_normalize(
        raw, policy_result=high_risk_policy_result(), evidence_pack=evidence_pack
    )
    assert result.decision != "allow"
    assert result.severity == "S1"


def test_normalization_overlays_server_side_decision_and_severity(policy_result, evidence_pack):
    raw = raw_model_result(
        findings=[{"type": "ae", "confidence": 0.8, "evidence_refs": [VALID_EVIDENCE_ID]}]
    )
    result = validate_and_normalize(raw, policy_result=policy_result, evidence_pack=evidence_pack)
    assert result.decision == policy_result.decision
    assert result.severity == policy_result.severity
    assert result.failed_safe is False
    assert result.findings[0].type == "ae"


def test_empty_model_response_enters_failed_safe(policy_result, evidence_pack):
    raw = RawModelResult(provider="mock", raw_json={})
    result = validate_and_normalize(raw, policy_result=policy_result, evidence_pack=evidence_pack)
    assert result.failed_safe is True
    assert result.decision == "refused"
    assert result.error_category == "schema"


def test_error_category_from_adapter_enters_failed_safe(policy_result, evidence_pack):
    raw = RawModelResult(provider="mock", raw_json={}, error_category="mock_response_missing")
    result = validate_and_normalize(raw, policy_result=policy_result, evidence_pack=evidence_pack)
    assert result.failed_safe is True
    assert result.error_category == "mock_response_missing"


def test_refused_model_response_enters_failed_safe(policy_result, evidence_pack):
    raw = raw_model_result(refused=True, reason="cannot comply")
    result = validate_and_normalize(raw, policy_result=policy_result, evidence_pack=evidence_pack)
    assert result.failed_safe is True
    assert result.error_category == "refused"


def test_truncated_model_response_enters_failed_safe(policy_result, evidence_pack):
    raw = raw_model_result(truncated=True)
    result = validate_and_normalize(raw, policy_result=policy_result, evidence_pack=evidence_pack)
    assert result.failed_safe is True
    assert result.error_category == "truncated"


def test_malformed_unknown_decision_enters_failed_safe(policy_result, evidence_pack):
    raw = raw_model_result(decision="unlimited_everything", severity="S3")
    result = validate_and_normalize(raw, policy_result=policy_result, evidence_pack=evidence_pack)
    assert result.failed_safe is True
    assert result.error_category == "schema"


def test_malformed_unknown_severity_enters_failed_safe(policy_result, evidence_pack):
    raw = raw_model_result(decision="allow", severity="S9")
    result = validate_and_normalize(raw, policy_result=policy_result, evidence_pack=evidence_pack)
    assert result.failed_safe is True
    assert result.error_category == "schema"


def test_malformed_extra_keys_enter_failed_safe(policy_result, evidence_pack):
    raw = raw_model_result(bogus_key="unexpected")
    result = validate_and_normalize(raw, policy_result=policy_result, evidence_pack=evidence_pack)
    assert result.failed_safe is True
    assert result.error_category == "schema"


def test_dlp_rejects_raw_pii_in_model_output(policy_result, evidence_pack):
    raw = raw_model_result(
        findings=[{"type": "ae", "reason": "患者王小明电话13812345678", "evidence_refs": []}]
    )
    result = validate_and_normalize(raw, policy_result=policy_result, evidence_pack=evidence_pack)
    assert result.failed_safe is True
    assert result.error_category == "dlp"


def test_invalid_evidence_refs_are_dropped(policy_result, evidence_pack):
    raw = raw_model_result(
        findings=[
            {
                "type": "ae",
                "confidence": 0.9,
                "reason": "signal",
                "evidence_refs": [VALID_EVIDENCE_ID, "EV-NOPE-0001"],
            }
        ]
    )
    result = validate_and_normalize(raw, policy_result=policy_result, evidence_pack=evidence_pack)
    assert result.findings[0].evidence_refs == [VALID_EVIDENCE_ID]


def test_evaluator_references_only_existing_evidence(evidence_pack):
    extracted = ExtractedData(
        entities=[Entity(type="patient", token="患者")],
        findings=[
            CandidateFinding(
                type="ae",
                confidence=0.9,
                reason="signal",
                evidence_refs=[VALID_EVIDENCE_ID, "EV-IMAGINED-1"],
            )
        ],
        extracted_fields={},
    )
    findings = evaluate_with_evidence(
        extracted,
        evidence_pack,
        high_risk_policy_result(),
        task_classification=None,
    )
    for candidate in findings.findings:
        assert set(candidate.evidence_refs) <= {VALID_EVIDENCE_ID}


def test_evaluator_returns_gap_when_no_evidence(evidence_pack):
    extracted = ExtractedData(
        entities=[Entity(type="patient", token="患者")],
        findings=[CandidateFinding(type="ae", confidence=0.9, reason="signal", evidence_refs=[])],
        extracted_fields={},
    )
    findings = evaluate_with_evidence(
        extracted, evidence_pack, high_risk_policy_result(), task_classification=None
    )
    assert any("evidence" in candidate.missing_information for candidate in findings.findings)


def test_gateway_records_route_metadata(registry: ModelRegistry, mock_gateway: ModelGateway):
    route = registry.resolve(
        TaskType.ROUTINE_COMPLIANCE, modality="text", data_class="pii_tokenized", region="CN"
    )
    result = mock_gateway.complete(
        task_type="routine_compliance",
        request=ModelRequest(scenario="normal", content="synthetic content"),
        constraints=ModelConstraints(mode="mock"),
        route=route,
    )
    assert result.profile_id == route.primary_profile.profile_id
    assert result.model_id == route.primary_profile.model_id
    assert result.route_version == route.route_version
    assert result.error_category is None
    assert result.latency_ms >= 0
    assert result.fallback_used is False


def test_gateway_uses_published_fallback_and_records_fallback_used(
    registry: ModelRegistry,
):
    class FailingPrimary(MockAdapter):
        def complete(self, task_type, request, constraints):
            if constraints.profile_id == "deepseek-routine":
                return RawModelResult(
                    provider="mock",
                    profile_id="deepseek-routine",
                    model_id="DeepSeek V4 Flash",
                    raw_json={},
                    error_category="provider",
                )
            return super().complete(task_type, request, constraints)

    gateway = ModelGateway(mock_adapter=FailingPrimary())
    route = registry.resolve(
        TaskType.ROUTINE_COMPLIANCE, modality="text", data_class="pii_tokenized", region="CN"
    )
    result = gateway.complete(
        task_type="routine_compliance",
        request=ModelRequest(scenario="normal", content="synthetic content"),
        constraints=ModelConstraints(mode="mock"),
        route=route,
    )
    assert result.fallback_used is True
    assert result.profile_id == "kimi-complex"
    assert result.model_id == "Kimi K3"
    assert result.error_category is None
