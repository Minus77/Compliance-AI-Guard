"""Constrained evaluation and strict output normalization.

Model output is a candidate. ``validate_and_normalize`` parses untrusted output
through a strict schema, rejects unknown decisions/severities, verifies evidence
IDs, applies DLP and length limits, and overlays the server-controlled policy
decision and severity. Empty, truncated, refused, malformed, or unsafe responses
enter ``FAILED_SAFE`` metadata. ``evaluate_with_evidence`` can reference only
evidence IDs that exist in the EvidencePack.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import Field, ValidationError

from compliance_guard.domain.enums import Decision, Severity
from compliance_guard.domain.models import (
    CandidateFinding,
    DomainModel,
    ExtractedData,
    SecurityFinding,
)
from compliance_guard.knowledge.evidence_pack import EvidencePack
from compliance_guard.llm.types import RawModelResult
from compliance_guard.security.dlp import DlpScanner

from .pv_signal import detect_pv_signals

_MAX_OUTPUT_CHARS = 100_000
_MAX_FINDINGS = 50


class CandidateFindings(DomainModel):
    """Evidence-constrained candidate findings produced by evaluation."""

    findings: list[CandidateFinding] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    confidence: float | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    prompt_version: str | None = None
    refused: bool = False


class ValidatedResult(DomainModel):
    """Normalized, server-overlaid result of one model evaluation."""

    decision: Decision
    severity: Severity
    findings: list[CandidateFinding] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    failed_safe: bool = False
    failure_reason: str | None = None
    error_category: str | None = None
    policy_version: str | None = None
    prompt_version: str | None = None
    security_findings: list[SecurityFinding] = Field(default_factory=list)


class _RawFinding(DomainModel):
    type: str = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0, le=1)
    reason: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)


class _ModelCandidateSchema(DomainModel):
    """Strict envelope: reserved top-level fields are accepted but never honored."""

    refused: bool = False
    summary: str | None = None
    reason: str | None = None
    truncated: bool = False
    findings: list[_RawFinding] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    decision: Decision | None = None
    severity: Severity | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    approval_status: str | None = None
    routing: Any | None = None
    tool_permissions: Any | None = None


def _available_evidence_ids(evidence_pack: EvidencePack) -> set[str]:
    return {item.evidence_id for item in evidence_pack.items}


def evaluate_with_evidence(
    extracted_data: ExtractedData,
    evidence_pack: EvidencePack,
    policy_result: Any,
    task_classification: Any | None = None,
) -> CandidateFindings:
    """Build evidence-constrained candidate findings referencing only existing IDs."""
    del policy_result, task_classification
    evidence_ids = _available_evidence_ids(evidence_pack)

    findings: list[CandidateFinding] = []
    seen_types: set[str] = set()
    for candidate in extracted_data.findings:
        refs = [ref for ref in candidate.evidence_refs if ref in evidence_ids]
        missing = list(candidate.missing_information)
        if not refs and "evidence" not in missing:
            missing.append("evidence")
        seen_types.add(candidate.type)
        findings.append(
            CandidateFinding(
                finding_id=candidate.finding_id,
                type=candidate.type,
                confidence=candidate.confidence,
                reason=candidate.reason,
                evidence_refs=refs,
                missing_information=missing,
            )
        )

    for signal in detect_pv_signals(extracted_data, evidence_pack):
        if signal.type in seen_types:
            continue
        seen_types.add(signal.type)
        findings.append(signal)

    return CandidateFindings(
        findings=findings,
        missing_information=list(extracted_data.missing_information),
        confidence=extracted_data.confidence,
        evidence_ids=sorted(evidence_ids),
    )


def validate_and_normalize(
    raw_result: RawModelResult,
    policy_result: Any,
    evidence_pack: EvidencePack,
    prompt_version: str | None = None,
) -> ValidatedResult:
    """Parse, validate, and overlay server-side policy on one raw model result."""
    policy_version = getattr(policy_result, "policy_version", None)
    evidence_ids = _available_evidence_ids(evidence_pack)
    server_severity = Severity(getattr(policy_result, "severity", Severity.S3))
    server_decision = Decision(getattr(policy_result, "decision", Decision.HUMAN_REVIEW))

    def failed_safe(reason: str, category: str) -> ValidatedResult:
        return ValidatedResult(
            decision=Decision.REFUSED,
            severity=server_severity,
            findings=[],
            evidence_refs=[],
            failed_safe=True,
            failure_reason=reason,
            error_category=category,
            policy_version=policy_version,
            prompt_version=prompt_version,
        )

    if raw_result is None or raw_result.raw_json is None:
        return failed_safe("empty model response", "schema")

    if raw_result.error_category is not None:
        return failed_safe(f"model error: {raw_result.error_category}", raw_result.error_category)

    if not raw_result.raw_json:
        return failed_safe("empty model response", "schema")

    if not isinstance(raw_result.raw_json, dict):
        return failed_safe("malformed non-object model response", "schema")

    dlp = DlpScanner().scan(raw_result.raw_json)
    if dlp:
        return ValidatedResult(
            decision=Decision.REFUSED,
            severity=server_severity,
            findings=[],
            evidence_refs=[],
            failed_safe=True,
            failure_reason="model output contains raw personal identifiers",
            error_category="dlp",
            policy_version=policy_version,
            prompt_version=prompt_version,
            security_findings=dlp,
        )

    serialized = json.dumps(raw_result.raw_json, ensure_ascii=False)
    if len(serialized) > _MAX_OUTPUT_CHARS:
        return failed_safe("model output exceeds length limit", "too_large")

    try:
        schema = _ModelCandidateSchema(**raw_result.raw_json)
    except ValidationError as exc:
        detail = exc.errors()[0]["msg"] if exc.errors() else "schema violation"
        return failed_safe(f"malformed model output: {detail}", "schema")

    if schema.refused:
        return failed_safe(schema.summary or "model refused to comply", "refused")

    if schema.truncated:
        return failed_safe("model output truncated", "truncated")

    findings: list[CandidateFinding] = []
    for raw_finding in schema.findings[:_MAX_FINDINGS]:
        refs = [ref for ref in raw_finding.evidence_refs if ref in evidence_ids]
        missing = list(raw_finding.missing_information)
        if not refs and "evidence" not in missing:
            missing.append("evidence")
        findings.append(
            CandidateFinding(
                type=raw_finding.type,
                confidence=raw_finding.confidence,
                reason=raw_finding.reason,
                evidence_refs=refs,
                missing_information=missing,
            )
        )

    evidence_refs = [ref for ref in schema.evidence_refs if ref in evidence_ids]

    return ValidatedResult(
        decision=server_decision,
        severity=server_severity,
        findings=findings,
        evidence_refs=evidence_refs,
        missing_information=list(schema.missing_information),
        failed_safe=False,
        policy_version=policy_version,
        prompt_version=prompt_version,
    )


__all__ = ["CandidateFindings", "ValidatedResult", "evaluate_with_evidence", "validate_and_normalize"]
