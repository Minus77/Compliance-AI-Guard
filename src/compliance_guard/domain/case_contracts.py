"""Case intake and response contracts with cross-object invariants."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, ValidationError, field_validator
from pydantic_core import InitErrorDetails, PydanticCustomError

from .base import DomainModel, _utc
from .content_primitives import ContentPart, Entity, ProductContext
from .enums import CaseState, Decision, Severity
from .evidence import Evidence
from .findings import Finding, SecurityFinding

_HUMAN_SAFE_FINDING_TYPES = frozenset(
    {
        "ae",
        "ae_sae",
        "adverse_event",
        "bribery",
        "evidence_conflict",
        "irreversible_write",
        "irreversible_writes",
        "injection",
        "off_label",
        "permission_failure",
        "phi",
        "pii",
        "pii_phi",
        "prompt_injection",
        "sae",
        "safety",
        "safety_finding",
        "security",
        "security_finding",
        "security_issue",
        "security_risk",
        "serious_adverse_event",
    }
)

_OUTCOME_DECISIONS = {
    CaseState.ALLOWED: Decision.ALLOW,
    CaseState.NEEDS_INFO: Decision.NEEDS_INFO,
    CaseState.HUMAN_REVIEW: Decision.HUMAN_REVIEW,
    CaseState.BLOCKED: Decision.BLOCKED,
    CaseState.REFUSED: Decision.REFUSED,
}
_FAILURE_STATES = {
    CaseState.FAILED_RETRYABLE,
    CaseState.FAILED_SAFE,
    CaseState.MANUAL_DEGRADED,
}


class CheckCaseRequest(DomainModel):
    case_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    content: str
    content_parts: list[ContentPart] = Field(default_factory=list)
    source: str
    source_record_id: str | None = None
    source_version: str | None = None
    market: str
    language: str
    product_id: str
    channel: str
    received_at: datetime
    idempotency_key: str = Field(min_length=1)
    extensions: dict[str, Any] = Field(default_factory=dict)

    _normalize_received_at = field_validator("received_at")(_utc)


def _raise_business_validation(
    model_name: str,
    errors: list[tuple[tuple[str | int, ...], str, Any]],
) -> None:
    line_errors = [
        InitErrorDetails(
            type=PydanticCustomError("business_invariant", message),
            loc=location,
            input=input_value,
        )
        for location, message, input_value in errors
    ]
    raise ValidationError.from_exception_data(model_name, line_errors)


class CheckCaseResponse(DomainModel):
    case_id: str = Field(min_length=1)
    decision: Decision
    status: CaseState
    market: str = Field(min_length=1, strict=True)
    language: str = Field(min_length=1, strict=True)
    product: ProductContext
    entities: list[Entity] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    policy_version: str | None = None
    knowledge_snapshot_id: str | None = None
    model_profile_id: str | None = None
    model_version: str | None = None
    route_version: str | None = None
    prompt_version: str | None = None
    trace_id: str = Field(min_length=1, strict=True)
    audit_event_id: str = Field(min_length=1, strict=True)
    # Retrieval (RAG) explainability, carried as a plain mapping because the
    # knowledge layer imports this module (importing EvidencePack here would
    # be circular). Populated by the orchestrator from the EvidencePack.
    retrieval: dict[str, Any] = Field(default_factory=dict)
    # ICSR minimum-criteria assessment and regulatory reporting clock, carried
    # as a plain mapping for the same import-cycle reason as `retrieval`.
    icsr: dict[str, Any] = Field(default_factory=dict)
    # Plain-language reading of this result: what happened, why it matters, what to
    # do next. Carried as a plain mapping for the same import-cycle reason as
    # `retrieval`. The machine codes stay on the response proper -- this section
    # exists so a reader never has to decode `S1` to know what to do, while an
    # auditor still gets the exact rule ids under `technical`.
    guidance: dict[str, Any] = Field(default_factory=dict)
    # Outstanding ICSR questions, as fields the author can actually fill. Naming a
    # missing element without offering somewhere to supply it reads as a refusal
    # (defect P-9). Plain mapping for the same import-cycle reason as `retrieval`.
    followup: dict[str, Any] = Field(default_factory=dict)

    def validate_business_invariants(self) -> CheckCaseResponse:
        """Validate cross-object rules that cannot be expressed by field types."""

        errors: list[tuple[tuple[str | int, ...], str, Any]] = []
        evidence_ids = {item.evidence_id for item in self.evidence}
        high_risk = {Severity.S0, Severity.S1}
        product_id = self.product.product_id
        label_version = self.product.label_version

        if self.status in _FAILURE_STATES and self.decision is Decision.ALLOW:
            errors.append(
                (
                    ("decision",),
                    "allow is invalid in failure or manual degraded states",
                    self.decision,
                )
            )

        expected_decision = _OUTCOME_DECISIONS.get(self.status)
        if expected_decision is not None and self.decision is not expected_decision:
            errors.append(
                (
                    ("decision", "status"),
                    f"{self.status.value} requires decision {expected_decision.value!r}",
                    self.decision,
                )
            )

        evidence_versions = {item.version for item in self.evidence if item.version}
        if len(evidence_versions) > 1:
            errors.append(
                (
                    ("evidence",),
                    "evidence from multiple versions cannot share a response",
                    evidence_versions,
                )
            )

        for index, evidence in enumerate(self.evidence):
            if not evidence.market or evidence.market != self.market:
                errors.append(
                    (
                        ("evidence", index, "market"),
                        "evidence market does not match the response market",
                        evidence.market,
                    )
                )
            if not evidence.product_id or evidence.product_id != product_id:
                errors.append(
                    (
                        ("evidence", index, "product_id"),
                        "evidence product does not match the response product",
                        evidence.product_id,
                    )
                )
            if not evidence.version or evidence.version != label_version:
                errors.append(
                    (
                        ("evidence", index, "version"),
                        "evidence version does not match the response label version",
                        evidence.version,
                    )
                )

        for index, finding in enumerate(self.findings):
            location = ("findings", index)
            finding_type = (
                finding.type.strip().lower().replace("/", "_").replace("-", "_").replace(" ", "_")
            )
            if finding.severity in high_risk and not finding.evidence_refs:
                has_gap = finding.evidence_gap or "evidence_gap" in (
                    item.lower() for item in finding.missing_information
                )
                if not has_gap:
                    errors.append(
                        (
                            location,
                            "high-risk finding requires evidence or evidence_gap",
                            finding,
                        )
                    )

            for evidence_ref in finding.evidence_refs:
                if evidence_ref not in evidence_ids:
                    errors.append(
                        (
                            (*location, "evidence_refs"),
                            f"evidence reference {evidence_ref!r} is not present",
                            evidence_ref,
                        )
                    )

            if self.decision is Decision.ALLOW and finding.severity in high_risk:
                errors.append(
                    (
                        ("decision",),
                        "S0/S1 findings cannot produce a top-level allow",
                        self.decision,
                    )
                )

            if self.decision is Decision.ALLOW and finding_type in _HUMAN_SAFE_FINDING_TYPES:
                errors.append(
                    (
                        ("decision",),
                        f"{finding.type!r} findings cannot produce a top-level allow",
                        self.decision,
                    )
                )

        for index, finding in enumerate(self.security_findings):
            location = ("security_findings", index)
            if self.decision is Decision.ALLOW:
                errors.append(
                    (
                        ("decision",),
                        "security findings cannot produce a top-level allow",
                        self.decision,
                    )
                )
            if finding.severity in high_risk and not finding.evidence_refs:
                has_gap = finding.evidence_gap or "evidence_gap" in (
                    item.lower() for item in finding.missing_information
                )
                if not has_gap:
                    errors.append(
                        (
                            location,
                            "high-risk security finding requires evidence or evidence_gap",
                            finding,
                        )
                    )
            for evidence_ref in finding.evidence_refs:
                if evidence_ref not in evidence_ids:
                    errors.append(
                        (
                            (*location, "evidence_refs"),
                            f"evidence reference {evidence_ref!r} is not present",
                            evidence_ref,
                        )
                    )

        if errors:
            _raise_business_validation(self.__class__.__name__, errors)
        return self
