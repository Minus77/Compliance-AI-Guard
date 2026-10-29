"""Content, evidence, and completed-check domain contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import (
    AliasChoices,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import InitErrorDetails, PydanticCustomError

from .base import DomainModel, _contains_reserved_model_field, _utc, _validate_char_span
from .enums import (
    CaseState,
    ContentPartType,
    Decision,
    EvidenceStatus,
    Role,
    SecurityAction,
    Severity,
)

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


class CharacterSpan(DomainModel):
    """A half-open Unicode character range in an identified text version."""

    start: int = Field(ge=0, strict=True)
    end: int = Field(ge=0, strict=True)
    quote_hash: str | None = None

    @model_validator(mode="after")
    def _ordered_range(self) -> "CharacterSpan":
        if self.end < self.start:
            raise ValueError("span end must not precede its start")
        return self


class ContentPart(DomainModel):
    type: ContentPartType
    ref: str | None = None
    text: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProductContext(DomainModel):
    product_id: str = Field(min_length=1, strict=True)
    label_version: str = Field(min_length=1, strict=True)
    name: str | None = None


class Entity(DomainModel):
    entity_id: str = Field(default_factory=lambda: f"entity-{uuid4().hex}")
    type: str
    token: str | None = None
    span: str | None = Field(
        default=None,
        validation_alias=AliasChoices("span", "source_span"),
    )
    confidence: float | None = Field(default=None, ge=0, le=1)

    _validate_span = field_validator("span")(_validate_char_span)


class Finding(DomainModel):
    finding_id: str = Field(default_factory=lambda: f"finding-{uuid4().hex}")
    type: str
    severity: Severity
    decision: Decision
    confidence: float | None = Field(default=None, ge=0, le=1)
    reason: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    required_role: Role | None = None
    next_action: str | None = None
    evidence_gap: bool = False
    # Auditable rule provenance, surfaced so the UI can render a natural-language
    # explanation instead of echoing the internal reason string. Optional to keep
    # every existing construction site valid.
    rule_id: str | None = None
    matched_terms: list[str] = Field(default_factory=list)
    sla_label: str | None = None
    required_roles: list[Role] = Field(default_factory=list)
    spans: list["CharacterSpan"] = Field(default_factory=list)
    rule_version: str = ""
    category: str = ""
    allow_save: bool = True
    allow_generate: bool = True
    allow_publish: bool = True
    notification_message: str = ""
    remediation_guidance: str = ""


class CandidateFinding(DomainModel):
    """Untrusted model candidate without server-owned risk or decision fields."""

    finding_id: str = Field(default_factory=lambda: f"candidate-{uuid4().hex}")
    type: str
    confidence: float | None = Field(default=None, ge=0, le=1)
    reason: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)


class Evidence(DomainModel):
    evidence_id: str = Field(min_length=1, strict=True)
    source_id: str = Field(min_length=1, strict=True)
    version: str = Field(min_length=1, strict=True)
    market: str = Field(min_length=1, strict=True)
    product_id: str = Field(min_length=1, strict=True)
    language: str = Field(min_length=1, strict=True)
    status: EvidenceStatus = EvidenceStatus.ACTIVE
    effective_at: datetime | None = None
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    location: str = "char:0-0"
    quote: str = ""
    hash: str = Field(default="", validation_alias=AliasChoices("hash", "content_hash"))
    source_type: str = "unknown"
    tenant_id: str | None = None
    access_scope: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    _normalize_effective_at = field_validator("effective_at")(_utc)
    _normalize_effective_from = field_validator("effective_from")(_utc)
    _normalize_effective_to = field_validator("effective_to")(_utc)
    _validate_location = field_validator("location")(_validate_char_span)

    @model_validator(mode="after")
    def _sync_effective_window(self) -> "Evidence":
        if self.effective_from is None and self.effective_at is not None:
            self.effective_from = self.effective_at
        elif self.effective_at is None and self.effective_from is not None:
            self.effective_at = self.effective_from
        return self


class KnowledgeChunk(DomainModel):
    chunk_id: str = Field(min_length=1, strict=True)
    source_id: str = Field(min_length=1, strict=True)
    version: str = Field(min_length=1, strict=True)
    market: str = Field(min_length=1, strict=True)
    product_id: str = Field(min_length=1, strict=True)
    language: str = Field(min_length=1, strict=True)
    tenant_id: str | None = None
    status: EvidenceStatus = EvidenceStatus.ACTIVE
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    location: str = "char:0-0"
    text: str = ""
    checksum: str = ""
    access_scope: list[str] = Field(default_factory=list)
    source_type: str = "unknown"
    release_evidence: bool = True

    _normalize_effective_from = field_validator("effective_from")(_utc)
    _normalize_effective_to = field_validator("effective_to")(_utc)
    _validate_location = field_validator("location")(_validate_char_span)


class KnowledgeDocument(DomainModel):
    document_id: str = Field(min_length=1, strict=True)
    source_id: str = Field(min_length=1, strict=True)
    version: str = Field(min_length=1, strict=True)
    market: str = Field(min_length=1, strict=True)
    product_id: str = Field(min_length=1, strict=True)
    language: str = Field(min_length=1, strict=True)
    tenant_id: str | None = None
    status: EvidenceStatus = EvidenceStatus.ACTIVE
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    checksum: str = ""
    access_scope: list[str] = Field(default_factory=list)
    source_type: str = "unknown"
    release_evidence: bool = True
    chunks: list[KnowledgeChunk] = Field(default_factory=list)

    _normalize_effective_from = field_validator("effective_from")(_utc)
    _normalize_effective_to = field_validator("effective_to")(_utc)


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


class SecurityFinding(DomainModel):
    finding_id: str = Field(
        default_factory=lambda: f"security-{uuid4().hex}",
        min_length=1,
        strict=True,
    )
    type: str = Field(min_length=1, strict=True)
    severity: Severity
    action: SecurityAction
    reason: str | None = None
    spans: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    evidence_gap: bool = Field(default=False, strict=True)
    blocked: bool = Field(default=True, strict=True)


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
