"""Response contracts and latency budget for the L1 pre-check."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from compliance_guard.domain.enums import Decision
from compliance_guard.domain.models import CharacterSpan, DomainModel

# L1 must stay clear of the point where a hint stops feeling like part of typing.
L1_BUDGET_MS = 300


class PrecheckFinding(DomainModel):
    """One pre-check finding, already phrased for a reader."""

    type: str
    severity: str
    decision: str
    rule_id: str | None = None
    matched_terms: list[str] = Field(default_factory=list)
    spans: list[CharacterSpan] = Field(default_factory=list)
    rule_version: str = ""
    category: str = ""
    allow_save: bool = True
    allow_generate: bool = True
    allow_publish: bool = True
    notification_message: str = ""
    remediation_guidance: str = ""
    # The three-sentence card. Plain language is the point, so these are filled
    # from the glossary rather than from an internal reason string.
    title: str = ""
    why: str = ""
    what_to_do: str = ""
    term_label: str = ""
    term_plain: str = ""


class PrecheckResult(DomainModel):
    """Outcome of one deterministic pre-check pass."""

    layer: str = "L1"
    model_called: bool = False
    decision: str = Decision.ALLOW.value
    decision_label: str = ""
    decision_plain: str = ""
    next_step: str = ""
    findings: list[PrecheckFinding] = Field(default_factory=list)
    masked_text: str = ""
    masked_count: int = 0
    ambiguous_entities: bool = False
    resolved_fields: dict[str, Any] = Field(default_factory=dict)
    claimed_fields: dict[str, Any] = Field(default_factory=dict)
    discrepancies: list[str] = Field(default_factory=list)
    policy_version: str = ""
    content_version: str = ""
    spans_stale: bool = False
    glossary_version: str = ""
    elapsed_ms: float = 0.0
    within_budget: bool = True
    budget_ms: int = L1_BUDGET_MS
