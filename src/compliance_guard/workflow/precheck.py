"""L1 deterministic pre-check: review while the rep is still writing.

The tool only examined content on submit (defect D-4). That is the wrong moment:
the narrative is already finished, so a block reads as a rejection of work done
rather than a hint offered in passing. Worse, the business goal is to encourage
rich narratives, and a rep who gets blocked after writing three paragraphs learns
to write two bland sentences instead.

Pre-check runs the deterministic layer only -- masking, entity resolution, field
resolution, rule matching, label comparison -- and never calls a model. That is
the whole reason it fits inside a typing-latency budget: a model round trip is
hundreds of milliseconds to seconds, while these layers are measured in single
milliseconds.

Three properties this must preserve:

**Same policy, same wording.** It loads the same bundle as the submit path, so a
hint cannot contradict the final answer. A pre-check that says "fine" and a submit
that says "blocked" would destroy trust in the pre-check permanently.

**No record.** No case is created and the narrative is not stored. A draft in
progress is not a submission, and turning keystrokes into audit records would both
pollute the trail and expose text the author has not chosen to submit.

**Findings are a subset of the submit result.** Evidence-completeness rules are
deliberately excluded: whether the knowledge base holds a supporting record is a
statement about retrieval, not about the sentence being typed. Reporting it while
someone writes would produce a permanent "missing evidence" nag that no amount of
editing can clear, training the reader to ignore the panel entirely.
"""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from compliance_guard.domain.enums import Decision, Entrypoint
from compliance_guard.domain.models import (
    CaseContext,
    CharacterSpan,
    DomainModel,
    ExtractedData,
)
from compliance_guard.knowledge.evidence_pack import EvidencePack
from compliance_guard.knowledge.field_resolver import FieldResolver
from compliance_guard.knowledge.glossary import DEFAULT_LOCALE, Glossary, default_glossary
from compliance_guard.policy.engine import PolicyEngine
from compliance_guard.security.injection_scan import scan_untrusted_content
from compliance_guard.security.pii_gateway import PiiGateway, SanitizeContext

# Keys a client must never be able to set, because each one names part of the
# verdict. Mirrors the submit path's reserved list so the two entry points cannot
# drift into different trust boundaries.
_RESERVED_CLAIM_KEYS = frozenset(
    {"decision", "severity", "approval_status", "routing", "tool_permissions"}
)

# Rules about retrieval state rather than about the text being written. See the
# module docstring: surfacing these during typing creates an uncleanable warning.
_EVIDENCE_RULES = frozenset({"CN-010", "CN-011", "CN-012", "CN-013"})

# Same ordering the policy engine uses, so a pre-check verdict and a submit
# verdict rank outcomes identically.
_DECISION_RANK = {
    Decision.BLOCKED: 0,
    Decision.REFUSED: 1,
    Decision.HUMAN_REVIEW: 2,
    Decision.NEEDS_INFO: 3,
    Decision.ALLOW: 4,
}

# Budget from the three-tier latency design: L1 must stay clear of the point
# where a hint stops feeling like part of typing.
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


class PrecheckService:
    """Runs the deterministic layers against draft text, without a model."""

    def __init__(
        self,
        *,
        policy_store,
        label_facts_store,
        glossary: Glossary | None = None,
    ) -> None:
        self._policy_store = policy_store
        self._label_facts_store = label_facts_store
        self._glossary = glossary or default_glossary()
        self._pii = PiiGateway()
        self._fields = FieldResolver()

    def run(
        self,
        content: str,
        *,
        tenant_id: str,
        market: str = "CN",
        language: str = "zh-CN",
        product_id: str = "",
        claimed_fields: dict[str, Any] | None = None,
        known_identifiers: list[Any] | None = None,
        as_of: datetime | None = None,
        locale: str = DEFAULT_LOCALE,
        content_type: str = "customer_interaction_note",
        content_subtype: str = "",
        therapeutic_area: str = "",
        client_content_version: str = "",
        entrypoint: Entrypoint = Entrypoint.CONTENT,
    ) -> PrecheckResult:
        started = time.perf_counter()
        text = content or ""
        moment = as_of or datetime.now(UTC)
        bundle = self._policy_store.load()

        sanitized = self._pii.sanitize(
            text,
            SanitizeContext(
                tenant_id=tenant_id,
                known_identifiers=list(known_identifiers or []),
                # Pre-check is not a case, so resolution stays scoped to this
                # request and its heuristic groupings never leak into a case id.
                case_id=None,
            ),
        )

        # Strip the keys that name an outcome before anything downstream sees
        # them. The submit path already did this; the pre-check path did not, so a
        # forged `decision` field reached model validation and turned into a 500.
        # A crash is not a safe failure here: an endpoint that errors on a
        # hostile field teaches the sender that the field is interesting.
        safe_claims = {
            key: value
            for key, value in (claimed_fields or {}).items()
            if str(key).casefold() not in _RESERVED_CLAIM_KEYS
        }

        resolution = self._fields.resolve(
            text,
            market=market,
            as_of=moment,
            claimed_fields=safe_claims,
        )

        label_facts = None
        if product_id:
            try:
                label_facts = self._label_facts_store.current(product_id, market)
            except (ValueError, KeyError):
                # An unknown product is not a reason to stop offering hints; the
                # rule layer still works, only the label comparison is skipped.
                label_facts = None

        extracted = ExtractedData(
            entities=list(sanitized.entities),
            resolved_fields=dict(resolution.resolved_fields),
            claimed_fields=dict(resolution.claimed_fields),
            field_discrepancies=list(resolution.discrepancies),
        )

        # An empty pack with no declared gap: retrieval has not run, and claiming
        # a gap here would fire exactly the rules this layer excludes.
        pack = EvidencePack(
            snapshot_id="precheck",
            query=sanitized.model_text or text,
            evidence_gap=False,
        )

        engine = PolicyEngine(
            bundle,
            label_facts=label_facts,
            route_version="precheck",
            now=moment,
        )
        policy_result = engine.evaluate(
            CaseContext(
                case_id="precheck",
                trace_id="precheck",
                tenant_id=tenant_id,
                market=market,
                language=language,
                product_id=product_id,
                channel="precheck",
                content_type=content_type,
                content_version=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                therapeutic_area=therapeutic_area or None,
                source="precheck",
                source_version="draft",
                policy_version=bundle.policy_version,
            ),
            extracted,
            list(sanitized.findings) + scan_untrusted_content(text),
            pack,
            entity_resolution=sanitized.resolution,
            entrypoint=entrypoint,
            offset_map=sanitized.offset_map,
        )

        findings = [
            self._present(finding, locale)
            for finding in policy_result.findings
            if finding.rule_id not in _EVIDENCE_RULES
        ]
        decision = self._aggregate(policy_result.findings)
        decision_card = self._glossary.explain_decision(decision.value, locale)
        elapsed_ms = (time.perf_counter() - started) * 1000

        return PrecheckResult(
            decision=decision.value,
            decision_label=decision_card.label,
            decision_plain=decision_card.plain,
            next_step=decision_card.next_step,
            findings=findings,
            masked_text=sanitized.model_text,
            masked_count=len(sanitized.entities),
            ambiguous_entities=sanitized.ambiguous_entities,
            resolved_fields=dict(resolution.resolved_fields),
            claimed_fields=dict(resolution.claimed_fields),
            discrepancies=list(resolution.discrepancies),
            policy_version=bundle.policy_version,
            content_version=policy_result.content_version,
            spans_stale=bool(
                client_content_version
                and client_content_version != policy_result.content_version
            ),
            glossary_version=self._glossary.version,
            elapsed_ms=round(elapsed_ms, 3),
            within_budget=elapsed_ms < L1_BUDGET_MS,
        )

    def _aggregate(self, findings: list[Any]) -> Decision:
        """Gravest outcome among findings this layer is willing to speak about."""
        relevant = [
            finding for finding in findings if finding.rule_id not in _EVIDENCE_RULES
        ]
        if not relevant:
            return Decision.ALLOW
        return min(
            (finding.decision for finding in relevant),
            key=lambda decision: _DECISION_RANK[decision],
        )

    def _present(self, finding: Any, locale: str) -> PrecheckFinding:
        card = self._glossary.explain_finding(
            finding.type, locale, rule_id=finding.rule_id
        )
        return PrecheckFinding(
            type=finding.type,
            severity=finding.severity.value,
            decision=finding.decision.value,
            rule_id=finding.rule_id,
            matched_terms=list(finding.matched_terms),
            spans=list(finding.spans),
            rule_version=finding.rule_version,
            category=finding.category,
            allow_save=finding.allow_save,
            allow_generate=finding.allow_generate,
            allow_publish=finding.allow_publish,
            notification_message=finding.notification_message,
            remediation_guidance=finding.remediation_guidance,
            title=card.title,
            why=card.why,
            what_to_do=card.what_to_do,
            term_label=card.term_label,
            term_plain=card.term_plain,
        )


__all__ = ["L1_BUDGET_MS", "PrecheckFinding", "PrecheckResult", "PrecheckService"]
