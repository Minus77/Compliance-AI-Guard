"""Deterministic compliance policy engine.

Model output is a candidate; the final decision, severity, approval status,
routing, and tool permissions are server-controlled. This engine evaluates
server-side rules from a policy bundle plus structured inputs (extraction,
security findings, label comparison, evidence pack) and produces a
:class:`PolicyResult` that no model can override.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from compliance_guard.domain.enums import (
    Decision,
    Entrypoint,
    EvidenceStatus,
    Role,
    SecurityAction,
    Severity,
    normalize_content_type,
)
from compliance_guard.domain.models import (
    CaseContext,
    CharacterSpan,
    DomainModel,
    Evidence,
    ExtractedData,
    Finding,
    PolicyBundle,
    SecurityFinding,
)
from compliance_guard.knowledge.evidence_pack import EvidencePack
from compliance_guard.knowledge.label_facts import LabelFacts, compare_label_fields

from .bundles import PolicyRule, parse_bundle_rules
from .routing import RaciMatrix, ReviewPlan, default_raci, route_review
from .severity import calculate_severity
from .spans import TextOffsetMap, find_spans

_COMPARED_FIELDS = ("indication", "indication_id", "population", "line", "dose", "route", "duration", "combination")

# Rules the server determines from state the model cannot observe: what the
# evidence pack contains, whether authorization succeeded, whether a write was
# irreversible, and whether content/entities were actually present.
#
# A model candidate for one of these is speculation, and promoting it lets model
# prose move the decision. Observed with a live provider: on the clean on-label
# sentence "本品适用于成人原发性高血压的治疗，应遵医嘱规律服用。" the model
# volunteered a `missing_context` candidate ("no indication detail or safety
# information"), which promoted to CN-013 (S2) and downgraded `allow` to
# `needs_info`. Nothing was wrong with the sentence, and the server had already
# determined that context was present.
#
# Semantic rules stay promotable on purpose -- an AE, off-label claim, bribery
# hint or comparative claim that no keyword matched is exactly what the model is
# for, and each of those raises risk rather than lowering it.
# One wording, one characterisation. When both rules describe the same sentence,
# the more specific rule wins and the broader/graver one is folded into it.
#
# Observed with a live provider on "同类药中本品安全性最佳。" and "本品明显优于现有
# 标准治疗方案。": the model reported comparative_claim (CN-004, S1, human review)
# *and* unapproved_promotion (CN-017, S0, blocked) for the same clause, which
# escalated an S1 comparison to an S0 block. An unsupported comparison is a
# comparative claim; promoting an unlicensed product is a different act.
_SUBSUMED_BY = {"CN-017": "CN-004"}

_SERVER_DETERMINED_RULE_IDS = frozenset(
    {
        "CN-010",  # evidence_conflict   <- evidence_pack.contradictions
        "CN-011",  # expired_evidence    <- evidence status and dates
        "CN-012",  # missing_evidence    <- evidence_pack.evidence_gap
        "CN-013",  # missing_context     <- content and entity presence
        "CN-014",  # permission_failure  <- authorization result
        "CN-015",  # irreversible_write  <- tool permission outcome
        "CN-016",  # security_issue      <- security scanner findings
        "CN-019",  # ambiguous_entity    <- deterministic entity resolution
        "CN-020",  # claim_discrepancy   <- claimed vs resolved field comparison
        "CN-021",  # unresolved_indication <- ontology lookup outcome
    }
)

_DECISION_RANK = {
    Decision.BLOCKED: 0,
    Decision.REFUSED: 1,
    Decision.HUMAN_REVIEW: 2,
    Decision.NEEDS_INFO: 3,
    Decision.ALLOW: 4,
}
_SEVERITY_RANK = {
    Severity.S0: 0,
    Severity.S1: 1,
    Severity.S2: 2,
    Severity.S3: 3,
}
_HIGH_RISK = frozenset({Severity.S0, Severity.S1})


def _norm_type(value: str) -> str:
    return value.strip().lower().replace("/", "_").replace("-", "_").replace(" ", "_")


class PolicyFinding(Finding):
    """A server-owned finding extended with the auditable rule and roles."""

    rule_id: str = ""
    required_roles: list[Role] = Field(default_factory=list)
    sla_label: str | None = None
    irreversible: bool = False
    spans: list[CharacterSpan] = Field(default_factory=list)
    rule_version: str = ""
    category: str = ""
    allow_save: bool = True
    allow_generate: bool = True
    allow_publish: bool = True
    notification_message: str = ""
    remediation_guidance: str = ""


class PolicyResult(DomainModel):
    decision: Decision
    severity: Severity
    findings: list[PolicyFinding] = Field(default_factory=list)
    policy_version: str
    reasons: list[str] = Field(default_factory=list)
    routing: ReviewPlan | None = None
    evidence_gap: bool = False
    rule_ids: list[str] = Field(default_factory=list)
    case_id: str = ""
    trace_id: str = ""
    content_version: str = ""


class PolicyEngine:
    """Evaluates a bundle against extraction, security, label, and evidence inputs."""

    def __init__(
        self,
        bundle: PolicyBundle,
        label_facts: LabelFacts | None = None,
        raci: RaciMatrix | None = None,
        route_version: str = "routing-v1",
        now: datetime | None = None,
    ) -> None:
        self._bundle = bundle
        self._rules = parse_bundle_rules(bundle)
        self._rule_by_id = {rule.rule_id: rule for rule in self._rules}
        self._alias_map: dict[str, PolicyRule] = {}
        for rule in self._rules:
            for alias in rule.aliases:
                self._alias_map[_norm_type(alias)] = rule
        self._label_facts = label_facts
        self._raci = raci
        self._route_version = route_version
        self._now = now or datetime.now(UTC)

    def _rule(self, rule_id: str) -> PolicyRule:
        return self._rule_by_id[rule_id]

    def _rule_for_type(self, raw_type: str) -> PolicyRule | None:
        return self._alias_map.get(_norm_type(raw_type))

    def _content_text(self, extracted: ExtractedData, evidence_pack: EvidencePack) -> str:
        parts: list[str] = [evidence_pack.query]
        parts.extend(str(value) for value in extracted.extracted_fields.values())
        parts.extend(finding.reason or "" for finding in extracted.findings)
        return "\n".join(part for part in parts if part)

    def _new_finding(
        self,
        rule: PolicyRule,
        evidence_pack: EvidencePack,
        matched: list[str],
        override_decision: Decision | None = None,
        spans: list[CharacterSpan] | None = None,
    ) -> PolicyFinding:
        reason = f"rule {rule.rule_id} ({rule.type}) matched patterns {matched}" if matched else rule.next_action
        finding = PolicyFinding(
            type=rule.type,
            severity=rule.severity,
            decision=override_decision or rule.decision,
            reason=reason,
            required_role=rule.required_roles[0] if rule.required_roles else None,
            required_roles=list(rule.required_roles),
            rule_id=rule.rule_id,
            sla_label=rule.sla_label,
            next_action=rule.next_action,
            irreversible=not rule.reversible,
            matched_terms=list(matched),
            spans=list(spans or []),
            rule_version=rule.version,
            category=rule.category,
            allow_save=rule.allow_save,
            allow_generate=rule.allow_generate,
            allow_publish=rule.allow_publish,
            notification_message=rule.notification_message,
            remediation_guidance=rule.remediation_guidance,
        )
        if rule.requires_evidence and not rule.evidence_gap_acceptable:
            if evidence_pack.supporting:
                finding.evidence_refs = [item.evidence_id for item in evidence_pack.supporting]
        return finding

    @staticmethod
    def _keys_for_rule(findings: dict[str, PolicyFinding], rule_id: str) -> list[str]:
        return [key for key, finding in findings.items() if finding.rule_id == rule_id]

    def _apply_subsumption(self, findings: dict[str, PolicyFinding], reasons: list[str]) -> None:
        """Fold a broader rule into the specific rule that already covers it.

        Only *model-proposed* gravity is subsumed. A rule the server matched
        deterministically stands on its own evidence and is never folded away, so
        this can only ever relax an escalation the model invented.
        """
        for grave_id, specific_id in _SUBSUMED_BY.items():
            specific_keys = self._keys_for_rule(findings, specific_id)
            grave_keys = [
                key for key in self._keys_for_rule(findings, grave_id) if key.startswith("candidate:")
            ]
            if not specific_keys or not grave_keys:
                continue
            target = findings[specific_keys[0]]
            for key in grave_keys:
                self._merge_finding(target, findings.pop(key), keep_existing_disposition=True)
                reasons.append(
                    f"rule {grave_id} subsumed by rule {specific_id} "
                    "(same wording; the more specific rule is authoritative)"
                )

    def _constrain_uncorroborated_blocks(
        self, findings: dict[str, PolicyFinding], reasons: list[str]
    ) -> None:
        """Model prose alone must not produce the gravest blocking outcome.

        ``CN-017`` carries no patterns, so it can only ever come from a model
        candidate -- yet it is S0 and ``blocked``. That let the model set the most
        severe decision in the system by itself, which is precisely what
        "the model proposes, the server decides" is supposed to prevent. Observed
        on a prompt-injection case that promotes nothing at all.

        The finding is **kept** so nothing is hidden and no case can become an
        ``allow``: only its decision is relaxed to human review, so a person makes
        the blocking call. Severity is untouched, so SLA and routing still treat it
        as grave. A candidate corroborated by a deterministic signal for the same
        rule keeps its blocking decision.
        """
        for key, finding in findings.items():
            if not key.startswith("candidate:"):
                continue
            if finding.severity is not Severity.S0 or finding.decision is not Decision.BLOCKED:
                continue
            corroborating = [
                other for other in self._keys_for_rule(findings, finding.rule_id) if other != key
            ]
            if corroborating:
                continue
            finding.decision = Decision.HUMAN_REVIEW
            if "deterministic_corroboration" not in finding.missing_information:
                finding.missing_information.append("deterministic_corroboration")
            reasons.append(
                f"rule {finding.rule_id} kept at S0 but routed to human review: "
                "model candidate alone cannot block"
            )

    @staticmethod
    def _merge_finding(
        existing: PolicyFinding,
        incoming: PolicyFinding,
        *,
        keep_existing_disposition: bool = False,
    ) -> None:
        """Fold a duplicate finding for the same rule into the one already held.

        A real model often reports the same rule twice for one sentence -- an
        off-label indication *and* an off-label dose, for example -- and the
        deterministic label comparison may independently raise the same rule. Each
        of those is the same compliance problem, so showing three copies teaches a
        representative to skim past findings instead of reading them.

        Merging is additive and never loses information: reasons are joined, and
        evidence references and missing-information entries are unioned. Severity
        keeps the graver of the two so a merge can never soften a case.
        """
        if incoming.reason and incoming.reason not in (existing.reason or ""):
            existing.reason = f"{existing.reason}; {incoming.reason}" if existing.reason else incoming.reason

        for ref in incoming.evidence_refs:
            if ref not in existing.evidence_refs:
                existing.evidence_refs.append(ref)

        for item in incoming.missing_information:
            if item not in existing.missing_information:
                existing.missing_information.append(item)

        for span in incoming.spans:
            if span not in existing.spans:
                existing.spans.append(span)

        if incoming.confidence is not None:
            existing.confidence = (
                incoming.confidence
                if existing.confidence is None
                else max(existing.confidence, incoming.confidence)
            )

        # Two different merge semantics, deliberately separated:
        #
        # * duplicates of the *same* rule take the graver severity/decision, so
        #   repeated reporting can never dilute a finding;
        # * subsumption (``keep_existing_disposition``) keeps the surviving
        #   specific rule's own severity and decision, because the point is that
        #   the specific rule is the correct characterisation of the wording. The
        #   subsumed rule's reasoning is still absorbed above, so nothing is lost.
        if keep_existing_disposition:
            return
        if _SEVERITY_RANK[incoming.severity] < _SEVERITY_RANK[existing.severity]:
            existing.severity = incoming.severity
        if _DECISION_RANK[incoming.decision] < _DECISION_RANK[existing.decision]:
            existing.decision = incoming.decision

        existing.evidence_gap = existing.evidence_gap or incoming.evidence_gap

    def _apply_evidence_invariant(self, finding: PolicyFinding) -> None:
        """Every evidence-requiring finding carries refs or an explicit gap.

        The invariant only adds a gap when refs are absent; an explicit
        caller-set ``evidence_gap`` is preserved even when refs also exist.
        """
        rule = self._rule_by_id.get(finding.rule_id)
        if rule is None or not rule.requires_evidence or rule.evidence_gap_acceptable:
            return
        if finding.evidence_refs:
            return
        finding.evidence_gap = True
        if "evidence" not in finding.missing_information:
            finding.missing_information.append("evidence")

    @staticmethod
    def _is_expired(item: Evidence, now: datetime) -> bool:
        if item.status in {EvidenceStatus.EXPIRED, EvidenceStatus.WITHDRAWN}:
            return True
        return item.effective_to is not None and item.effective_to < now

    @staticmethod
    def _has_label_fields(fields: dict[str, Any]) -> bool:
        return any(field in fields for field in _COMPARED_FIELDS)

    @staticmethod
    def _scope_matches(
        rule: PolicyRule,
        context: CaseContext,
        entrypoint: Entrypoint,
    ) -> bool:
        scope = rule.scope
        content_type = context.content_type or normalize_content_type(context.channel)

        def matches(value: str | None, allowed: list[str]) -> bool:
            return not allowed or (value is not None and value.casefold() in {item.casefold() for item in allowed})

        return (
            matches(context.tenant_id, scope.tenant_ids)
            and matches(context.market, scope.markets)
            and matches(context.language, scope.languages)
            and matches(context.product_id, scope.product_ids)
            and matches(context.therapeutic_area, scope.therapeutic_areas)
            and (
                not scope.content_types
                or (content_type is not None and content_type in scope.content_types)
            )
            and (not scope.entrypoints or entrypoint in scope.entrypoints)
        )

    def _scan_content(
        self,
        text: str,
        *,
        context: CaseContext,
        entrypoint: Entrypoint,
        evidence_pack: EvidencePack,
        offset_map: TextOffsetMap | None,
    ) -> tuple[dict[str, PolicyFinding], list[str]]:
        findings: dict[str, PolicyFinding] = {}
        reasons: list[str] = []
        for rule in self._rules:
            if not rule.patterns or not self._scope_matches(rule, context, entrypoint):
                continue
            safe_spans = find_spans(text, rule.patterns)
            if not safe_spans:
                continue
            original_spans: list[CharacterSpan] = []
            for span in safe_spans:
                mapped = (
                    offset_map.to_original(span.start, span.end)
                    if offset_map is not None
                    else span
                )
                if mapped is not None and mapped not in original_spans:
                    original_spans.append(mapped)
            matched = list(dict.fromkeys(text[span.start : span.end] for span in safe_spans))
            finding = self._new_finding(
                rule,
                evidence_pack,
                matched,
                spans=original_spans,
            )
            if rule.requires_span and not original_spans:
                finding.decision = Decision.HUMAN_REVIEW
            findings[rule.rule_id] = finding
            reasons.append(f"rule {rule.rule_id} ({rule.type}) matched pattern {matched[0]!r}")
        return findings, reasons

    def evaluate_text(
        self,
        text: str,
        *,
        context: CaseContext,
        entrypoint: Entrypoint,
        offset_map: TextOffsetMap | None = None,
        evidence_gap: bool = True,
    ) -> PolicyResult:
        """Evaluate scoped patterns against one text version with real spans."""
        if not context.case_id or not context.trace_id:
            raise ValueError("context must carry non-empty case_id and trace_id for auditability")
        pack = EvidencePack(
            snapshot_id="text-only",
            query=text,
            evidence_gap=evidence_gap,
        )
        findings, reasons = self._scan_content(
            text,
            context=context,
            entrypoint=entrypoint,
            evidence_pack=pack,
            offset_map=offset_map,
        )
        finding_list = list(findings.values())
        aggregated = calculate_severity(finding_list)
        content_version = context.content_version or _content_version(text)
        result = PolicyResult(
            decision=self._aggregate_decision(
                finding_list,
                pack,
                require_evidence=evidence_gap,
            ),
            severity=aggregated.severity,
            findings=finding_list,
            policy_version=self._bundle.policy_version,
            reasons=reasons,
            routing=None,
            evidence_gap=evidence_gap,
            rule_ids=[finding.rule_id for finding in finding_list],
            case_id=context.case_id,
            trace_id=context.trace_id,
            content_version=content_version,
        )
        result.routing = route_review(result, self._raci, self._route_version)
        return result

    def evaluate(
        self,
        context: CaseContext,
        extracted: ExtractedData,
        security_findings: list[SecurityFinding],
        evidence_pack: EvidencePack,
        entity_resolution: dict[str, Any] | None = None,
        entrypoint: Entrypoint = Entrypoint.CONTENT,
        offset_map: TextOffsetMap | None = None,
    ) -> PolicyResult:
        """Evaluate the bundle and produce the server-controlled result."""
        if not context.case_id or not context.trace_id:
            raise ValueError("context must carry non-empty case_id and trace_id for auditability")

        content = evidence_pack.query
        findings, reasons = self._scan_content(
            content,
            context=context,
            entrypoint=entrypoint,
            evidence_pack=evidence_pack,
            offset_map=offset_map,
        )

        for candidate in extracted.findings:
            rule = self._rule_for_type(candidate.type)
            if rule is None or rule.rule_id in findings:
                continue
            if rule.rule_id in _SERVER_DETERMINED_RULE_IDS:
                # Keep the model's observation in the audit trail, but never let
                # it create the finding: this condition is the server's to decide.
                reasons.append(
                    f"candidate {candidate.type!r} not promoted: rule {rule.rule_id} is server-determined"
                )
                continue
            finding = self._new_finding(rule, evidence_pack, [])
            finding.confidence = candidate.confidence
            if candidate.reason:
                finding.reason = candidate.reason
            if candidate.evidence_refs:
                finding.evidence_refs = list(candidate.evidence_refs)
            if candidate.missing_information:
                finding.missing_information = list(candidate.missing_information)
            key = f"candidate:{rule.rule_id}"
            existing = findings.get(key)
            if existing is not None:
                # Same rule reported twice for one submission; see _merge_finding.
                self._merge_finding(existing, finding)
                reasons.append(f"candidate {candidate.finding_id} merged into rule {rule.rule_id}")
            else:
                findings[key] = finding
                reasons.append(f"candidate {candidate.finding_id} promoted to rule {rule.rule_id}")

        for security_finding in security_findings:
            rule = self._rule_for_type(security_finding.type) or self._rule("CN-016")
            decision = (
                Decision.BLOCKED
                if security_finding.blocked or security_finding.action is SecurityAction.BLOCK
                else Decision.HUMAN_REVIEW
            )
            finding = self._new_finding(rule, evidence_pack, [security_finding.reason or security_finding.type], decision)
            finding.severity = min(
                (rule.severity, security_finding.severity),
                key=lambda severity: _SEVERITY_RANK[severity],
            )
            if security_finding.evidence_refs:
                finding.evidence_refs = list(security_finding.evidence_refs)
            if security_finding.missing_information:
                finding.missing_information = list(security_finding.missing_information)
            if security_finding.evidence_gap:
                finding.evidence_gap = True
            findings[f"security:{security_finding.finding_id}"] = finding
            reasons.append(f"security finding {security_finding.finding_id} routed to rule {rule.rule_id}")

        # Judgment reads server-derived facts. Client declarations live in
        # `claimed_fields` and are cross-checked below, never compared to the
        # label as if they were observations (defect P-1).
        decision_fields = extracted.decision_fields
        if self._label_facts is not None and self._has_label_fields(decision_fields):
            comparison = compare_label_fields(decision_fields, self._label_facts)
            if comparison.mismatches:
                rule = self._rule("CN-009")
                finding = self._new_finding(rule, evidence_pack, [])
                finding.reason = f"label field mismatch: {', '.join(comparison.mismatches)}"
                finding.missing_information = [f"label_field:{field}" for field in comparison.mismatches]
                existing = findings.get(f"candidate:{rule.rule_id}") or findings.get(rule.rule_id)
                if existing is not None:
                    # The deterministic comparison is authoritative, so its reason
                    # is folded in rather than being shown as a separate finding.
                    self._merge_finding(existing, finding)
                else:
                    findings[f"label:{rule.rule_id}"] = finding
                reasons.append(
                    f"rule {rule.rule_id} (off_label) mismatch on {','.join(comparison.mismatches)}"
                )

        if evidence_pack.evidence_gap or not evidence_pack.items:
            rule = self._rule("CN-012")
            finding = self._new_finding(rule, evidence_pack, [])
            finding.evidence_gap = True
            if "evidence" not in finding.missing_information:
                finding.missing_information.append("evidence")
            findings[f"evidence:{rule.rule_id}"] = finding
            reasons.append("rule CN-012 (missing_evidence) evidence gap present")

        expired_ids = [item.evidence_id for item in evidence_pack.items if self._is_expired(item, self._now)]
        if expired_ids:
            rule = self._rule("CN-011")
            finding = self._new_finding(rule, evidence_pack, [])
            finding.evidence_refs = expired_ids
            if "current_evidence" not in finding.missing_information:
                finding.missing_information.append("current_evidence")
            findings[f"evidence:{rule.rule_id}"] = finding
            reasons.append(f"rule CN-011 (expired_evidence) refs {expired_ids}")

        if evidence_pack.contradictions:
            rule = self._rule("CN-010")
            finding = self._new_finding(rule, evidence_pack, [])
            finding.evidence_refs = [item.evidence_id for item in evidence_pack.contradictions]
            findings[f"evidence:{rule.rule_id}"] = finding
            reasons.append(f"rule CN-010 (evidence_conflict) refs {finding.evidence_refs}")

        if extracted.field_discrepancies:
            # The client declared one thing and the narrative says another. That
            # gap used to be a bypass; recording it turns it into a detection.
            rule = self._rule("CN-020")
            finding = self._new_finding(rule, evidence_pack, [])
            finding.reason = (
                "declared fields disagree with the narrative on: "
                + ", ".join(extracted.field_discrepancies)
            )
            finding.missing_information = [
                f"claim_conflict:{field}" for field in extracted.field_discrepancies
            ]
            findings[f"claim:{rule.rule_id}"] = finding
            reasons.append(
                f"rule CN-020 (claim_discrepancy) fields {','.join(extracted.field_discrepancies)}"
            )

        if entity_resolution and entity_resolution.get("ambiguous"):
            # Two people share a surname in one narrative. Merging them would
            # attribute one clinician's opinion to another, so the server asks
            # the author to disambiguate rather than picking a reading.
            rule = self._rule("CN-019")
            finding = self._new_finding(rule, evidence_pack, [])
            finding.missing_information = ["entity_identity"]
            ambiguous_clusters = [
                cluster
                for cluster in entity_resolution.get("clusters", [])
                if cluster.get("ambiguous")
            ]
            findings[f"resolution:{rule.rule_id}"] = finding
            reasons.append(
                f"rule CN-019 (ambiguous_entity) {len(ambiguous_clusters)} unresolved person cluster(s)"
            )

        missing_context_info: list[str] = []
        if not content.strip():
            missing_context_info.append("content")
        if not extracted.entities:
            missing_context_info.append("entities")
        if missing_context_info:
            rule = self._rule("CN-013")
            finding = self._new_finding(rule, evidence_pack, [])
            finding.missing_information = missing_context_info
            findings[f"context:{rule.rule_id}"] = finding
            reasons.append(f"rule CN-013 (missing_context) missing {','.join(missing_context_info)}")

        for finding in findings.values():
            if finding.type == "comparative_claim" and not evidence_pack.supporting:
                if "comparison_context" not in finding.missing_information:
                    finding.missing_information.append("comparison_context")
                if not evidence_pack.items and not finding.evidence_gap:
                    finding.evidence_gap = True

        self._apply_subsumption(findings, reasons)
        self._constrain_uncorroborated_blocks(findings, reasons)

        finding_list = list(findings.values())
        for finding in finding_list:
            self._apply_evidence_invariant(finding)
        aggregated = calculate_severity(finding_list)
        decision = self._aggregate_decision(finding_list, evidence_pack)

        result = PolicyResult(
            decision=decision,
            severity=aggregated.severity,
            findings=finding_list,
            policy_version=self._bundle.policy_version,
            reasons=reasons,
            routing=None,
            evidence_gap=evidence_pack.evidence_gap or not evidence_pack.items,
            rule_ids=[finding.rule_id for finding in finding_list],
            case_id=context.case_id,
            trace_id=context.trace_id,
            content_version=context.content_version or _content_version(content),
        )
        result.routing = route_review(result, self._raci, self._route_version)
        return result

    def _aggregate_decision(
        self,
        findings: list[PolicyFinding],
        evidence_pack: EvidencePack,
        *,
        require_evidence: bool = True,
    ) -> Decision:
        evidence_missing = evidence_pack.evidence_gap or (
            require_evidence and not evidence_pack.items
        )
        if not findings:
            if evidence_missing:
                return Decision.NEEDS_INFO
            return Decision.ALLOW
        top = min((finding.decision for finding in findings), key=lambda decision: _DECISION_RANK[decision])
        if top is Decision.ALLOW:
            if evidence_missing:
                top = Decision.NEEDS_INFO
            elif any(finding.severity in _HIGH_RISK for finding in findings):
                top = Decision.HUMAN_REVIEW
        return top


def _content_version(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


__all__ = ["PolicyEngine", "PolicyFinding", "PolicyResult"]
