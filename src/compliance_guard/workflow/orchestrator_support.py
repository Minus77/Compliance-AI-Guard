"""Pure helpers for request preparation and result assembly."""

from __future__ import annotations

import hashlib
from typing import Any

from compliance_guard.agents.icsr_assessment import assess_icsr
from compliance_guard.agents.icsr_followup import build_followup_form
from compliance_guard.domain.enums import Severity
from compliance_guard.domain.models import (
    CheckCaseRequest,
    CheckCaseResponse,
    Entity,
    ExtractedData,
    Finding,
    ProductContext,
)
from compliance_guard.knowledge.evidence_pack import EvidencePack
from compliance_guard.knowledge.field_resolver import FieldResolution
from compliance_guard.knowledge.glossary import DEFAULT_LOCALE, default_glossary
from compliance_guard.policy.engine import PolicyResult
from compliance_guard.security.pii_gateway import KnownIdentifier
from compliance_guard.llm.types import RawModelResult

_MAX_EVIDENCE_EXCERPT_CHARS = 600

_RESERVED_FORM_KEYS = frozenset(
    {
        "decision",
        "severity",
        "approval_status",
        "routing",
        "tool_permissions",
    }
)


def digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def data_class(security_findings: list[Any], request: Any | None = None) -> str:
    types = {finding.type.casefold() for finding in security_findings}
    if any("phi" in finding_type for finding_type in types):
        return "phi_tokenized"
    if any("pii" in finding_type for finding_type in types):
        return "pii_tokenized"
    # Attachments are unopened server-side, so assume they may contain personal data.
    for part in getattr(request, "content_parts", None) or []:
        part_type = getattr(part, "type", None)
        value = getattr(part_type, "value", part_type)
        if value in {"image_ref", "audio_ref"}:
            return "pii_tokenized"
    return "internal"


_LABEL_FACT_FIELDS = (
    "product_id",
    "market",
    "version",
    "indication",
    "indication_id",
    "population",
    "line",
    "dose",
    "route",
    "duration",
    "combination",
)


def label_fact_fields(label_facts: Any) -> dict[str, Any]:
    if label_facts is None:
        return {}
    selected: dict[str, Any] = {}
    for field in _LABEL_FACT_FIELDS:
        value = getattr(label_facts, field, None)
        if value not in (None, ""):
            selected[field] = value
    return selected


def roster(request: Any) -> list[KnownIdentifier]:
    raw = request.extensions.get("known_identifiers") or []
    result: list[KnownIdentifier] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        entity_type = str(item.get("entity_type") or item.get("type") or "").strip()
        canonical_id = str(item.get("canonical_id") or "").strip()
        values = [str(value) for value in (item.get("values") or []) if str(value).strip()]
        if entity_type not in {"patient", "hcp"} or not canonical_id or not values:
            continue
        result.append(
            KnownIdentifier(entity_type=entity_type, canonical_id=canonical_id, values=values)
        )
    return result


def evidence_excerpts(evidence_pack: EvidencePack) -> list[dict[str, Any]]:
    stance_by_id: dict[str, str] = {}
    for item in evidence_pack.supporting:
        stance_by_id[item.evidence_id] = "supports"
    for item in evidence_pack.contradictions:
        stance_by_id[item.evidence_id] = "contradicts"

    excerpts: list[dict[str, Any]] = []
    for item in evidence_pack.items:
        quote = (item.quote or "").strip()
        if not quote:
            continue
        excerpts.append(
            {
                "evidence_id": item.evidence_id,
                "version": item.version,
                "source_type": item.source_type,
                "stance": stance_by_id.get(item.evidence_id, "retrieved"),
                "excerpt": quote[:_MAX_EVIDENCE_EXCERPT_CHARS],
            }
        )
    return excerpts


def overlay_intake(
    extracted: ExtractedData,
    request: Any,
    *,
    field_resolution: FieldResolution | None = None,
) -> ExtractedData:
    # Client claims stay separate; policy decisions read only server-resolved fields.
    form_fields = request.extensions.get("structured_fields") or {}
    claimed_fields = {
        key: value
        for key, value in form_fields.items()
        if key.casefold() not in _RESERVED_FORM_KEYS
    }
    form_entities = [
        Entity(type=str(item.get("type", "entity")), token=str(item.get("token", "")))
        for item in (request.extensions.get("entities") or [])
        if isinstance(item, dict)
    ]
    return ExtractedData(
        entities=list(extracted.entities) + form_entities,
        findings=extracted.findings,
        extracted_fields=dict(extracted.extracted_fields),
        claimed_fields=claimed_fields,
        resolved_fields=dict(field_resolution.resolved_fields) if field_resolution else {},
        field_discrepancies=list(field_resolution.discrepancies) if field_resolution else [],
        evidence_refs=list(extracted.evidence_refs),
        missing_information=list(extracted.missing_information),
        confidence=extracted.confidence,
    )


def map_finding(finding: Any) -> Finding:
    return Finding(
        finding_id=finding.finding_id,
        type=finding.type,
        severity=finding.severity,
        decision=finding.decision,
        confidence=finding.confidence,
        reason=finding.reason,
        evidence_refs=list(finding.evidence_refs),
        missing_information=list(finding.missing_information),
        required_role=finding.required_role,
        next_action=finding.next_action,
        evidence_gap=finding.evidence_gap,
        rule_id=getattr(finding, "rule_id", None) or None,
        matched_terms=list(getattr(finding, "matched_terms", []) or []),
        sla_label=getattr(finding, "sla_label", None),
        required_roles=list(getattr(finding, "required_roles", []) or []),
        spans=list(getattr(finding, "spans", []) or []),
        rule_version=getattr(finding, "rule_version", ""),
        category=getattr(finding, "category", ""),
        allow_save=getattr(finding, "allow_save", True),
        allow_generate=getattr(finding, "allow_generate", True),
        allow_publish=getattr(finding, "allow_publish", True),
        notification_message=getattr(finding, "notification_message", ""),
        remediation_guidance=getattr(finding, "remediation_guidance", ""),
    )


def normalize_finding_gaps(findings: list[Finding]) -> list[Finding]:
    high_risk = {Severity.S0, Severity.S1}
    for finding in findings:
        if finding.severity in high_risk and not finding.evidence_refs:
            has_gap = finding.evidence_gap or "evidence_gap" in (
                item.lower() for item in finding.missing_information
            )
            if not has_gap:
                finding.evidence_gap = True
                if "evidence_gap" not in finding.missing_information:
                    finding.missing_information.append("evidence_gap")
    return findings


def guidance_payload(
    request: Any,
    policy_result: PolicyResult,
    findings: list[Finding],
    *,
    rewrite: Any | None = None,
    rewrite_service: Any = None,
) -> dict[str, Any]:
    locale = DEFAULT_LOCALE
    if str(request.language or "").casefold().startswith("en"):
        locale = "en"
    glossary = default_glossary()

    decision_card = glossary.explain_decision(policy_result.decision.value, locale)
    cards: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.type in seen:
            continue
        seen.add(finding.type)
        card = glossary.explain_finding(finding.type, locale, rule_id=finding.rule_id)
        payload = card.model_dump(mode="json")
        payload["type"] = finding.type
        payload["severity_label"] = glossary.explain_severity(
            finding.severity.value, locale
        )["label"]
        cards.append(payload)

    if rewrite is None:
        rewrite = rewrite_service.suggest(
            request.content, finding_types=[finding.type for finding in findings]
        )

    routing = policy_result.routing
    review_roles = (
        [role.value for role in getattr(routing, "required_roles", [])] if routing else []
    )
    return {
        "rewrite": rewrite.model_dump(mode="json"),
        "locale": locale,
        "glossary_version": glossary.version,
        "decision_label": decision_card.label,
        "decision_plain": decision_card.plain,
        "next_step": decision_card.next_step,
        "findings": cards,
        "review_roles": review_roles,
        "sla_label": getattr(routing, "sla_label", None) if routing else None,
        "technical": {
            "decision": policy_result.decision.value,
            "severity": policy_result.severity.value,
            "policy_version": policy_result.policy_version,
            "rule_ids": [f.rule_id for f in findings if f.rule_id],
            "finding_types": [f.type for f in findings],
        },
    }


def icsr_payload(
    request: Any,
    evidence_pack: EvidencePack,
    candidate: ExtractedData,
    findings: list[Finding],
) -> dict[str, Any]:
    safety_types = {
        "potential_adverse_event",
        "serious_adverse_event",
        "ae",
        "sae",
    }
    has_safety_finding = any(
        str(finding.type).casefold() in safety_types for finding in findings
    )
    patient_entity = any(
        str(getattr(entity, "type", "")).casefold() == "patient"
        for entity in (candidate.entities or [])
    )
    assessment = assess_icsr(
        evidence_pack.query or request.content,
        received_at=request.received_at,
        product_id=request.product_id,
        reporter_known=True,
        patient_entity_present=patient_entity,
    )
    payload = assessment.model_dump(mode="json")
    payload["policy_flagged_safety"] = has_safety_finding
    payload["assessment_conflict"] = bool(
        has_safety_finding and not assessment.is_safety_relevant
    )
    return payload


def followup_payload(icsr: dict[str, Any]) -> dict[str, Any]:
    return build_followup_form(icsr).model_dump(mode="json")


def build_response(
    request: CheckCaseRequest,
    *,
    case_id: str,
    trace_id: str,
    audit_event_id: str,
    state: Any,
    policy_result: PolicyResult,
    evidence_pack: EvidencePack,
    candidate: ExtractedData,
    route: Any,
    security_findings: list[Any],
    label_version: str,
    prompt_version: str,
    raw: RawModelResult | None = None,
    rewrite: Any | None = None,
    rewrite_service: Any = None,
) -> CheckCaseResponse:
    findings = normalize_finding_gaps([map_finding(f) for f in policy_result.findings])
    icsr = icsr_payload(request, evidence_pack, candidate, findings)
    guidance = guidance_payload(
        request,
        policy_result,
        findings,
        rewrite=rewrite,
        rewrite_service=rewrite_service,
    )
    return CheckCaseResponse(
        case_id=case_id,
        decision=policy_result.decision,
        status=state,
        market=request.market,
        language=request.language,
        product=ProductContext(
            product_id=request.product_id,
            label_version=label_version,
        ),
        entities=list(candidate.entities),
        findings=findings,
        evidence=[item.model_copy(deep=True) for item in evidence_pack.items],
        security_findings=[finding.model_copy(deep=True) for finding in security_findings],
        policy_version=policy_result.policy_version,
        knowledge_snapshot_id=evidence_pack.snapshot_id,
        model_profile_id=(
            raw.profile_id
            if raw is not None and raw.profile_id
            else route.primary_profile.profile_id
        ),
        model_version=(
            raw.model_id
            if raw is not None and raw.model_id
            else route.primary_profile.model_id
        ),
        route_version=route.route_version,
        prompt_version=prompt_version,
        trace_id=trace_id,
        audit_event_id=audit_event_id,
        retrieval={
            "query": evidence_pack.query,
            "query_tokens": list(evidence_pack.query_tokens),
            "filters_applied": dict(evidence_pack.filters_applied),
            "snapshot_id": evidence_pack.snapshot_id,
            "stages": [stage.model_dump(mode="json") for stage in evidence_pack.stages],
            "chunks": [chunk.model_dump(mode="json") for chunk in evidence_pack.chunks],
            "gaps": [gap.model_dump(mode="json") for gap in evidence_pack.gaps],
            "supporting_count": len(evidence_pack.supporting),
            "contradiction_count": len(evidence_pack.contradictions),
            "evidence_gap": evidence_pack.evidence_gap,
        },
        icsr=icsr,
        guidance=guidance,
        followup=followup_payload(icsr),
    )
