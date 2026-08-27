"""Pharmacovigilance signal detection over candidate extraction.

A deterministic helper that surfaces potential adverse-event candidates from
sanitized structured fields and evidence-pack text. It never invents evidence:
signals reference only evidence IDs that exist in the supplied pack.
"""

from __future__ import annotations

from typing import Any

from compliance_guard.domain.models import CandidateFinding, ExtractedData
from compliance_guard.knowledge.evidence_pack import EvidencePack

_AE_PATTERNS = (
    "皮疹",
    "恶心",
    "呕吐",
    "腹泻",
    "头晕",
    "头痛",
    "瘙痒",
    "不良反应",
    "副作用",
    "停药",
    "嗜睡",
    "心悸",
    "失眠",
)

_SAE_PATTERNS = (
    "死亡",
    "昏迷",
    "休克",
    "危及生命",
    "严重住院",
    "致残",
    "先天畸形",
)


def _evidence_ids(evidence_pack: EvidencePack) -> list[str]:
    if evidence_pack.supporting:
        return [item.evidence_id for item in evidence_pack.supporting]
    return [item.evidence_id for item in evidence_pack.items]


def _candidate_text(extracted: ExtractedData) -> str:
    parts = [
        str(value) for value in extracted.extracted_fields.values()
    ]
    parts.extend(entity.token or "" for entity in extracted.entities)
    parts.extend(finding.reason or "" for finding in extracted.findings)
    return "\n".join(part for part in parts if part)


def detect_pv_signals(
    extracted: ExtractedData,
    evidence_pack: EvidencePack,
) -> list[CandidateFinding]:
    """Return potential AE/SAE candidate signals referencing only existing evidence."""
    haystack = _candidate_text(extracted).casefold()
    evidence_ids = _evidence_ids(evidence_pack)
    signals: list[CandidateFinding] = []
    seen: set[str] = set()

    for pattern in (*_AE_PATTERNS, *_SAE_PATTERNS):
        if pattern.casefold() not in haystack:
            continue
        if pattern in seen:
            continue
        seen.add(pattern)
        is_sae = pattern in _SAE_PATTERNS
        signals.append(
            CandidateFinding(
                type="sae" if is_sae else "ae",
                confidence=0.8 if is_sae else 0.7,
                reason=f"possible {'serious adverse event' if is_sae else 'adverse event'} signal: {pattern}",
                evidence_refs=list(evidence_ids),
                missing_information=[] if evidence_ids else ["evidence"],
            )
        )
    return signals


__all__ = ["detect_pv_signals"]
