"""Metadata-first filtered, lexical retrieval producing an EvidencePack."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from compliance_guard.domain.enums import EvidenceStatus
from compliance_guard.domain.models import Evidence, KnowledgeFilter
from compliance_guard.runtime_paths import fixtures_dir as _bundled_fixtures_dir

from .chunking import chunk_text
from .evidence_pack import EvidenceGap, EvidencePack, RetrievalChunk, RetrievalStage
from .ingestion import _RELEASE_SOURCE_TYPES

_ASCII_RE = re.compile(r"[a-z0-9]+")
_CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def _fixtures_dir() -> Path:
    # Read-only resource: ships inside the bundle when frozen.
    return _bundled_fixtures_dir()


def _query_tokens(query: str) -> set[str]:
    tokens: set[str] = set()
    lowered = query.lower()
    tokens.update(_ASCII_RE.findall(lowered))
    cjk = _CJK_RE.findall(query)
    if len(cjk) >= 2:
        tokens.update("".join(cjk[i : i + 2]) for i in range(len(cjk) - 1))
    return tokens


def _is_release_evidence(evidence: Evidence) -> bool:
    """Release evidence must match ingestion semantics: active, approved source type,
    declared access scope, and a content hash. External or unsigned content is non-release."""
    return (
        evidence.status is EvidenceStatus.ACTIVE
        and evidence.source_type in _RELEASE_SOURCE_TYPES
        and bool(evidence.access_scope)
        and bool(evidence.hash)
    )


class EvidenceRetriever:
    """Filtered lexical retriever over the single-product China fixtures."""

    def __init__(self, fixtures_path: str | Path | None = None) -> None:
        path = Path(fixtures_path) if fixtures_path else _fixtures_dir() / "evidence.json"
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        self._units: list[tuple[Evidence, list[tuple[str, str]]]] = []
        for item in raw["items"]:
            evidence = Evidence.model_validate(item["evidence"])
            chunks = chunk_text(item["content"])
            self._units.append((evidence, chunks))

    def _passes_filters(self, evidence: Evidence, filters: KnowledgeFilter, as_of: datetime) -> bool:
        if evidence.tenant_id != filters.tenant_id:
            return False
        if evidence.market != filters.market:
            return False
        if evidence.product_id != filters.product_id:
            return False
        if evidence.language != filters.language:
            return False
        allowed = set(filters.statuses) if filters.statuses else {"active"}
        if evidence.status.value not in allowed:
            return False
        if evidence.effective_from is not None and evidence.effective_from > as_of:
            return False
        if evidence.effective_to is not None and as_of > evidence.effective_to:
            return False
        if not evidence.access_scope:
            return False
        if filters.access_scope and not (set(evidence.access_scope) & set(filters.access_scope)):
            return False
        return True

    def search_evidence(self, query: str, filters: KnowledgeFilter) -> EvidencePack:
        as_of = filters.as_of or datetime.now(UTC)
        tokens = _query_tokens(query)

        # Retrieval (RAG) explainability: each stage records how the candidate
        # set narrowed, so a reviewer can audit why evidence was or was not used.
        stages: list[RetrievalStage] = []
        chunk_records: list[RetrievalChunk] = []
        total_units = len(self._units)
        stages.append(
            RetrievalStage(
                stage="query_build",
                detail=(
                    "tokenized the tokenized (PII-safe) narrative into "
                    f"{len(tokens)} lexical keys; CJK uses 2-gram keys"
                ),
                candidates_in=total_units,
                candidates_out=total_units,
            )
        )

        filtered: list[tuple[Evidence, list[tuple[str, str]]]] = []
        for evidence, chunks in self._units:
            if self._passes_filters(evidence, filters, as_of):
                filtered.append((evidence, chunks))
            else:
                chunk_records.append(
                    RetrievalChunk(
                        evidence_id=evidence.evidence_id,
                        source_id=evidence.source_id,
                        stance=str(evidence.metadata.get("stance", "support")),
                        selected=False,
                        excluded_reason="metadata_filter",
                    )
                )
        stages.append(
            RetrievalStage(
                stage="metadata_filter",
                detail=(
                    "applied tenant / market / product / language / status / "
                    "effective-window / access-scope filters before any scoring"
                ),
                candidates_in=total_units,
                candidates_out=len(filtered),
            )
        )

        supporting: list[Evidence] = []
        contradictions: list[Evidence] = []
        scored_count = 0
        for evidence, chunks in filtered:
            score = 0
            best_location = ""
            best_matches: list[str] = []
            for _, chunk_text_value in chunks:
                lowered = chunk_text_value.lower()
                matches = [token for token in tokens if token in lowered]
                if len(matches) > score:
                    score = len(matches)
                    best_matches = matches
            for location, chunk_text_value in chunks:
                lowered = chunk_text_value.lower()
                if len([token for token in tokens if token in lowered]) == score and score > 0:
                    best_location = location
                    break
            stance = str(evidence.metadata.get("stance", "support"))
            if score <= 0:
                chunk_records.append(
                    RetrievalChunk(
                        evidence_id=evidence.evidence_id,
                        source_id=evidence.source_id,
                        stance=stance,
                        selected=False,
                        excluded_reason="no_lexical_match",
                    )
                )
                continue
            scored_count += 1
            is_release = _is_release_evidence(evidence)
            chunk_records.append(
                RetrievalChunk(
                    evidence_id=evidence.evidence_id,
                    source_id=evidence.source_id,
                    location=best_location,
                    score=score,
                    matched_tokens=sorted(best_matches)[:8],
                    stance=stance,
                    selected=(stance == "contradict") or is_release,
                    excluded_reason="" if (stance == "contradict" or is_release) else "non_release_source",
                )
            )
            if stance == "contradict":
                contradictions.append(evidence)
            elif is_release:
                supporting.append(evidence)
            # Non-release support items (external or unsigned) are excluded from
            # the release EvidencePack; they never become supporting evidence.

        stages.append(
            RetrievalStage(
                stage="lexical_score",
                detail="scored chunks by lexical key overlap; zero-overlap items dropped",
                candidates_in=len(filtered),
                candidates_out=scored_count,
            )
        )
        stages.append(
            RetrievalStage(
                stage="stance_split",
                detail=(
                    "split into supporting release evidence and retained "
                    "contradictions; non-release sources cannot support a release"
                ),
                candidates_in=scored_count,
                candidates_out=len(supporting) + len(contradictions),
            )
        )

        items = supporting + contradictions
        gaps: list[EvidenceGap] = []
        if not supporting:
            gaps.append(
                EvidenceGap(
                    topic=query,
                    reason="no supporting release evidence matched within the applied filters",
                )
            )
        if contradictions:
            conflict_ids = ", ".join(item.evidence_id for item in contradictions)
            gaps.append(
                EvidenceGap(
                    topic=query,
                    reason=f"conflicting evidence retained: {conflict_ids}",
                )
            )

        snapshot_material = (
            query
            + "|"
            + json.dumps(filters.model_dump(mode="json"), sort_keys=True)
        )
        snapshot_id = "snap-" + hashlib.sha256(snapshot_material.encode("utf-8")).hexdigest()[:16]

        return EvidencePack(
            snapshot_id=snapshot_id,
            query=query,
            filters_applied=filters.model_dump(mode="json"),
            items=items,
            supporting=supporting,
            contradictions=contradictions,
            gaps=gaps,
            evidence_gap=(not supporting) or bool(contradictions),
            query_tokens=sorted(tokens)[:24],
            stages=stages,
            chunks=chunk_records,
        )


_DEFAULT_RETRIEVER: EvidenceRetriever | None = None


def search_evidence(query: str, filters: KnowledgeFilter) -> EvidencePack:
    global _DEFAULT_RETRIEVER
    if _DEFAULT_RETRIEVER is None:
        _DEFAULT_RETRIEVER = EvidenceRetriever()
    return _DEFAULT_RETRIEVER.search_evidence(query, filters)
