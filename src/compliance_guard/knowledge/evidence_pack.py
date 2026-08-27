"""EvidencePack: supporting evidence, contradictions, gaps, and a snapshot ID."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from compliance_guard.domain.models import DomainModel, Evidence


class EvidenceGap(DomainModel):
    topic: str = ""
    reason: str = ""


class RetrievalStage(DomainModel):
    """One observable stage of the retrieval (RAG) pipeline.

    Recorded so the UI can show how evidence was actually selected -- query
    construction, metadata filtering, chunk scoring, stance split -- rather
    than asserting that retrieval happened.
    """

    stage: str
    detail: str = ""
    candidates_in: int = 0
    candidates_out: int = 0


class RetrievalChunk(DomainModel):
    """A scored chunk considered during retrieval, kept for explainability."""

    evidence_id: str
    source_id: str = ""
    location: str = ""
    score: int = 0
    matched_tokens: list[str] = Field(default_factory=list)
    stance: str = "support"
    selected: bool = False
    excluded_reason: str = ""


class EvidencePack(DomainModel):
    snapshot_id: str
    query: str
    filters_applied: dict[str, Any] = Field(default_factory=dict)
    items: list[Evidence] = Field(default_factory=list)
    supporting: list[Evidence] = Field(default_factory=list)
    contradictions: list[Evidence] = Field(default_factory=list)
    gaps: list[EvidenceGap] = Field(default_factory=list)
    evidence_gap: bool = True
    # Retrieval explainability. Defaulted so existing constructions stay valid.
    query_tokens: list[str] = Field(default_factory=list)
    stages: list[RetrievalStage] = Field(default_factory=list)
    chunks: list[RetrievalChunk] = Field(default_factory=list)
