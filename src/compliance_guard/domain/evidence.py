"""Evidence and knowledge contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import AliasChoices, Field, field_validator, model_validator

from .base import DomainModel, _utc, _validate_char_span
from .enums import EvidenceStatus


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
