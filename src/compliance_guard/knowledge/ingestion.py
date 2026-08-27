"""Validate metadata and ingest text into a versioned KnowledgeDocument."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any
from uuid import uuid4

from compliance_guard.domain.enums import EvidenceStatus
from compliance_guard.domain.models import KnowledgeChunk, KnowledgeDocument

from .chunking import chunk_text

_REQUIRED_METADATA = frozenset(
    {
        "source_id",
        "version",
        "market",
        "product_id",
        "language",
        "status",
    }
)

_RELEASE_SOURCE_TYPES = frozenset({"label", "signed"})


def _normalize_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def ingest_document(source: str, metadata: dict[str, Any]) -> KnowledgeDocument:
    """Validate metadata, checksum the source, and chunk it.

    External or unsigned content is marked as non-release evidence.
    """
    if not source or not source.strip():
        raise ValueError("source text must be non-empty")

    missing = _REQUIRED_METADATA - set(metadata)
    if missing:
        raise ValueError(f"missing required metadata keys: {sorted(missing)}")

    try:
        status = EvidenceStatus(metadata["status"])
    except ValueError:
        raise ValueError(f"invalid status: {metadata['status']!r}") from None

    source_id = str(metadata["source_id"])
    version = str(metadata["version"])
    market = str(metadata["market"])
    product_id = str(metadata["product_id"])
    language = str(metadata["language"])
    tenant_id = str(metadata["tenant_id"]) if metadata.get("tenant_id") else None
    source_type = str(metadata.get("source_type", "unknown"))
    access_scope = list(metadata.get("access_scope", []))
    effective_from = _normalize_datetime(metadata.get("effective_from"))
    effective_to = _normalize_datetime(metadata.get("effective_to"))

    release_evidence = bool(metadata.get("release_evidence", True))
    release_evidence = release_evidence and status is EvidenceStatus.ACTIVE
    release_evidence = release_evidence and source_type in _RELEASE_SOURCE_TYPES
    release_evidence = release_evidence and bool(access_scope)

    checksum = hashlib.sha256(source.encode("utf-8")).hexdigest()

    chunks: list[KnowledgeChunk] = []
    for location, chunk in chunk_text(source):
        chunk_checksum = hashlib.sha256(chunk.encode("utf-8")).hexdigest()
        chunks.append(
            KnowledgeChunk(
                chunk_id=f"chunk-{uuid4().hex}",
                source_id=source_id,
                version=version,
                market=market,
                product_id=product_id,
                language=language,
                tenant_id=tenant_id,
                status=status,
                effective_from=effective_from,
                effective_to=effective_to,
                location=location,
                text=chunk,
                checksum=chunk_checksum,
                access_scope=list(access_scope),
                source_type=source_type,
                release_evidence=release_evidence,
            )
        )

    return KnowledgeDocument(
        document_id=f"doc-{uuid4().hex}",
        source_id=source_id,
        version=version,
        market=market,
        product_id=product_id,
        language=language,
        tenant_id=tenant_id,
        status=status,
        effective_from=effective_from,
        effective_to=effective_to,
        checksum=checksum,
        access_scope=list(access_scope),
        source_type=source_type,
        release_evidence=release_evidence,
        chunks=chunks,
    )