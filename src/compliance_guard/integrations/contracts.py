"""Vendor-neutral connector models and protocol."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, field_validator

from compliance_guard.domain.enums import ContentType, DataClass, Decision
from compliance_guard.domain.models import DomainModel


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class ContentEnvelope(DomainModel):
    """Authoritative text read from a content source."""

    record_id: str = Field(min_length=1, strict=True)
    version: str = Field(min_length=1, strict=True)
    text: str
    content_type: ContentType
    title: str = ""
    tenant_id: str = ""
    market: str = ""
    product_id: str = ""
    updated_at: datetime | None = None

    _normalize_updated_at = field_validator("updated_at")(_utc)


class SafetyCandidate(DomainModel):
    """A safety signal held locally until intake accepts it."""

    record_id: str = Field(min_length=1, strict=True)
    version: str = Field(min_length=1, strict=True)
    text: str = Field(min_length=1)
    content_type: ContentType = ContentType.OTHER
    tenant_id: str = ""
    market: str = ""
    product_id: str = ""


class SafetyReceipt(DomainModel):
    receipt_id: str
    record_id: str
    version: str
    idempotency_key: str
    status: Literal["accepted"] = "accepted"
    accepted_at: datetime

    _normalize_accepted_at = field_validator("accepted_at")(_utc)


class ReviewExportRequest(DomainModel):
    case_id: str = Field(min_length=1, strict=True)
    record_id: str = Field(min_length=1, strict=True)
    version: str = Field(min_length=1, strict=True)
    decision: Decision
    rule_ids: list[str] = Field(default_factory=list)
    actor_id: str = ""


class ExportReceipt(DomainModel):
    export_id: str
    case_id: str
    idempotency_key: str
    status: Literal["exported"] = "exported"
    exported_at: datetime

    _normalize_exported_at = field_validator("exported_at")(_utc)


class ConnectorInfo(DomainModel):
    """Descriptor used by API clients and operators to inspect a connector."""

    connector_id: str = Field(min_length=1, strict=True)
    connector_kind: Literal["content_source", "safety_intake", "review_export"]
    label: str = Field(min_length=1, strict=True)
    description: str = ""
    capabilities: list[str] = Field(default_factory=list)
    data_classes: list[DataClass] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    enabled: bool = True
    mode: Literal["mock"] = "mock"


class HealthStatus(DomainModel):
    connector_id: str = Field(min_length=1, strict=True)
    status: Literal["healthy", "degraded", "disabled"]
    detail: str = ""
    checked_at: datetime

    _normalize_checked_at = field_validator("checked_at")(_utc)


@runtime_checkable
class ConnectorContract(Protocol):
    """Minimum surface every connector exposes to the registry."""

    @property
    def info(self) -> ConnectorInfo: ...

    def health(self) -> HealthStatus: ...


__all__ = [
    "ConnectorContract",
    "ConnectorInfo",
    "ContentEnvelope",
    "ExportReceipt",
    "HealthStatus",
    "ReviewExportRequest",
    "SafetyCandidate",
    "SafetyReceipt",
]
