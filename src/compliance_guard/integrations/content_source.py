"""In-memory authoritative content source connector."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from compliance_guard.domain.enums import ContentType, DataClass

from .contracts import ConnectorInfo, ContentEnvelope, HealthStatus
from .stale_version import StaleVersionError


class ContentSourceError(ValueError):
    """Base failure for content-source reads."""


class ContentNotFoundError(KeyError, ContentSourceError):
    """The requested record does not exist in the source."""


@runtime_checkable
class ContentSource(Protocol):
    def fetch(self, record_id: str, version: str | None = None) -> ContentEnvelope: ...


class InMemoryContentSource:
    """Reference content source that performs no network calls."""

    def __init__(
        self,
        *,
        connector_id: str = "content_source",
        label: str = "Reference content source",
        description: str = "In-memory authoritative content records.",
    ) -> None:
        self._info = ConnectorInfo(
            connector_id=connector_id,
            connector_kind="content_source",
            label=label,
            description=description,
            capabilities=["read", "version_check"],
            data_classes=[
                DataClass.INTERNAL,
                DataClass.CONFIDENTIAL,
                DataClass.PII_TOKENIZED,
                DataClass.PHI_TOKENIZED,
            ],
            allowed_actions=["read"],
        )
        self._records: dict[str, ContentEnvelope] = {}

    @property
    def info(self) -> ConnectorInfo:
        return self._info.model_copy(deep=True)

    def put(self, envelope: ContentEnvelope) -> ContentEnvelope:
        """Store one authoritative record; callers cannot use event payloads."""
        self._records[envelope.record_id] = envelope.model_copy(deep=True)
        return envelope

    def fetch(self, record_id: str, version: str | None = None) -> ContentEnvelope:
        record = self._records.get(record_id)
        if record is None:
            raise ContentNotFoundError(f"unknown content record {record_id!r}")
        if version is not None and version != record.version:
            raise StaleVersionError(record_id, version, record.version)
        return record.model_copy(deep=True)

    def records(self) -> list[dict[str, str]]:
        return [
            {
                "connector_id": self._info.connector_id,
                "record_id": record.record_id,
                "version": record.version,
                "title": record.title,
                "content_type": record.content_type.value,
            }
            for _, record in sorted(self._records.items())
        ]

    def health(self) -> HealthStatus:
        return HealthStatus(
            connector_id=self._info.connector_id,
            status="healthy",
            detail=f"{len(self._records)} authoritative record(s) available",
            checked_at=datetime.now(UTC),
        )


def seed_generic_records(source: InMemoryContentSource) -> None:
    """Load neutral demo records for the reference connector."""
    rows = (
        (
            "CONTENT-0001",
            "3",
            "成人原发性高血压用药说明",
            "本品适用于成人原发性高血压的治疗，应遵医嘱规律服用。",
            ContentType.MEDICAL_INFORMATION_REQUEST,
            "CN",
            "PRODUCT-001",
        ),
        (
            "CONTENT-0002",
            "2",
            "客户互动记录中的潜在安全信号",
            "服药后出现皮疹，建议停药。",
            ContentType.CUSTOMER_INTERACTION_NOTE,
            "CN",
            "PRODUCT-001",
        ),
        (
            "CONTENT-0003",
            "5",
            "客户互动记录",
            "身份证号：13800138000。",
            ContentType.CUSTOMER_INTERACTION_NOTE,
            "CN",
            "PRODUCT-001",
        ),
        (
            "CONTENT-0004",
            "4",
            "推广材料草稿",
            "本品可用于糖尿病的治疗，推荐剂量100mg每日一次。",
            ContentType.PROMOTIONAL_CONTENT,
            "CN",
            "PRODUCT-001",
        ),
        (
            "CONTENT-0005",
            "1",
            "医疗信息请求回复",
            "出现昏迷，危及生命，需立即处理。",
            ContentType.MEDICAL_INFORMATION_REQUEST,
            "CN",
            "PRODUCT-001",
        ),
    )
    updated_at = datetime(2026, 8, 20, tzinfo=UTC)
    for record_id, version, title, text, content_type, market, product_id in rows:
        source.put(
            ContentEnvelope(
                record_id=record_id,
                version=version,
                title=title,
                text=text,
                content_type=content_type,
                tenant_id="TENANT-CN",
                market=market,
                product_id=product_id,
                updated_at=updated_at,
            )
        )


__all__ = [
    "ContentNotFoundError",
    "ContentSource",
    "ContentSourceError",
    "InMemoryContentSource",
    "StaleVersionError",
    "seed_generic_records",
]
