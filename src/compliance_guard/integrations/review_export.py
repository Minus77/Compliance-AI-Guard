"""Explicitly enabled, idempotent review export connector."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from compliance_guard.domain.enums import DataClass

from .contracts import (
    ConnectorInfo,
    ExportReceipt,
    HealthStatus,
    ReviewExportRequest,
)


class ReviewExportDisabledError(PermissionError):
    """The operator has not enabled review export."""


@runtime_checkable
class ReviewExport(Protocol):
    def export(
        self, request: ReviewExportRequest, idempotency_key: str
    ) -> ExportReceipt: ...


class InMemoryReviewExport:
    """Reference export sink that is disabled unless explicitly enabled."""

    def __init__(
        self,
        *,
        connector_id: str = "review_export",
        label: str = "Reference review export",
        enabled: bool = False,
    ) -> None:
        self._enabled = enabled
        self._info = ConnectorInfo(
            connector_id=connector_id,
            connector_kind="review_export",
            label=label,
            description="Opt-in idempotent export of completed review decisions.",
            capabilities=["export", "idempotency"],
            data_classes=[DataClass.CONFIDENTIAL, DataClass.PII_TOKENIZED],
            allowed_actions=["export_review"],
            enabled=enabled,
        )
        self._exports: dict[str, ExportReceipt] = {}

    @property
    def info(self) -> ConnectorInfo:
        return self._info.model_copy(deep=True)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self) -> None:
        self._enabled = True
        self._info = self._info.model_copy(update={"enabled": True})

    def disable(self) -> None:
        self._enabled = False
        self._info = self._info.model_copy(update={"enabled": False})

    def export(self, request: ReviewExportRequest, idempotency_key: str) -> ExportReceipt:
        if not self._enabled:
            raise ReviewExportDisabledError("review export is disabled")
        key = idempotency_key.strip()
        if not key:
            raise ValueError("idempotency key required")
        existing = self._exports.get(key)
        if existing is not None:
            return existing.model_copy(deep=True)
        receipt = ExportReceipt(
            export_id=f"export-{uuid.uuid4().hex}",
            case_id=request.case_id,
            idempotency_key=key,
            exported_at=datetime.now(UTC),
        )
        self._exports[key] = receipt
        return receipt.model_copy(deep=True)

    def health(self) -> HealthStatus:
        return HealthStatus(
            connector_id=self._info.connector_id,
            status="healthy" if self._enabled else "disabled",
            detail=(
                "export enabled"
                if self._enabled
                else "export disabled until explicitly enabled"
            ),
            checked_at=datetime.now(UTC),
        )


__all__ = [
    "InMemoryReviewExport",
    "ReviewExport",
    "ReviewExportDisabledError",
]
