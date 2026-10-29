"""Structured label facts and comparison result contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from compliance_guard.domain.models import DomainModel


class LabelFacts(DomainModel):
    product_id: str
    market: str
    version: str
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    indication: str | None = None
    indication_id: str | None = None
    population: str | None = None
    line: str | None = None
    dose: str | None = None
    route: str | None = None
    duration: str | None = None
    combination: str | None = None
    contraindications: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class LabelComparison(DomainModel):
    matches: bool
    mismatches: list[str] = Field(default_factory=list)
    details: dict[str, dict[str, Any]] = Field(default_factory=dict)


__all__ = ["LabelComparison", "LabelFacts"]
