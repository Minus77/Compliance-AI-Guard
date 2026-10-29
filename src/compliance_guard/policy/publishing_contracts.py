"""Immutable data contracts for rule test reports and published snapshots."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from compliance_guard.domain.enums import RuleStatus
from compliance_guard.domain.models import DomainModel

from .bundles import PolicyRule


class RuleTestFailure(DomainModel):
    rule_id: str
    case_index: int
    message: str


class RuleTestReport(DomainModel):
    version: str
    passed: bool
    failures: list[RuleTestFailure] = Field(default_factory=list)


class RuleVersion(DomainModel):
    version: str
    status: RuleStatus
    rules: dict[str, PolicyRule]
    created_at: datetime
    published_at: datetime | None = None
    market: str = "GLOBAL"
    product_id: str | None = None
    channel: str | None = None
    effective_from: datetime | None = None
    effective_until: datetime | None = None
    source_version: str = ""
    last_test_passed: bool = False
    published_by: str | None = None

    model_config = DomainModel.model_config | {"frozen": True}


__all__ = ["RuleTestFailure", "RuleTestReport", "RuleVersion"]
