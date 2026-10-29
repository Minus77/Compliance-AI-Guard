"""Model routing and policy configuration contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import ConfigDict, Field, field_validator

from .base import DomainModel, _utc
from .enums import AdapterType, CostTier, DataClass, Modality, TaskType


class ModelProfile(DomainModel):
    profile_id: str
    provider: str
    display_name: str
    model_id: str
    adapter_type: AdapterType = AdapterType.MOCK
    capabilities: list[Modality] = Field(default_factory=lambda: [Modality.TEXT])
    allowed_data_classes: list[DataClass] = Field(default_factory=list)
    region: str = "CN"
    credential_ref: str | None = None
    endpoint_ref: str | None = None
    timeout_ms: int = Field(default=5_000, gt=0)
    token_budget: int = Field(default=2_048, gt=0)
    cost_tier: CostTier = CostTier.LOW
    enabled: bool = Field(default=True, strict=True)
    version: str = "1"

    model_config = ConfigDict(frozen=True)


class TaskRoute(DomainModel):
    task_type: TaskType
    primary_profile_id: str
    fallback_profile_ids: list[str] = Field(default_factory=list)
    required_capabilities: list[Modality] = Field(default_factory=list)
    allowed_regions: list[str] = Field(default_factory=list)
    allowed_data_classes: list[DataClass] = Field(default_factory=list)
    max_attempts: int = Field(default=1, ge=1, strict=True)
    requires_human_on_failure: bool = Field(default=True, strict=True)
    route_version: str

    model_config = ConfigDict(frozen=True)


class PolicyBundle(DomainModel):
    policy_version: str
    market: str
    product_id: str | None = None
    channel: str | None = None
    effective_from: datetime | None = None
    effective_until: datetime | None = None
    rules: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

    _normalize_effective_from = field_validator("effective_from")(_utc)
    _normalize_effective_until = field_validator("effective_until")(_utc)
