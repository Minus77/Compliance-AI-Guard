"""Public request and result contracts for content checks."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field, field_validator

from compliance_guard.domain.enums import (
    ContentType,
    Decision,
    Severity,
    normalize_content_type,
)
from compliance_guard.domain.models import CharacterSpan, ContentPart, DomainModel


class CheckRequest(DomainModel):
    tenant_id: str = Field(min_length=1)
    content_type: ContentType = ContentType.CUSTOMER_INTERACTION_NOTE
    content_subtype: str = ""
    market: str = Field(min_length=1)
    language: str = Field(default="zh-CN", min_length=1)
    product_id: str = ""
    therapeutic_area: str = ""
    content: str = ""
    content_parts: list[ContentPart] = Field(default_factory=list)
    business_fields: dict[str, Any] = Field(default_factory=dict)
    rule_version: str = ""
    retention_policy: str = ""
    external_ref: str = ""
    client_content_version: str = ""

    @field_validator("content_type", mode="before")
    @classmethod
    def _normalize_content_type(cls, value):
        if isinstance(value, ContentType):
            return value
        return normalize_content_type(str(value or ""))


class CheckFinding(DomainModel):
    finding_id: str = ""
    type: str
    severity: Severity
    decision: Decision
    rule_id: str | None = None
    rule_version: str = ""
    category: str = ""
    matched_terms: list[str] = Field(default_factory=list)
    spans: list[CharacterSpan] = Field(default_factory=list)
    allow_save: bool = True
    allow_generate: bool = True
    allow_publish: bool = True
    notification_message: str = ""
    remediation_guidance: str = ""


class CheckResult(DomainModel):
    check_id: str = ""
    decision: Decision
    severity: Severity
    findings: list[CheckFinding] = Field(default_factory=list)
    policy_version: str
    content_version: str
    spans_stale: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    safe_text: str = ""
    masked_count: int = 0
    model_called: bool = False
    status: str = ""
