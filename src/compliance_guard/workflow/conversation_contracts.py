"""Request and response contracts for guarded AI conversations."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from compliance_guard.domain.enums import ContentType, Decision, Severity
from compliance_guard.domain.models import DomainModel
from compliance_guard.workflow.check_contracts import CheckFinding


class GuardInputRequest(DomainModel):
    tenant_id: str = Field(min_length=1)
    content: str
    language: str = Field(default="zh-CN", min_length=1)
    market: str = Field(default="CN", min_length=1)
    product_id: str = ""
    content_type: ContentType = ContentType.AI_CONVERSATION
    content_subtype: str = ""
    therapeutic_area: str = ""
    business_fields: dict[str, Any] = Field(default_factory=dict)
    rule_version: str = ""
    client_content_version: str = ""


class GuardInputResult(DomainModel):
    conversation_id: str | None = None
    decision: Decision
    severity: Severity
    findings: list[CheckFinding] = Field(default_factory=list)
    safe_message: str
    policy_version: str
    content_version: str
    expires_at: datetime | None = None


class GenerateRequest(DomainModel):
    tenant_id: str = Field(min_length=1)
    content: str
    rule_version: str = ""


class GenerationResult(DomainModel):
    conversation_id: str
    state: str
    published_text: str = ""
    findings: list[CheckFinding] = Field(default_factory=list)
    model_called: bool = False
    withdrawn: bool = False
