"""Request payloads shared by the grouped API routes."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from compliance_guard.knowledge.glossary import DEFAULT_LOCALE
from compliance_guard.policy.workbench import MAX_BATCH_CASES, RuleCase


class DecisionPayload(BaseModel):
    decision: str
    reason: str = ""


class LoginPayload(BaseModel):
    username: str = ""
    password: str = ""


class ChangePasswordPayload(BaseModel):
    current: str = ""
    replacement: str = ""


class PrecheckPayload(BaseModel):
    tenant_id: str = "TENANT-CN"
    content: str = ""
    market: str = "CN"
    language: str = "zh-CN"
    product_id: str = ""
    source: str = "customer_interaction_note"
    content_type: str = "customer_interaction_note"
    content_subtype: str = ""
    therapeutic_area: str = ""
    client_content_version: str = ""
    structured_fields: dict[str, Any] = Field(default_factory=dict)
    locale: str = DEFAULT_LOCALE


class RevisePayload(BaseModel):
    content: str
    structured_fields: dict[str, Any] = Field(default_factory=dict)


class AppealPayload(BaseModel):
    reason: str = ""


class AppealResolutionPayload(BaseModel):
    upheld: bool = True
    reason: str = ""


class FollowupPayload(BaseModel):
    answers: dict[str, Any] = Field(default_factory=dict)


class BatchDecisionPayload(BaseModel):
    task_ids: list[str] = Field(default_factory=list)
    decision: str = ""
    reason: str = ""


class UsabilityPayload(BaseModel):
    event: str
    context: dict[str, Any] = Field(default_factory=dict)


class FeedbackPayload(BaseModel):
    kind: str
    reason: str = ""


class DraftPayload(BaseModel):
    profiles: list[dict[str, Any]] = Field(default_factory=list)
    routes: list[dict[str, Any]] = Field(default_factory=list)
    draft: list[Any] | None = None


class ModelTestPayload(BaseModel):
    task_type: str
    modality: str | None = None
    data_class: str | None = None
    region: str | None = None
    content: str | None = None


class AttachmentPayload(BaseModel):
    kind: str
    filename: str
    mime_type: str = ""
    size_bytes: int = Field(default=0, ge=0)
    duration_seconds: float | None = Field(default=None, ge=0)


class RuleTestPayload(BaseModel):
    version: str
    rule_id: str
    case: RuleCase


class RuleBatchPayload(BaseModel):
    version: str
    cases: list[RuleCase] = Field(default_factory=list, max_length=MAX_BATCH_CASES)


class RuleVersionPayload(BaseModel):
    version: str
