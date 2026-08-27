"""Typed contracts for the deterministic model boundary."""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ModelRequest(BaseModel):
    """Sanitized, minimum-necessary input sent to a model adapter."""

    model_config = ConfigDict(extra="forbid")

    scenario: str
    task_type: str | None = None
    content: str
    evidence_ids: list[str] = Field(default_factory=list)
    # Retrieved evidence the model may reason from: id, version, stance and the
    # approved excerpt. Sending only ids asked the model to reason from facts it
    # could not see, and a real model correctly refused the task. Excerpts come
    # from the curated knowledge base, never from user input.
    evidence_excerpts: list[dict[str, Any]] = Field(default_factory=list)
    structured_payload: dict[str, Any] | None = None
    # The current approved label for *one* product/market, as structured fields.
    # Never label prose: what travels here is a fixed set of short values, so the
    # request size is decoupled from catalogue size and document length. Growing
    # from 1 product to 500 grows a local table, not this payload.
    label_facts: dict[str, Any] | None = None


class ModelConstraints(BaseModel):
    """Runtime constraints selected by the task route."""

    model_config = ConfigDict(extra="forbid")

    mode: str = Field(default_factory=lambda: os.getenv("LLM_MODE", "mock"))
    profile_id: str | None = None
    model_id: str | None = None
    route_version: str | None = None
    timeout_ms: int = Field(default=5_000, gt=0)
    token_budget: int = Field(default=2_048, gt=0)
    data_class: str | None = None
    region: str | None = None
    allowed_data_classes: list[str] = Field(default_factory=list)
    allowed_regions: list[str] = Field(default_factory=list)


class RawModelResult(BaseModel):
    """Adapter output before downstream schema and policy validation."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    model_id: str | None = None
    profile_id: str | None = None
    # The provider-specific model that actually answered. ``model_id`` is the
    # business routing name shown in the UI and pinned by configuration; this is
    # the real upstream identity. Both are recorded so a case stays reproducible
    # even after the endpoint mapping is repointed at a different model.
    upstream_model: str | None = None
    route_version: str | None = None
    raw_json: dict[str, Any] = Field(default_factory=dict)
    latency_ms: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    fallback_used: bool = False
    error_category: str | None = None
