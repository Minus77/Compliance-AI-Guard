"""Content primitives shared by domain contracts."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from pydantic import AliasChoices, Field, field_validator, model_validator

from .base import DomainModel, _validate_char_span
from .enums import ContentPartType


class CharacterSpan(DomainModel):
    """A half-open Unicode character range in an identified text version."""

    start: int = Field(ge=0, strict=True)
    end: int = Field(ge=0, strict=True)
    quote_hash: str | None = None

    @model_validator(mode="after")
    def _ordered_range(self) -> "CharacterSpan":
        if self.end < self.start:
            raise ValueError("span end must not precede its start")
        return self


class ContentPart(DomainModel):
    type: ContentPartType
    ref: str | None = None
    text: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProductContext(DomainModel):
    product_id: str = Field(min_length=1, strict=True)
    label_version: str = Field(min_length=1, strict=True)
    name: str | None = None


class Entity(DomainModel):
    entity_id: str = Field(default_factory=lambda: f"entity-{uuid4().hex}")
    type: str
    token: str | None = None
    span: str | None = Field(
        default=None,
        validation_alias=AliasChoices("span", "source_span"),
    )
    confidence: float | None = Field(default=None, ge=0, le=1)

    _validate_span = field_validator("span")(_validate_char_span)
