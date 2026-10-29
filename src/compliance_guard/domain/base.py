"""Shared strict model configuration and validation primitives."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

_RESERVED_MODEL_FIELDS = frozenset(
    {
        "approval_status",
        "decision",
        "routing",
        "severity",
        "tool_permissions",
    }
)

def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _validate_char_span(value: str) -> str:
    if value.startswith("char:"):
        span = value[5:]
        try:
            start_text, end_text = span.split("-", 1)
            start = int(start_text)
            end = int(end_text)
        except (TypeError, ValueError):
            raise ValueError("location must use char:start-end notation") from None
        if start < 0 or end < start:
            raise ValueError("location must use a non-negative char:start-end span")
    return value


def _contains_reserved_model_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if isinstance(key, str) and key.casefold() in _RESERVED_MODEL_FIELDS:
                return True
            if _contains_reserved_model_field(nested_value):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_reserved_model_field(item) for item in value)
    return False


class DomainModel(BaseModel):
    """Base configuration for code-controlled domain structures."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
