"""Contracts for misclassification feedback and regression candidates."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import Field

from compliance_guard.domain.models import DomainModel


class FeedbackKind(str, Enum):
    """What the reviewer says went wrong."""

    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


class FeedbackEntry(DomainModel):
    """One reported misclassification, pending or confirmed."""

    entry_id: str = Field(default_factory=lambda: f"feedback-{uuid.uuid4().hex}")
    case_id: str
    kind: FeedbackKind
    reason: str
    masked_text: str
    observed_decision: str
    observed_findings: list[str] = Field(default_factory=list)
    expected_decision: str
    category: str
    reported_by: str
    reported_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: str = "candidate"
    confirmed_by: str | None = None
    confirmed_at: datetime | None = None

    def golden_case(self) -> dict[str, Any]:
        """Shape the entry as a golden-set row."""
        return {
            "case_id": f"R-{self.entry_id[-8:]}",
            "category": self.category,
            "scenario": "normal" if self.kind is FeedbackKind.FALSE_POSITIVE else "ae",
            "content": self.masked_text,
            "expected_decision": self.expected_decision,
            "source_case_id": self.case_id,
            "note": (
                f"regression candidate from production feedback "
                f"({self.kind.value}): {self.reason}"
            ),
        }


__all__ = ["FeedbackEntry", "FeedbackKind"]
