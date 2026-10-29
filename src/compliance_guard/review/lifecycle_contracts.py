"""Contracts for case notifications and appeals."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import Field

from compliance_guard.domain.models import DomainModel


class NotificationKind(str, Enum):
    """Why the author is being told something.

    Only outcomes that need the author to know appear here. A clean release
    updates their list silently: notifying on every state change trains people to
    dismiss notifications without reading them, and then the one that matters is
    dismissed too.
    """

    REVIEW_DECIDED = "review_decided"
    APPEAL_RESOLVED = "appeal_resolved"


class AppealStatus(str, Enum):
    PENDING = "pending"
    UPHELD = "upheld"      # the original decision stands
    OVERTURNED = "overturned"


class Notification(DomainModel):
    """One message to the author of a case. Never carries personal data."""

    notification_id: str = Field(default_factory=lambda: f"note-{uuid.uuid4().hex}")
    case_id: str
    recipient_id: str
    kind: NotificationKind
    title: str
    body: str = ""
    next_step: str = ""
    decision: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    read_at: datetime | None = None

    @property
    def unread(self) -> bool:
        return self.read_at is None


class Appeal(DomainModel):
    """A request for a person to look again. Does not change the current decision."""

    appeal_id: str = Field(default_factory=lambda: f"appeal-{uuid.uuid4().hex}")
    case_id: str
    reason: str
    raised_by: str
    decision_at_appeal: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: AppealStatus = AppealStatus.PENDING
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    resolution_reason: str = ""


__all__ = ["Appeal", "AppealStatus", "Notification", "NotificationKind"]
