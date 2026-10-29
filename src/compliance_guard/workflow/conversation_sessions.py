"""Short-lived, actor-bound conversation session storage."""

from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from pydantic import Field

from compliance_guard.domain.models import DomainModel


DEFAULT_SESSION_LIFETIME = timedelta(minutes=15)


class ConversationNotFoundError(KeyError):
    """The session is absent or does not belong to this tenant and actor."""


class ConversationExpiredError(ValueError):
    """The session can no longer authorize generation."""


class ConversationStaleError(ValueError):
    """The conversation was checked against a different rule version."""


class ConversationPromptMismatchError(ValueError):
    """The caller attempted to replace the server-held checked input."""


class ConversationSession(DomainModel):
    conversation_id: str
    tenant_id: str
    actor_id: str
    inspected_content_sha256: str
    safe_content: str
    content_version: str
    rule_version: str
    allowed_constraints: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime
    status: str = "active"

    def inspected_content_matches(self, content: str) -> bool:
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return digest == self.inspected_content_sha256


class ConversationStore:
    """In-memory session store containing safe text and a source hash only."""

    def __init__(
        self,
        *,
        now: Callable[[], datetime] | None = None,
        lifetime: timedelta = DEFAULT_SESSION_LIFETIME,
    ) -> None:
        self._now = now or (lambda: datetime.now(UTC))
        self._lifetime = lifetime
        self._sessions: dict[str, ConversationSession] = {}
        self._lock = threading.Lock()

    def create(
        self,
        *,
        tenant_id: str,
        actor_id: str,
        inspected_content_sha256: str,
        safe_content: str,
        content_version: str,
        rule_version: str,
        allowed_constraints: dict[str, Any] | None = None,
    ) -> ConversationSession:
        session = ConversationSession(
            conversation_id=f"conv-{uuid.uuid4().hex}",
            tenant_id=tenant_id,
            actor_id=actor_id,
            inspected_content_sha256=inspected_content_sha256,
            safe_content=safe_content,
            content_version=content_version,
            rule_version=rule_version,
            allowed_constraints=dict(allowed_constraints or {}),
            expires_at=self._now() + self._lifetime,
        )
        with self._lock:
            self._sessions[session.conversation_id] = session
        return session.model_copy(deep=True)

    def get(
        self,
        conversation_id: str,
        tenant_id: str,
        actor_id: str,
        rule_version: str,
    ) -> ConversationSession:
        with self._lock:
            return self._active_session(
                conversation_id,
                tenant_id,
                actor_id,
                rule_version,
            ).model_copy(deep=True)

    def consume(
        self,
        conversation_id: str,
        tenant_id: str,
        actor_id: str,
        rule_version: str,
    ) -> ConversationSession:
        """Atomically close an active session before its one model attempt."""
        with self._lock:
            session = self._active_session(
                conversation_id,
                tenant_id,
                actor_id,
                rule_version,
            )
            session.status = "closed"
            return session.model_copy(deep=True)

    def _active_session(
        self,
        conversation_id: str,
        tenant_id: str,
        actor_id: str,
        rule_version: str,
    ) -> ConversationSession:
        session = self._sessions.get(conversation_id)
        if (
            session is None
            or session.tenant_id != tenant_id
            or session.actor_id != actor_id
        ):
            raise ConversationNotFoundError(conversation_id)
        if session.rule_version != rule_version:
            raise ConversationStaleError(conversation_id)
        if session.status != "active" or self._now() >= session.expires_at:
            raise ConversationExpiredError(conversation_id)
        return session


__all__ = [
    "ConversationExpiredError",
    "ConversationNotFoundError",
    "ConversationPromptMismatchError",
    "ConversationSession",
    "ConversationStaleError",
    "ConversationStore",
    "DEFAULT_SESSION_LIFETIME",
]
