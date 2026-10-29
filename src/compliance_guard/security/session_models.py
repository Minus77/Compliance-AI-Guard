"""Data contracts for local users and authenticated sessions."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field

from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import Actor, DomainModel


class User(DomainModel):
    """A local account. Never carries a plaintext password."""

    username: str
    role: Role
    password_hash: str
    must_change_password: bool = False
    tenant_id: str = "TENANT-CN"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Bootstrap recovery depends on this recorded fact; do not infer it from timestamps.
    last_login_at: datetime | None = None

    @property
    def never_used(self) -> bool:
        """True when no one has ever signed in with this account.

        An account with no history has nothing to protect, which is what makes it
        safe to re-key. Once it has been used it is a real identity and re-keying
        would be a way in rather than a recovery.
        """
        return self.last_login_at is None and self.must_change_password

    def actor(self) -> Actor:
        return Actor(actor_id=f"user-{self.username}", role=self.role, tenant_id=self.tenant_id)


class Session(DomainModel):
    """An authenticated session. The token is the only credential presented."""

    token: str
    username: str
    role: Role
    tenant_id: str = "TENANT-CN"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    must_change_password: bool = False

    @property
    def actor(self) -> Actor:
        return Actor(actor_id=f"user-{self.username}", role=self.role, tenant_id=self.tenant_id)

    def expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(UTC)) >= self.expires_at
