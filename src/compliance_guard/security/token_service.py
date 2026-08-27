"""Tenant-scoped tokenization and fail-closed re-identification.

Tokens are deterministic digests over (tenant_id, entity_type, canonical_id),
so the same subject maps to the same token across tasks within a tenant and
even across service instances. Raw canonical identifiers are never carried on
ordinary returned objects; the protected in-memory mapping exists only for the
demo and is never exposed.
"""

from __future__ import annotations

import hashlib
import threading
from typing import Any, Callable

from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import Actor, DomainModel

AuditCallback = Callable[[str, dict[str, Any]], None]

_TOKEN_PREFIXES = {
    "hcp": "HCP_TKN_",
    "patient": "PATIENT_TKN_",
}

_REIDENTIFY_ROLES = frozenset(
    {
        Role.MEDICAL_REVIEWER,
        Role.COMPLIANCE_ADMIN,
        Role.PV_REVIEWER,
        Role.SYSTEM,
    }
)

_REIDENTIFY_PURPOSES = frozenset(
    {
        "medical_review",
        "safety_follow_up",
        "case_resolution",
        "audit_compliance",
    }
)


class TokenRef(DomainModel):
    """Stable token reference; never carries the raw canonical identifier."""

    token: str
    entity_type: str
    tenant_id: str


class TokenService:
    """Deterministic, tenant-scoped token minting with a protected demo mapping."""

    def __init__(self, audit_callback: AuditCallback | None = None) -> None:
        self._audit_callback = audit_callback
        self._lock = threading.Lock()
        self._registry: dict[tuple[str, str, str], str] = {}
        self._reverse: dict[str, tuple[str, str, str]] = {}

    def _audit(self, event: str, payload: dict[str, Any]) -> None:
        if self._audit_callback is not None:
            self._audit_callback(event, payload)

    def _derive_token(self, entity_type: str, canonical_id: str, tenant_id: str) -> str:
        digest = hashlib.sha256(
            f"{tenant_id}|{entity_type}|{canonical_id}".encode("utf-8")
        ).hexdigest()
        prefix = _TOKEN_PREFIXES.get(entity_type, "ENTITY_TKN_")
        return f"[{prefix}{digest[:16]}]"

    def tokenize(self, entity_type: str, canonical_id: str, tenant_id: str) -> TokenRef:
        token = self._derive_token(entity_type, canonical_id, tenant_id)
        key = (tenant_id, entity_type, canonical_id)
        with self._lock:
            self._registry[key] = token
            self._reverse.setdefault(token, key)
        self._audit(
            "tokenize",
            {
                "token": token,
                "entity_type": entity_type,
                "tenant_id": tenant_id,
            },
        )
        return TokenRef(token=token, entity_type=entity_type, tenant_id=tenant_id)

    def reidentify(self, token: str, actor: Actor, purpose: str) -> str:
        with self._lock:
            key = self._reverse.get(token)
        reason = None
        if key is None:
            reason = "unknown_token"
        elif actor.role not in _REIDENTIFY_ROLES:
            reason = "role_not_approved"
        elif purpose not in _REIDENTIFY_PURPOSES:
            reason = "purpose_not_approved"
        elif self._audit_callback is None:
            reason = "audit_callback_required"
        elif actor.tenant_id is not None and actor.tenant_id != key[0]:
            reason = "tenant_mismatch"
        if reason is not None:
            self._audit(
                "reidentify_denied",
                {
                    "token": token,
                    "actor_id": actor.actor_id,
                    "role": actor.role.value,
                    "purpose": purpose,
                    "reason": reason,
                },
            )
            raise PermissionError(f"re-identification denied: {reason}")
        _, entity_type, canonical_id = key
        self._audit(
            "reidentify_granted",
            {
                "token": token,
                "entity_type": entity_type,
                "actor_id": actor.actor_id,
                "role": actor.role.value,
                "purpose": purpose,
            },
        )
        return canonical_id
