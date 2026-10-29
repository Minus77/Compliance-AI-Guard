"""Validation and contract types for the versioned model registry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field

from compliance_guard.domain.enums import AdapterType
from compliance_guard.domain.models import DomainModel, ModelProfile, TaskRoute

_APPROVED_ADAPTERS = frozenset({AdapterType.MOCK})
_FORBIDDEN_SECRET_KEYS = frozenset(
    {"api_key", "apikey", "secret_key", "secret", "client_secret", "password", "access_token"}
)
_FORBIDDEN_ENDPOINT_PREFIXES = ("http://", "https://", "ftp://", "ws://", "wss://")


class DraftValidationError(RuntimeError):
    """Raised when a staged draft violates capability, region, data-class or security rules."""


class RegistrySnapshot(DomainModel):
    """Redacted, immutable view of the currently published configuration."""

    version: str
    profiles: dict[str, ModelProfile] = Field(default_factory=dict)
    routes: dict[str, TaskRoute] = Field(default_factory=dict)
    redacted: bool = True


def load_raw(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise DraftValidationError(f"{path} must contain a JSON object")
    return payload


def reject_plaintext_secrets(
    raw_profiles: dict[str, Any], raw_routes: dict[str, Any]
) -> None:
    """Reject configuration payloads carrying literal secrets or arbitrary endpoints."""
    problems: list[str] = []
    for profile_id, raw in raw_profiles.items():
        if not isinstance(raw, dict):
            problems.append(f"profile {profile_id!r} must be a JSON object")
            continue
        for key in raw:
            if key.casefold() in _FORBIDDEN_SECRET_KEYS:
                problems.append(
                    f"profile {profile_id!r} must not store plaintext {key!r}; "
                    "use credential_ref"
                )
        endpoint = str(raw.get("endpoint_ref") or "").casefold()
        if endpoint.startswith(_FORBIDDEN_ENDPOINT_PREFIXES):
            problems.append(
                f"profile {profile_id!r} endpoint_ref must be a server-side "
                "reference, not an endpoint"
            )
        credential = str(raw.get("credential_ref") or "")
        if credential.casefold().startswith(("sk-", "bearer ")) or (
            ":" in credential and "://" not in credential
        ):
            problems.append(
                f"profile {profile_id!r} credential_ref must be a reference, "
                "not a secret value"
            )
    if problems:
        raise DraftValidationError("; ".join(problems))


def validate_adapter(profile: ModelProfile) -> list[str]:
    problems: list[str] = []
    if profile.adapter_type not in _APPROVED_ADAPTERS:
        problems.append(
            f"profile {profile.profile_id!r} uses unapproved adapter "
            f"{profile.adapter_type.value!r}"
        )
    endpoint = (profile.endpoint_ref or "").casefold()
    if endpoint.startswith(_FORBIDDEN_ENDPOINT_PREFIXES):
        problems.append(
            f"profile {profile.profile_id!r} endpoint_ref must be a server-side reference"
        )
    if profile.credential_ref and profile.credential_ref.casefold().startswith(
        ("sk-", "bearer ")
    ):
        problems.append(
            f"profile {profile.profile_id!r} credential_ref must not hold a plaintext secret"
        )
    return problems
