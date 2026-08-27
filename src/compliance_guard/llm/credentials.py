"""Server-side resolution of live model endpoints and credentials.

Two hard rules preserved from the mock-only design:

1. **Profiles never carry secrets.** ``ModelProfile.credential_ref`` and
   ``endpoint_ref`` stay opaque server-side *references* (for example
   ``secrets/deepseek-routine`` and ``config/endpoints/deepseek-routine``).
   This module is the only place that turns a reference into a real base URL,
   upstream model id, and API key.
2. **Secrets live outside the repository tree that gets committed.** The key is
   read from the environment first, then from a gitignored local file. It is
   never written to a snapshot, never returned by an API, and never logged.

The upstream model id is deliberately separate from ``ModelProfile.model_id``:
the profile id is the *business* routing name shown in the audit trail, while
the upstream id is provider-specific wiring that may change without changing
any compliance decision.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from compliance_guard.runtime_paths import config_dir

# Environment overrides win, so a deployment can inject configuration without
# writing anything to disk.
ENV_API_KEY = "COMPLIANCE_GUARD_LLM_API_KEY"
ENV_BASE_URL = "COMPLIANCE_GUARD_LLM_BASE_URL"
ENV_SECRETS_FILE = "COMPLIANCE_GUARD_LLM_SECRETS_FILE"

_DEFAULT_SECRETS_FILENAME = "llm.local.json"
_REDACTED = "****"


class CredentialError(RuntimeError):
    """Raised when a live call is requested but wiring is missing or malformed.

    Callers turn this into a fail-safe model result rather than letting it
    escape: a missing credential must never silently downgrade to "approved".
    """


@dataclass(frozen=True)
class LiveEndpoint:
    """Everything needed to make one live call, resolved server-side."""

    base_url: str
    upstream_model: str
    api_key: str
    timeout_ms: int
    max_output_tokens: int

    def redacted(self) -> dict[str, object]:
        """Loggable view. The key is replaced, never truncated-but-present."""
        return {
            "base_url": self.base_url,
            "upstream_model": self.upstream_model,
            "timeout_ms": self.timeout_ms,
            "max_output_tokens": self.max_output_tokens,
            "api_key": _REDACTED,
        }


def secrets_path() -> Path:
    """Location of the gitignored local secrets file."""
    override = os.environ.get(ENV_SECRETS_FILE)
    if override:
        return Path(override).expanduser()
    return config_dir() / "secrets" / _DEFAULT_SECRETS_FILENAME


def _read_secrets_file() -> dict[str, object]:
    path = secrets_path()
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CredentialError(f"local secrets file is unreadable or malformed: {path}") from exc
    if not isinstance(payload, dict):
        raise CredentialError(f"local secrets file must contain a JSON object: {path}")
    return payload


def resolve_api_key() -> str:
    """Return the API key from the environment, else the local secrets file."""
    from_env = os.environ.get(ENV_API_KEY, "").strip()
    if from_env:
        return from_env

    value = _read_secrets_file().get("api_key")
    key = str(value).strip() if value is not None else ""
    if not key:
        raise CredentialError(
            "no live API key configured; set "
            f"{ENV_API_KEY} or add {{\"api_key\": \"...\"}} to {secrets_path()}"
        )
    return key


def resolve_base_url() -> str:
    """Return the provider base URL, without a trailing slash."""
    from_env = os.environ.get(ENV_BASE_URL, "").strip()
    if from_env:
        return from_env.rstrip("/")

    value = _read_secrets_file().get("base_url")
    base = str(value).strip() if value is not None else ""
    if not base:
        raise CredentialError(
            "no live base URL configured; set "
            f"{ENV_BASE_URL} or add {{\"base_url\": \"...\"}} to {secrets_path()}"
        )
    return base.rstrip("/")


def _endpoint_file(endpoint_ref: str) -> Path:
    """Resolve an opaque ``config/endpoints/<name>`` reference to a real file.

    The reference is treated as untrusted configuration: only a bare name is
    accepted, so a crafted profile cannot walk the filesystem.
    """
    ref = (endpoint_ref or "").strip()
    if not ref:
        raise CredentialError("profile has no endpoint_ref; cannot resolve a live endpoint")

    name = ref.rsplit("/", 1)[-1]
    if not name or name in {".", ".."} or "\\" in name or Path(name).name != name:
        raise CredentialError(f"endpoint_ref {endpoint_ref!r} is not a plain server-side reference")

    return config_dir() / "endpoints" / f"{name}.json"


def resolve_endpoint(
    *,
    endpoint_ref: str | None,
    timeout_ms: int,
    token_budget: int,
) -> LiveEndpoint:
    """Resolve one profile's live wiring, or raise :class:`CredentialError`."""
    path = _endpoint_file(endpoint_ref or "")
    if not path.is_file():
        raise CredentialError(f"no endpoint mapping file for {endpoint_ref!r} (expected {path})")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CredentialError(f"endpoint mapping is unreadable or malformed: {path}") from exc

    if not isinstance(payload, dict):
        raise CredentialError(f"endpoint mapping must be a JSON object: {path}")

    for forbidden in ("api_key", "apikey", "secret", "secret_key", "password", "access_token"):
        if forbidden in {str(key).casefold() for key in payload}:
            raise CredentialError(
                f"endpoint mapping {path} must not contain plaintext {forbidden!r}; "
                f"use {ENV_API_KEY} or the local secrets file"
            )

    upstream = str(payload.get("upstream_model") or "").strip()
    if not upstream:
        raise CredentialError(f"endpoint mapping {path} must set a non-empty 'upstream_model'")

    base_url = str(payload.get("base_url") or "").strip() or resolve_base_url()

    return LiveEndpoint(
        base_url=base_url.rstrip("/"),
        upstream_model=upstream,
        api_key=resolve_api_key(),
        timeout_ms=int(payload.get("timeout_ms") or timeout_ms),
        max_output_tokens=int(payload.get("max_output_tokens") or token_budget),
    )


__all__ = [
    "ENV_API_KEY",
    "ENV_BASE_URL",
    "ENV_SECRETS_FILE",
    "CredentialError",
    "LiveEndpoint",
    "resolve_api_key",
    "resolve_base_url",
    "resolve_endpoint",
    "secrets_path",
]
