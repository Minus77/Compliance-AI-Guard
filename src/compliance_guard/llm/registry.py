"""Versioned model control plane: profile registry, task routing, publish/rollback.

The registry holds immutable, versioned profiles and routes. Static defaults are
loaded from ``config/model_profiles.json`` and ``config/task_routes.json``; only
non-secret fields are persisted to the runtime snapshot. Drafting, validating,
publishing and rolling back require admin authorization, and a published route is
immutable until an admin publishes a new version. Task routing is deterministic:
``multimodal_extraction`` -> MiniMax, ``routine_compliance`` -> DeepSeek,
``complex_evidence_reasoning`` -> Kimi.

Model IDs are opaque configuration values (the user-supplied names); the registry
never invents provider-specific API IDs.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import Field

from compliance_guard.domain.enums import AdapterType, TaskType
from compliance_guard.domain.models import AuditEvent, DomainModel, ModelProfile, TaskRoute
from compliance_guard.security.authorization import AuthorizationService

from .task_router import ResolvedRoute, RouteValidationError, TaskRouter

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


@dataclass(frozen=True, slots=True)
class _StableSnapshot:
    version: int
    profiles: dict[str, ModelProfile]
    routes: dict[TaskType, TaskRoute]


def _repo_config_dir() -> Path:
    from compliance_guard.runtime_paths import config_dir

    # Read-only resource: ships inside the bundle when frozen.
    return config_dir()


def _repo_data_dir() -> Path:
    from compliance_guard.runtime_paths import writable_data_dir

    # Writable: runtime_config.json is rewritten on publish/rollback, so it
    # must not live inside a read-only bundle.
    return writable_data_dir()


def _default_profiles_path() -> Path:
    return _repo_config_dir() / "model_profiles.json"


def _default_routes_path() -> Path:
    return _repo_config_dir() / "task_routes.json"


def _default_runtime_path() -> Path:
    return _repo_data_dir() / "runtime_config.json"


def _default_prompts_dir() -> Path:
    return _repo_config_dir() / "prompts"


def _load_raw(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise DraftValidationError(f"{path} must contain a JSON object")
    return payload


def _reject_plaintext_secrets(raw_profiles: dict[str, Any], raw_routes: dict[str, Any]) -> None:
    """Reject configuration payloads that carry literal secret values or arbitrary endpoints."""
    problems: list[str] = []
    for profile_id, raw in raw_profiles.items():
        if not isinstance(raw, dict):
            problems.append(f"profile {profile_id!r} must be a JSON object")
            continue
        for key in raw:
            if key.casefold() in _FORBIDDEN_SECRET_KEYS:
                problems.append(f"profile {profile_id!r} must not store plaintext {key!r}; use credential_ref")
        endpoint = str(raw.get("endpoint_ref") or "").casefold()
        if endpoint.startswith(_FORBIDDEN_ENDPOINT_PREFIXES):
            problems.append(
                f"profile {profile_id!r} endpoint_ref must be a server-side reference, not an endpoint"
            )
        credential = str(raw.get("credential_ref") or "")
        if credential.casefold().startswith(("sk-", "bearer ")) or ":" in credential and "://" not in credential:
            problems.append(f"profile {profile_id!r} credential_ref must be a reference, not a secret value")
    if problems:
        raise DraftValidationError("; ".join(problems))


def _validate_adapter(profile: ModelProfile) -> list[str]:
    problems: list[str] = []
    if profile.adapter_type not in _APPROVED_ADAPTERS:
        problems.append(
            f"profile {profile.profile_id!r} uses unapproved adapter {profile.adapter_type.value!r}"
        )
    endpoint = (profile.endpoint_ref or "").casefold()
    if endpoint.startswith(_FORBIDDEN_ENDPOINT_PREFIXES):
        problems.append(
            f"profile {profile.profile_id!r} endpoint_ref must be a server-side reference"
        )
    if profile.credential_ref and profile.credential_ref.casefold().startswith(("sk-", "bearer ")):
        problems.append(
            f"profile {profile.profile_id!r} credential_ref must not hold a plaintext secret"
        )
    return problems




class ModelRegistry:
    """Versioned profile/route registry with draft, publish and rollback."""

    def __init__(
        self,
        profiles_path: str | Path | None = None,
        routes_path: str | Path | None = None,
        runtime_path: str | Path | None = None,
        prompts_dir: str | Path | None = None,
        auth: AuthorizationService | None = None,
    ) -> None:
        self._profiles_path = Path(profiles_path) if profiles_path else _default_profiles_path()
        self._routes_path = Path(routes_path) if routes_path else _default_routes_path()
        self._runtime_path = Path(runtime_path) if runtime_path else _default_runtime_path()
        self._prompts_dir = Path(prompts_dir) if prompts_dir else _default_prompts_dir()
        self._auth = auth or AuthorizationService()
        self._lock = threading.RLock()

        self._profiles: dict[str, ModelProfile] = {}
        self._routes: dict[TaskType, TaskRoute] = {}
        self._drafts: dict[str, ModelProfile] = {}
        self._route_drafts: dict[TaskType, TaskRoute] = {}
        self._version = 0
        self._history: list[_StableSnapshot] = []
        self._audit_events: list[AuditEvent] = []

    @property
    def prompts_dir(self) -> Path:
        return self._prompts_dir

    def load_defaults(self) -> "ModelRegistry":
        """Load static defaults, then restore a newer persisted snapshot if present.

        A persisted runtime snapshot that is newer than the static baseline is the
        authoritative published state and survives restart; defaults are only used
        to bootstrap when no newer snapshot exists.
        """
        with self._lock:
            return self._load_defaults()

    def _load_defaults(self) -> "ModelRegistry":
        raw_profiles = _load_raw(self._profiles_path)
        raw_routes = _load_raw(self._routes_path)
        _reject_plaintext_secrets(raw_profiles, raw_routes)
        profiles: dict[str, ModelProfile] = {}
        for profile_id, raw in raw_profiles.items():
            problems = self._validate_profile(profile_id, raw)
            model = ModelProfile(**raw)
            problems.extend(_validate_adapter(model))
            if problems:
                raise DraftValidationError("; ".join(problems))
            profiles[profile_id] = model
        routes = {
            TaskType(task_type): TaskRoute(**raw)
            for task_type, raw in raw_routes.items()
        }
        baseline_version = 1

        if self._runtime_path.is_file():
            snapshot = self._read_snapshot(self._runtime_path)
            persisted_version = int(snapshot["version"])
            if persisted_version > baseline_version:
                self._profiles, self._routes = self._profiles_from_snapshot(snapshot)
                self._version = persisted_version
                self._drafts.clear()
                self._route_drafts.clear()
                self._history.clear()
                return self

        self._profiles = profiles
        self._routes = routes
        self._drafts.clear()
        self._route_drafts.clear()
        self._history.clear()
        self._version = baseline_version
        self._persist_snapshot()
        return self

    @staticmethod
    def _read_snapshot(path: Path) -> dict[str, Any]:
        """Read and shape-check a persisted runtime snapshot; tampering fails loudly."""
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DraftValidationError(f"corrupt runtime snapshot {path}: {exc}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("profiles"), dict):
            raise DraftValidationError(f"invalid runtime snapshot shape in {path}")
        if not isinstance(payload.get("routes"), dict):
            raise DraftValidationError(f"invalid runtime snapshot shape in {path}")
        try:
            version = int(str(payload.get("version")))
        except (TypeError, ValueError):
            raise DraftValidationError(f"invalid runtime snapshot version in {path}") from None
        return {"version": version, "profiles": payload["profiles"], "routes": payload["routes"]}

    def _profiles_from_snapshot(
        self, snapshot: dict[str, Any]
    ) -> tuple[dict[str, ModelProfile], dict[TaskType, TaskRoute]]:
        """Rebuild typed, validated, deeply-copied state from a persisted snapshot."""
        raw_profiles = snapshot["profiles"]
        raw_routes = snapshot["routes"]
        _reject_plaintext_secrets(raw_profiles, raw_routes)
        profiles: dict[str, ModelProfile] = {}
        for profile_id, raw in raw_profiles.items():
            problems = self._validate_profile(profile_id, raw)
            model = ModelProfile(**raw)
            problems.extend(_validate_adapter(model))
            if problems:
                raise DraftValidationError("; ".join(problems))
            profiles[profile_id] = model.model_copy(deep=True)
        routes = {
            TaskType(task_type): TaskRoute(**raw).model_copy(deep=True)
            for task_type, raw in raw_routes.items()
        }
        return profiles, routes

    @staticmethod
    def _validate_profile(profile_id: str, raw: dict[str, Any]) -> list[str]:
        problems: list[str] = []
        if profile_id != raw.get("profile_id"):
            problems.append(f"profile key {profile_id!r} must match its profile_id")
        return problems

    def load_config(self, profiles_path: str | Path, routes_path: str | Path) -> "ModelRegistry":
        """Validate a config payload without mutating the registry; rejects secrets and endpoints."""
        raw_profiles = _load_raw(Path(profiles_path))
        raw_routes = _load_raw(Path(routes_path))
        _reject_plaintext_secrets(raw_profiles, raw_routes)
        for profile_id, raw in raw_profiles.items():
            problems = self._validate_profile(profile_id, raw)
            if problems:
                raise DraftValidationError("; ".join(problems))
            model = ModelProfile(**raw)
            adapter_problems = _validate_adapter(model)
            if adapter_problems:
                raise DraftValidationError("; ".join(adapter_problems))
        for task_type, raw in raw_routes.items():
            TaskRoute(**raw)
        return self

    def profile(self, profile_id: str) -> ModelProfile | None:
        with self._lock:
            profile = self._profiles.get(profile_id)
            return profile.model_copy(deep=True) if profile is not None else None

    def route(self, task_type: TaskType | str) -> TaskRoute | None:
        with self._lock:
            route = self._routes.get(TaskType(task_type))
            return route.model_copy(deep=True) if route is not None else None

    def audit_events(self) -> list[AuditEvent]:
        with self._lock:
            return [event.model_copy(deep=True) for event in self._audit_events]

    def draft(self, profile_or_route: ModelProfile | TaskRoute) -> None:
        """Stage a profile or route for an atomic publish (does not change live routes)."""
        with self._lock:
            if isinstance(profile_or_route, ModelProfile):
                self._drafts[profile_or_route.profile_id] = profile_or_route
            elif isinstance(profile_or_route, TaskRoute):
                self._route_drafts[profile_or_route.task_type] = profile_or_route
            else:
                raise TypeError("draft accepts ModelProfile or TaskRoute")

    def _draft_problems(self) -> list[str]:
        problems: list[str] = []
        known = set(self._profiles) | set(self._drafts)

        for profile_id, profile in self._drafts.items():
            problems.extend(_validate_adapter(profile))

        for task_type, route in self._route_drafts.items():
            primary = self._profiles.get(route.primary_profile_id) or self._drafts.get(
                route.primary_profile_id
            )
            if primary is None:
                problems.append(
                    f"route {task_type.value!r} references unknown primary profile {route.primary_profile_id!r}"
                )
            else:
                required = set(route.required_capabilities)
                if not required <= set(primary.capabilities):
                    problems.append(
                        f"route {task_type.value!r} primary profile lacks required capabilities {sorted(c.value for c in required - set(primary.capabilities))}"
                    )
                if route.allowed_regions and primary.region not in route.allowed_regions:
                    problems.append(
                        f"route {task_type.value!r} primary profile region {primary.region!r} is outside allowed regions"
                    )
                if not set(route.allowed_data_classes) <= set(primary.allowed_data_classes):
                    problems.append(
                        f"route {task_type.value!r} allowed data classes exceed primary profile capabilities"
                    )

            for fallback_id in route.fallback_profile_ids:
                if fallback_id == route.primary_profile_id:
                    problems.append(
                        f"route {task_type.value!r} profile {fallback_id!r} cannot be its own fallback"
                    )
                if fallback_id not in known:
                    problems.append(
                        f"route {task_type.value!r} references unknown fallback profile {fallback_id!r}"
                    )
                fallback = self._profiles.get(fallback_id) or self._drafts.get(fallback_id)
                if fallback is not None:
                    required = set(route.required_capabilities)
                    if not required <= set(fallback.capabilities):
                        problems.append(
                            f"route {task_type.value!r} fallback profile {fallback_id!r} lacks required capabilities"
                        )
                    if route.allowed_regions and fallback.region not in route.allowed_regions:
                        problems.append(
                            f"route {task_type.value!r} fallback profile {fallback_id!r} region {fallback.region!r} is outside allowed regions"
                        )
                    if not set(route.allowed_data_classes) <= set(fallback.allowed_data_classes):
                        problems.append(
                            f"route {task_type.value!r} fallback profile {fallback_id!r} does not cover allowed data classes"
                        )
        return problems

    def validate_draft(self) -> list[str]:
        """Validate staged drafts; raises DraftValidationError when incompatible."""
        with self._lock:
            problems = self._draft_problems()
            if problems:
                raise DraftValidationError("; ".join(problems))
            return problems

    def publish(self, actor: Any | None = None, *, bootstrap: bool = False) -> str:
        """Validate and atomically apply drafts as a new immutable published version.

        Requires an admin actor unless ``bootstrap=True`` (trusted startup only).
        Every publish records an audit event. Published state is deep-copied so
        returned references can never corrupt current or historical versions.
        """
        if not bootstrap:
            if actor is None:
                raise PermissionError(
                    "publish requires an authorized actor (or bootstrap=True for trusted startup)"
                )
            self._auth.require(actor, "config_publish")
        with self._lock:
            self.validate_draft()
            next_profiles = {
                profile_id: profile.model_copy(deep=True)
                for profile_id, profile in {**self._profiles, **self._drafts}.items()
            }
            next_routes = {
                task_type: route.model_copy(deep=True)
                for task_type, route in {**self._routes, **self._route_drafts}.items()
            }

            self._history.append(
                _StableSnapshot(self._version, self._copy_profiles(), self._copy_routes())
            )
            self._version += 1
            self._profiles = next_profiles
            self._routes = next_routes
            self._drafts.clear()
            self._route_drafts.clear()
            self._persist_snapshot()
            self._record_audit("config_publish", actor if not bootstrap else None, str(self._version))
            return str(self._version)

    def rollback(self, actor: Any | None = None, *, bootstrap: bool = False) -> str:
        """Restore the previous stable published version.

        Requires an admin actor unless ``bootstrap=True`` (trusted startup only).
        Every rollback records an audit event. Restored state is deep-copied.
        """
        if not bootstrap:
            if actor is None:
                raise PermissionError(
                    "rollback requires an authorized actor (or bootstrap=True for trusted startup)"
                )
            self._auth.require(actor, "config_rollback")
        with self._lock:
            if not self._history:
                raise DraftValidationError("no previous stable version to roll back to")
            previous = self._history.pop()
            self._profiles = self._copy_profiles_from(previous.profiles)
            self._routes = self._copy_routes_from(previous.routes)
            self._version = previous.version
            self._drafts.clear()
            self._route_drafts.clear()
            self._persist_snapshot()
            self._record_audit("config_rollback", actor if not bootstrap else None, str(self._version))
            return str(self._version)

    def current_snapshot(self) -> RegistrySnapshot:
        with self._lock:
            return RegistrySnapshot(
                version=str(self._version),
                profiles={
                    profile_id: profile.model_copy(deep=True)
                    for profile_id, profile in self._profiles.items()
                },
                routes={
                    task_type.value: route.model_copy(deep=True)
                    for task_type, route in self._routes.items()
                },
                redacted=True,
            )

    def _copy_profiles(self) -> dict[str, ModelProfile]:
        return {
            profile_id: profile.model_copy(deep=True)
            for profile_id, profile in self._profiles.items()
        }

    def _copy_routes(self) -> dict[TaskType, TaskRoute]:
        return {
            task_type: route.model_copy(deep=True)
            for task_type, route in self._routes.items()
        }

    @staticmethod
    def _copy_profiles_from(profiles: dict[str, ModelProfile]) -> dict[str, ModelProfile]:
        return {
            profile_id: profile.model_copy(deep=True)
            for profile_id, profile in profiles.items()
        }

    @staticmethod
    def _copy_routes_from(routes: dict[TaskType, TaskRoute]) -> dict[TaskType, TaskRoute]:
        return {
            task_type: route.model_copy(deep=True)
            for task_type, route in routes.items()
        }

    def _record_audit(self, event_type: str, actor: Any | None, version: str) -> None:
        self._audit_events.append(
            AuditEvent(
                event_id=f"audit-{uuid4().hex}",
                case_id="config",
                trace_id=f"config-{uuid4().hex}",
                event_type=event_type,
                occurred_at=datetime.now(UTC),
                actor=actor,
                configuration_versions={"registry_version": version},
            )
        )

    def _persist_snapshot(self) -> None:
        """Persist only non-secret fields of the published snapshot."""
        self._runtime_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": str(self._version),
            "redacted": True,
            "secrets_stored": "refs_only",
            "profiles": {
                profile_id: profile.model_dump(mode="json")
                for profile_id, profile in self._profiles.items()
            },
            "routes": {
                task_type.value: route.model_dump(mode="json")
                for task_type, route in self._routes.items()
            },
        }
        descriptor, temp_name = tempfile.mkstemp(
            prefix=f".{self._runtime_path.name}.",
            suffix=".tmp",
            dir=self._runtime_path.parent,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self._runtime_path)
        except BaseException:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise

    def resolve(
        self,
        task_type: TaskType | str,
        modality: str | None = None,
        data_class: str | None = None,
        region: str | None = None,
    ) -> ResolvedRoute:
        with self._lock:
            router = TaskRouter(
                self._profiles,
                self._routes,
                published_profile_ids=set(self._profiles),
            )
            resolved = router.resolve(task_type, modality, data_class, region)
            resolved.primary_profile = resolved.primary_profile.model_copy(deep=True)
            resolved.fallback_profiles = [
                profile.model_copy(deep=True) for profile in resolved.fallback_profiles
            ]
            return resolved


__all__ = [
    "DraftValidationError",
    "ModelRegistry",
    "RegistrySnapshot",
    "ResolvedRoute",
    "RouteValidationError",
    "TaskRouter",
]
