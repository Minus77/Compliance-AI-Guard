"""Deterministic task-to-profile routing against a published registry."""

from __future__ import annotations

from pydantic import Field

from compliance_guard.domain.enums import DataClass, Modality, TaskType
from compliance_guard.domain.models import DomainModel, ModelProfile, TaskRoute


class RouteValidationError(RuntimeError):
    """Raised when a task cannot be resolved against published profiles and routes."""


class ResolvedRoute(DomainModel):
    """The deterministic, published route selected for one task invocation."""

    task_type: TaskType
    route_version: str
    primary_profile: ModelProfile
    fallback_profiles: list[ModelProfile] = Field(default_factory=list)
    requires_human_on_failure: bool = True
    modality: str | None = None
    data_class: str | None = None
    region: str | None = None


def _capabilities_for_modality(modality: str | None) -> set[Modality]:
    if modality is None:
        return set()
    value = str(modality).casefold()
    if value in ("image", "image_ref"):
        return {Modality.VISION}
    if value in ("audio", "audio_ref"):
        return {Modality.AUDIO}
    if value in ("text", "text_ref"):
        return {Modality.TEXT}
    return set()


class TaskRouter:
    """Deterministic resolution of a task to published, compatible profiles."""

    def __init__(
        self,
        profiles: dict[str, ModelProfile],
        routes: dict[TaskType, TaskRoute],
        published_profile_ids: set[str] | None = None,
    ) -> None:
        self._profiles = profiles
        self._routes = routes
        self._published_profile_ids = published_profile_ids or set(profiles)

    def resolve(
        self,
        task_type: TaskType | str,
        modality: str | None = None,
        data_class: str | None = None,
        region: str | None = None,
    ) -> ResolvedRoute:
        try:
            task = TaskType(task_type)
        except (TypeError, ValueError):
            raise RouteValidationError(f"unknown task type {task_type!r}") from None

        route = self._routes.get(task)
        if route is None:
            raise RouteValidationError(f"no published route for task type {task.value!r}")

        primary = self._profiles.get(route.primary_profile_id)
        if primary is None or primary.profile_id not in self._published_profile_ids:
            raise RouteValidationError(
                f"primary profile {route.primary_profile_id!r} is not published for {task.value!r}"
            )
        if not primary.enabled:
            raise RouteValidationError(f"primary profile {primary.profile_id!r} is disabled")

        required_capabilities = set(route.required_capabilities)
        required_capabilities |= _capabilities_for_modality(modality)
        if not required_capabilities <= set(primary.capabilities):
            raise RouteValidationError(
                f"profile {primary.profile_id!r} lacks required capabilities for {task.value!r}"
            )

        if region not in route.allowed_regions:
            raise RouteValidationError(
                f"region {region!r} is not allowed for task {task.value!r} (allowed {[r for r in route.allowed_regions]})"
            )

        if data_class is None:
            raise RouteValidationError(f"data_class is required for task {task.value!r}")
        try:
            data_class_enum = DataClass(data_class)
        except (TypeError, ValueError):
            raise RouteValidationError(f"unknown data class {data_class!r}") from None
        if data_class_enum not in route.allowed_data_classes:
            raise RouteValidationError(
                f"data class {data_class_enum.value!r} is not allowed for task {task.value!r}"
            )
        if data_class_enum not in primary.allowed_data_classes:
            raise RouteValidationError(
                f"profile {primary.profile_id!r} does not accept data class {data_class_enum.value!r}"
            )

        fallbacks: list[ModelProfile] = []
        for fallback_id in route.fallback_profile_ids:
            fallback = self._profiles.get(fallback_id)
            if fallback is None or fallback.profile_id not in self._published_profile_ids:
                raise RouteValidationError(
                    f"fallback profile {fallback_id!r} is not published for {task.value!r}"
                )
            if not fallback.enabled:
                raise RouteValidationError(f"fallback profile {fallback_id!r} is disabled")
            if not required_capabilities <= set(fallback.capabilities):
                raise RouteValidationError(
                    f"fallback profile {fallback_id!r} lacks required capabilities for {task.value!r}"
                )
            if data_class_enum not in fallback.allowed_data_classes:
                raise RouteValidationError(
                    f"fallback profile {fallback_id!r} does not accept data class {data_class_enum.value!r}"
                )
            fallbacks.append(fallback)

        return ResolvedRoute(
            task_type=task,
            route_version=route.route_version,
            primary_profile=primary,
            fallback_profiles=fallbacks,
            requires_human_on_failure=route.requires_human_on_failure,
            modality=str(modality) if modality is not None else None,
            data_class=data_class_enum.value,
            region=region,
        )
