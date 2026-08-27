"""Deterministic gateway boundary for model calls.

Task 5 wires registry-selected routes into the gateway: when a :class:`ResolvedRoute`
is supplied, ``complete`` selects the primary profile and, on failure, tries only
published fallback profiles. Every result records ``profile_id``, ``model_id``,
``route_version``, ``fallback_used``, latency, and error category. Mock mode stays
fully offline and is the default.

``LLM_MODE=live`` swaps the offline fixture adapter for
:class:`~compliance_guard.llm.live_adapter.LiveHttpAdapter`, which calls a real
OpenAI-compatible provider. The gateway itself is unchanged by that switch: it
still makes no compliance decision, still records the same provenance fields,
and still treats any adapter error as a fail-safe signal for the orchestrator.
The route/fallback logic is shared, so a live primary that errors falls back to
the published secondary profile exactly like a mock one.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from .adapters import MockAdapter
from .types import ModelConstraints, ModelRequest, RawModelResult

# Mode names accepted by the gateway. Anything else fails safe rather than
# silently choosing a provider.
MOCK_MODE = "mock"
LIVE_MODE = "live"

if TYPE_CHECKING:
    from .registry import ResolvedRoute


class ModelGateway:
    """Route requests to the configured adapter without making policy decisions."""

    def __init__(
        self,
        response_dir: str | Path | None = None,
        mock_adapter: MockAdapter | None = None,
        live_adapter: Any | None = None,
        prompts_dir: str | Path | None = None,
    ) -> None:
        self._mock_adapter = mock_adapter or MockAdapter(response_dir=response_dir)
        self._live_adapter = live_adapter
        self._prompts_dir = prompts_dir

    def _resolve_live_adapter(self) -> Any:
        """Build the live adapter lazily so mock mode never imports httpx paths."""
        if self._live_adapter is None:
            from .live_adapter import LiveHttpAdapter

            self._live_adapter = LiveHttpAdapter(prompts_dir=self._prompts_dir)
        return self._live_adapter

    def complete(
        self,
        task_type: str,
        request: ModelRequest,
        constraints: ModelConstraints,
        route: "ResolvedRoute | None" = None,
    ) -> RawModelResult:
        if route is not None:
            return self._complete_with_route(task_type, request, constraints, route)
        return self._complete_single(task_type, request, constraints)

    def _complete_with_route(
        self,
        task_type: str,
        request: ModelRequest,
        constraints: ModelConstraints,
        route: "ResolvedRoute",
    ) -> RawModelResult:
        profiles = [route.primary_profile, *route.fallback_profiles]
        last_result: RawModelResult | None = None
        for index, profile in enumerate(profiles):
            profile_constraints = self._constraints_for_profile(constraints, profile, route)
            result = self._complete_single(task_type, request, profile_constraints)
            if result.error_category is None:
                result.fallback_used = index > 0
                return result
            last_result = result
        if last_result is None:
            last_result = RawModelResult(
                provider=route.primary_profile.provider,
                model_id=route.primary_profile.model_id,
                profile_id=route.primary_profile.profile_id,
                route_version=route.route_version,
                raw_json={},
                latency_ms=0,
                input_tokens=0,
                output_tokens=0,
                fallback_used=False,
                error_category="model_unavailable",
            )
        last_result.fallback_used = len(profiles) > 1
        return last_result

    @staticmethod
    def _constraints_for_profile(
        base: ModelConstraints,
        profile,
        route: "ResolvedRoute",
    ) -> ModelConstraints:
        return ModelConstraints(
            mode=base.mode,
            profile_id=profile.profile_id,
            model_id=profile.model_id,
            route_version=route.route_version,
            timeout_ms=profile.timeout_ms,
            token_budget=profile.token_budget,
            data_class=base.data_class or route.data_class,
            region=base.region or route.region,
            allowed_data_classes=[item.value for item in profile.allowed_data_classes],
            allowed_regions=[route.region] if route.region else [],
        )

    def _complete_single(
        self,
        task_type: str,
        request: ModelRequest,
        constraints: ModelConstraints,
    ) -> RawModelResult:
        if constraints.mode == MOCK_MODE:
            return self._mock_adapter.complete(task_type, request, constraints)

        if constraints.mode == LIVE_MODE:
            return self._resolve_live_adapter().complete(task_type, request, constraints)

        return RawModelResult(
            provider="gateway",
            model_id=constraints.model_id,
            profile_id=constraints.profile_id,
            route_version=constraints.route_version,
            raw_json={},
            latency_ms=0,
            input_tokens=0,
            output_tokens=0,
            fallback_used=False,
            error_category="model_mode_unsupported",
        )
