"""Provider adapter contracts and the offline mock implementation."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Protocol

from .types import ModelConstraints, ModelRequest, RawModelResult


class ModelAdapter(Protocol):
    """Minimal adapter interface used by the model gateway."""

    def complete(
        self,
        task_type: str,
        request: ModelRequest,
        constraints: ModelConstraints,
    ) -> RawModelResult:
        """Return a normalized candidate result for one model request."""


class MockAdapter:
    """Load deterministic candidate responses from local JSON fixtures."""

    provider = "mock"

    def __init__(self, response_dir: str | Path | None = None) -> None:
        self.response_dir = Path(response_dir) if response_dir is not None else None

    def complete(
        self,
        task_type: str,
        request: ModelRequest,
        constraints: ModelConstraints,
    ) -> RawModelResult:
        del task_type
        fixture = self._read_fixture(request.scenario)
        if fixture is None:
            return self._result(
                constraints=constraints,
                raw_json={},
                error_category="mock_response_missing",
            )

        if fixture.get("scenario") != request.scenario:
            return self._result(
                constraints=constraints,
                raw_json={},
                error_category="mock_response_invalid",
            )

        return self._result(constraints=constraints, raw_json=fixture)

    def _read_fixture(self, scenario: str) -> dict[str, object] | None:
        scenario_path = Path(scenario)
        if not scenario or scenario in {".", ".."} or scenario_path.name != scenario:
            return None

        if self.response_dir is None:
            fixture_path = resources.files("compliance_guard.llm").joinpath(
                "mock_responses", f"{scenario}.json"
            )
        else:
            fixture_path = self.response_dir / f"{scenario}.json"

        if not fixture_path.is_file():
            return None

        try:
            with fixture_path.open(encoding="utf-8") as fixture_file:
                payload = json.load(fixture_file)
        except (OSError, json.JSONDecodeError):
            return None

        return payload if isinstance(payload, dict) else None

    def _result(
        self,
        *,
        constraints: ModelConstraints,
        raw_json: dict[str, object],
        error_category: str | None = None,
    ) -> RawModelResult:
        return RawModelResult(
            provider=self.provider,
            model_id=constraints.model_id,
            profile_id=constraints.profile_id,
            route_version=constraints.route_version,
            raw_json=raw_json,
            latency_ms=0,
            input_tokens=0,
            output_tokens=0,
            fallback_used=False,
            error_category=error_category,
        )
