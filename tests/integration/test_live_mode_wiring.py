"""Wiring tests for live model mode.

These cover the seam between configuration and behaviour, which is where a
"real LLM" switch usually goes wrong:

* mock mode must stay completely offline, even with the live code present,
* live mode must actually select the live adapter (not silently stay on
  fixtures, which would fake a working integration),
* ``/health`` must tell the truth about readiness without leaking the key, and
* a live provider outage must degrade to human review, never to ``allow``.

No network socket is opened here: live behaviour is exercised with an injected
transport.
"""

from __future__ import annotations

import json
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from compliance_guard.llm.gateway import ModelGateway
from compliance_guard.llm.types import ModelConstraints, ModelRequest


def _client(monkeypatch, mode: str) -> TestClient:
    monkeypatch.setenv("LLM_MODE", mode)
    from apps.api import main

    return TestClient(main.create_app() if hasattr(main, "create_app") else main.app)


# -- mode selection ----------------------------------------------------------


def test_mock_mode_still_opens_no_socket(monkeypatch):
    """The live adapter existing must not make mock mode reach the network."""

    def fail_network(*args, **kwargs):
        raise AssertionError("mock mode must not open a network socket")

    monkeypatch.setattr(socket, "socket", fail_network)
    monkeypatch.setattr(socket, "create_connection", fail_network)

    result = ModelGateway().complete(
        task_type="routine_compliance",
        request=ModelRequest(scenario="normal", content="synthetic"),
        constraints=ModelConstraints(mode="mock"),
    )

    assert result.provider == "mock"
    assert result.error_category is None


def test_live_mode_selects_the_live_adapter():
    """Live mode must not fall through to offline fixtures."""
    calls: list[str] = []

    class Recorder:
        def complete(self, task_type, request, constraints):
            calls.append(task_type)
            from compliance_guard.llm.types import RawModelResult

            return RawModelResult(provider="live", raw_json={"summary": "ok"})

    result = ModelGateway(live_adapter=Recorder()).complete(
        task_type="routine_compliance",
        request=ModelRequest(scenario="normal", content="synthetic"),
        constraints=ModelConstraints(mode="live"),
    )

    assert calls == ["routine_compliance"]
    assert result.provider == "live"


def test_unknown_mode_fails_safe_instead_of_guessing_a_provider():
    result = ModelGateway().complete(
        task_type="routine_compliance",
        request=ModelRequest(scenario="normal", content="synthetic"),
        constraints=ModelConstraints(mode="staging"),
    )

    assert result.error_category == "model_mode_unsupported"
    assert result.raw_json == {}


# -- health reporting --------------------------------------------------------


def test_health_reports_offline_fixtures_in_mock_mode(monkeypatch):
    body = _client(monkeypatch, "mock").get("/health").json()

    assert body["mode"] == "mock"
    assert body["model_service"] == {
        "required": False,
        "ready": True,
        "reason": "offline_fixtures",
    }


def test_health_reports_live_readiness_without_leaking_the_key(monkeypatch):
    body = _client(monkeypatch, "live").get("/health").json()

    assert body["mode"] == "live"
    assert body["model_service"]["required"] is True
    serialized = json.dumps(body)
    assert "sk-" not in serialized
    assert "Bearer" not in serialized
    assert "api_key" not in serialized


def test_health_flags_missing_credential_in_live_mode(monkeypatch, tmp_path):
    """An unusable live setup must be visible, not silently degraded."""
    monkeypatch.setenv("COMPLIANCE_GUARD_LLM_SECRETS_FILE", str(tmp_path / "absent.json"))
    monkeypatch.delenv("COMPLIANCE_GUARD_LLM_API_KEY", raising=False)

    body = _client(monkeypatch, "live").get("/health").json()

    assert body["model_service"] == {
        "required": True,
        "ready": False,
        "reason": "missing_credential",
    }


# -- outage never becomes approval ------------------------------------------


@pytest.mark.parametrize("status", [401, 429, 500])
def test_provider_outage_never_yields_allow(status):
    """A dead provider must route to a human, not release content."""
    from compliance_guard.llm.live_adapter import LiveHttpAdapter

    def post(url, headers=None, json=None, timeout=None):  # noqa: A002
        return httpx.Response(status_code=status, json={"error": "down"})

    result = LiveHttpAdapter(post=post).complete(
        "routine_compliance",
        ModelRequest(scenario="normal", content="本品适用于成人原发性高血压的治疗。"),
        ModelConstraints(mode="live", profile_id="deepseek-routine"),
    )

    assert result.error_category is not None
    assert result.raw_json == {}
