import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from compliance_guard.llm.types import ModelConstraints, ModelRequest


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_mock_mode_never_calls_network(monkeypatch, mock_gateway):
    def fail_network(*args, **kwargs):
        raise AssertionError("mock mode must not open a network socket")

    monkeypatch.setattr(socket, "socket", fail_network)
    monkeypatch.setattr(socket, "create_connection", fail_network)

    result = mock_gateway.complete(
        task_type="routine_compliance",
        request=ModelRequest(scenario="normal", content="synthetic content"),
        constraints=ModelConstraints(mode="mock"),
    )

    assert result.error_category is None
    assert result.raw_json["scenario"] == "normal"
    assert result.provider == "mock"


def test_unknown_mock_scenario_fails_safe(mock_gateway):
    result = mock_gateway.complete(
        task_type="routine_compliance",
        request=ModelRequest(scenario="unknown", content="synthetic content"),
        constraints=ModelConstraints(mode="mock"),
    )

    assert result.error_category == "mock_response_missing"
    assert result.raw_json == {}


def test_isolated_package_source_loads_mock_fixture_and_preserves_constraints(
    tmp_path,
):
    shutil.copytree(
        PROJECT_ROOT / "src" / "compliance_guard",
        tmp_path / "compliance_guard",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    assert not (tmp_path / "data").exists()

    environment = os.environ.copy()
    environment.pop("LLM_MODE", None)
    environment["PYTHONPATH"] = str(tmp_path)
    smoke = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from compliance_guard.llm.gateway import ModelGateway; "
                "from compliance_guard.llm.types import ModelConstraints, ModelRequest; "
                "constraints = ModelConstraints(profile_id='routine-profile', "
                "model_id='opaque-model'); "
                "assert constraints.mode == 'mock'; "
                "result = ModelGateway().complete("
                "'routine_compliance', "
                "ModelRequest(scenario='normal', content='synthetic content'), "
                "constraints); "
                "assert result.error_category is None, result.error_category; "
                "assert result.raw_json['scenario'] == 'normal'; "
                "assert result.profile_id == 'routine-profile'; "
                "assert result.model_id == 'opaque-model'; "
                "print(result.raw_json['scenario'])"
            ),
        ],
        capture_output=True,
        check=False,
        cwd=tmp_path,
        env=environment,
        text=True,
    )

    assert smoke.returncode == 0, smoke.stdout + smoke.stderr
    assert smoke.stdout.strip() == "normal"


def test_top_level_and_packaged_mock_fixtures_match():
    source_dir = PROJECT_ROOT / "data" / "mock_responses"
    package_dir = (
        PROJECT_ROOT / "src" / "compliance_guard" / "llm" / "mock_responses"
    )
    expected_names = {
        "normal.json",
        "ae.json",
        "pii.json",
        "off_label.json",
        "redline.json",
        "injection.json",
    }
    source_fixtures = {
        path.name: path.read_bytes() for path in source_dir.glob("*.json")
    }
    package_fixtures = {
        path.name: path.read_bytes() for path in package_dir.glob("*.json")
    }

    assert set(source_fixtures) == expected_names
    assert package_fixtures == source_fixtures
