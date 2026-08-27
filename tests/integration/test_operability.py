"""K: the parts of "works out of the box" that are invisible until they fail.

Three specific failure modes this closes:

* **K1 liveness vs readiness.** One ``/health`` conflates "the process is up" with
  "the process can actually answer". A load balancer needs the first; an operator
  deciding whether to send traffic needs the second, per dependency.
* **K3 configuration validated at startup.** A malformed policy bundle used to be
  discovered by the first request that needed it — which means the first *user*
  discovers it, in the middle of writing something. Validation moves to boot, and
  a bad configuration refuses to start with a readable reason.
* **K2 logs that cannot leak.** A request id runs through the logs so one case can
  be followed, and log payloads pass the same DLP scanner as model output. A log
  file is the easiest place for a name to end up by accident.
"""

from __future__ import annotations

import json

import pytest


# -- K1: graded health ------------------------------------------------------


def test_liveness_answers_without_touching_dependencies(client):
    body = client.get("/health/live").json()
    assert body["status"] == "ok"
    assert "dependencies" not in body


def test_readiness_reports_each_dependency(client):
    body = client.get("/health/ready").json()
    assert body["ready"] is True
    names = {item["name"] for item in body["dependencies"]}
    for expected in ("policy_bundle", "label_facts", "indication_ontology", "glossary", "model_routes"):
        assert expected in names


def test_readiness_reports_versions_for_each_dependency(client):
    body = client.get("/health/ready").json()
    for item in body["dependencies"]:
        assert item["ok"] is True
        assert item["version"], f"{item['name']} reports no version"


def test_legacy_health_still_answers(client):
    """Existing callers and the mode badge must not break."""
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["mode"]


def test_readiness_never_exposes_a_credential(client):
    body = json.dumps(client.get("/health/ready").json())
    assert "api_key" not in body.casefold()
    assert "sk-" not in body


# -- K3: configuration validated before serving -----------------------------


def test_config_validation_passes_for_the_shipped_configuration():
    from compliance_guard.runtime_config import validate_configuration

    report = validate_configuration()
    assert report.ok is True, report.problems
    assert report.checked


def test_malformed_policy_bundle_is_rejected_with_a_readable_reason(tmp_path):
    from compliance_guard.runtime_config import validate_configuration

    broken = tmp_path / "policies"
    broken.mkdir()
    (broken / "cn-demo.json").write_text("{ not json", encoding="utf-8")
    report = validate_configuration(config_dir=tmp_path)
    assert report.ok is False
    assert report.problems
    joined = " ".join(report.problems)
    assert "cn-demo" in joined or "policy" in joined.casefold()


def test_validation_names_the_file_that_is_wrong(tmp_path):
    from compliance_guard.runtime_config import validate_configuration

    report = validate_configuration(config_dir=tmp_path)
    assert report.ok is False
    # An operator needs to know which file to open, not that "config is invalid".
    assert any(".json" in problem for problem in report.problems)


def test_expired_policy_bundle_is_reported(tmp_path):
    """A bundle whose validity window has closed must not silently keep deciding."""
    from compliance_guard.runtime_config import validate_configuration
    from compliance_guard.runtime_paths import config_dir as real_config_dir

    source = json.loads((real_config_dir() / "policies" / "cn-demo.json").read_text(encoding="utf-8"))
    source["effective_until"] = "2020-01-01T00:00:00Z"
    target = tmp_path / "policies"
    target.mkdir()
    (target / "cn-demo.json").write_text(json.dumps(source, ensure_ascii=False), encoding="utf-8")
    # Copy the rest of the configuration so only the bundle is at fault.
    report = validate_configuration(config_dir=tmp_path)
    assert report.ok is False
    assert any("effective" in problem.casefold() or "expired" in problem.casefold()
               for problem in report.problems)


def test_startup_refuses_a_broken_configuration(tmp_path, monkeypatch):
    """Fail at boot, not on the first request that happens to need the file."""
    from compliance_guard.runtime_config import ConfigurationError, require_valid_configuration

    with pytest.raises(ConfigurationError) as excinfo:
        require_valid_configuration(config_dir=tmp_path)
    assert "json" in str(excinfo.value).casefold()


# -- K2: structured logging -------------------------------------------------


def test_request_id_is_returned_so_a_case_can_be_followed(client):
    response = client.get("/health/live")
    assert response.headers.get("x-request-id")


def test_supplied_request_id_is_preserved(client):
    response = client.get("/health/live", headers={"x-request-id": "trace-abc-123"})
    assert response.headers["x-request-id"] == "trace-abc-123"


def test_log_records_are_json_lines():
    from compliance_guard.observability import format_log_record

    line = format_log_record("case_checked", request_id="req-1", fields={"decision": "allow"})
    parsed = json.loads(line)
    assert parsed["event"] == "case_checked"
    assert parsed["request_id"] == "req-1"
    assert parsed["decision"] == "allow"
    assert parsed["timestamp"]


def test_log_payloads_are_scrubbed_of_identifiers():
    """A log file is the easiest place for a name to end up by accident."""
    from compliance_guard.observability import format_log_record

    line = format_log_record(
        "case_checked",
        request_id="req-1",
        fields={"note": "患者李四电话13800138000"},
    )
    assert "13800138000" not in line
    assert "李四" not in line
    assert "[redacted]" in line


def test_scrubbing_keeps_non_sensitive_values_intact():
    from compliance_guard.observability import format_log_record

    line = json.loads(format_log_record("x", request_id="r", fields={"count": 3, "decision": "blocked"}))
    assert line["count"] == 3
    assert line["decision"] == "blocked"


# -- K4: retention ----------------------------------------------------------


def test_retention_policy_is_declared_per_store():
    from compliance_guard.runtime_config import retention_policy

    policy = retention_policy()
    for store in ("precheck_log", "notification", "draft", "audit_ledger"):
        assert store in policy


def test_audit_ledger_is_never_auto_deleted():
    """Append-only means append-only: retention must exceed the business record."""
    from compliance_guard.runtime_config import retention_policy

    assert retention_policy()["audit_ledger"]["retain_days"] is None


def test_transient_stores_have_a_bounded_retention():
    from compliance_guard.runtime_config import retention_policy

    policy = retention_policy()
    for store in ("precheck_log", "notification", "draft"):
        assert isinstance(policy[store]["retain_days"], int)
        assert policy[store]["retain_days"] > 0


def test_retention_is_exposed_for_inspection(client):
    body = client.get("/health/ready").json()
    assert body["retention"]["audit_ledger"]["retain_days"] is None
