"""Regression tests over the golden-set evaluation report.

The ``eval_report`` session fixture runs every golden case through the public
``run_check_case`` service in ``LLM_MODE=mock`` (fully offline and
deterministic) and returns the computed release-gate report. These tests treat
the report as the single source of truth for the safety gates, so any future
change that weakens a gate is caught here.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_RUN_EVAL_PATH = Path(__file__).resolve().parent / "run_eval.py"


def _load_run_eval():
    """Load run_eval.py by path so it works under any pytest import mode."""
    spec = importlib.util.spec_from_file_location("compliance_guard_eval_run", _RUN_EVAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def eval_report(tmp_path_factory):
    """Run the full golden set in mock mode and return the release-gate report."""
    run_eval = _load_run_eval()
    report_path = tmp_path_factory.mktemp("eval") / "eval-report.json"
    return run_eval.build_eval_report(output=report_path, mode="mock")


def test_regression_gate_has_zero_dangerous_false_allows(eval_report):
    assert eval_report["dangerous_false_allows"] == 0


def test_regression_report_records_versions(eval_report):
    assert eval_report["policy_version"]
    assert eval_report["knowledge_snapshot_id"]
    assert eval_report["route_version"]


def test_regression_release_gate_passes(eval_report):
    assert eval_report["release_gate"] == "pass"


def test_regression_every_gate_check_passes(eval_report):
    for name, passed in eval_report["gate_checks"].items():
        assert passed, f"gate {name} failed"


def test_regression_all_golden_cases_match_expected(eval_report):
    assert eval_report["matched_cases"] == eval_report["total_cases"]


def test_regression_each_category_matches(eval_report):
    for category, summary in eval_report["categories"].items():
        assert summary["failed"] == 0, f"category {category} had mismatches"


def test_regression_high_risk_evidence_or_gap_covered(eval_report):
    assert eval_report["evidence_coverage"]["uncovered"] == 0


def test_regression_cross_version_evidence_never_released(eval_report):
    assert eval_report["cross_version_releases"] == 0
    assert eval_report["cross_version_release_cases"] == []


def test_regression_known_injections_blocked(eval_report):
    assert eval_report["injection_cases"] > 0
    assert eval_report["injection_not_allowed"] is True


def test_regression_permission_denial_cases_honored(eval_report):
    assert eval_report["permission_denial_cases"] > 0
    assert eval_report["permission_denied_honored"] is True


def test_regression_audit_spans_complete(eval_report):
    assert eval_report["audit_incomplete_cases"] == 0


def test_regression_report_is_written(eval_report, tmp_path_factory):
    report_path = tmp_path_factory.mktemp("eval-write") / "nested" / "eval-report.json"
    run_eval = _load_run_eval()
    run_eval.build_eval_report(output=report_path, mode="mock")
    assert report_path.exists()


def test_regression_masking_preserves_redline_keyword(eval_report):
    """G-44 pins the D-1 fix: masking no longer eats the keyword next to a title.

    The case used to be blocked only incidentally, through the PII finding,
    because the name regex replaced "礼品给医生" as one span. Detection now happens
    on intact text, so the bribery rule is what blocks it.
    """
    row = next(r for r in eval_report["results"] if r["case_id"] == "G-44")
    assert row["matched"] is True
    assert row["actual_decision"] == "blocked"
    assert "bribery_or_inducement" in row["actual_finding_types"]


def test_regression_label_dose_conflict_baseline(eval_report):
    row = next(r for r in eval_report["results"] if r["case_id"] == "G-43")
    assert row["matched"] is True
    assert row["actual_decision"] == "human_review"
    assert "evidence_conflict" in row["actual_finding_types"]


# ---------------------------------------------------------------------------
# L3: the gates added by this iteration must be able to block a release
# ---------------------------------------------------------------------------


def test_release_gate_includes_masking_and_resolution(eval_report):
    """Masking recall and source fidelity are compliance floors, so they gate.

    Measuring a floor without wiring it to the gate means a regression ships and
    is discovered in the report afterwards.
    """
    for gate in ("gate_masking_recall", "gate_source_fidelity", "gate_wrong_merge_rate"):
        assert gate in eval_report["gate_checks"], f"{gate} is measured but does not gate"


def test_release_gate_includes_the_precheck_latency_slo(eval_report):
    """The typing path only works if it stays inside its budget."""
    assert "gate_l1_latency" in eval_report["gate_checks"]
    assert eval_report["l1_p95_ms"] >= 0
    assert eval_report["l1_budget_ms"] == 300


def test_precheck_latency_is_within_budget(eval_report):
    assert eval_report["l1_p95_ms"] < eval_report["l1_budget_ms"]


def test_resolution_metrics_are_reported_with_denominators(eval_report):
    resolution = eval_report["entity_resolution"]
    for metric in ("masking_recall", "source_fidelity", "coreference_accuracy"):
        assert resolution[metric]["denominator"] > 0, f"{metric} has no denominator"


def test_masking_recall_is_exactly_one_in_the_release_report(eval_report):
    assert eval_report["entity_resolution"]["masking_recall"]["rate"] == 1.0


def test_source_fidelity_is_exactly_one_in_the_release_report(eval_report):
    assert eval_report["entity_resolution"]["source_fidelity"]["rate"] == 1.0


def test_glossary_covers_every_finding_type_the_gate_can_produce(eval_report):
    """A rule with no plain-language wording would surface as a bare code."""
    assert eval_report["gate_checks"]["gate_glossary_coverage"] is True
    assert eval_report["glossary_missing_terms"] == []
