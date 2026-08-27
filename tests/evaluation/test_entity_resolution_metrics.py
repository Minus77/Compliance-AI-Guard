"""B4: masking and resolution metrics are measured, with denominators reported.

Percentages without denominators mislead, so every metric here is asserted as
numerator/denominator. Two of these are compliance floors with no tolerance:
masking recall and source fidelity must be exactly 1.0.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_RUN_EVAL_PATH = Path(__file__).resolve().parent / "run_eval.py"


def _load_run_eval():
    spec = importlib.util.spec_from_file_location("compliance_guard_eval_coref", _RUN_EVAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def resolution_report():
    run_eval = _load_run_eval()
    return run_eval.build_resolution_report()


def test_masking_recall_is_exactly_one(resolution_report):
    """Compliance floor: every identifier that must be masked, is masked."""
    recall = resolution_report["masking_recall"]
    assert recall["denominator"] > 0
    assert recall["numerator"] == recall["denominator"]
    assert recall["rate"] == 1.0


def test_source_fidelity_is_exactly_one(resolution_report):
    """Compliance floor: masking never damages non-identifier text (D-1)."""
    fidelity = resolution_report["source_fidelity"]
    assert fidelity["denominator"] > 0
    assert fidelity["numerator"] == fidelity["denominator"]
    assert fidelity["rate"] == 1.0


def test_coreference_accuracy_meets_target(resolution_report):
    accuracy = resolution_report["coreference_accuracy"]
    assert accuracy["denominator"] >= 10
    assert accuracy["rate"] >= 0.95


def test_wrong_merge_rate_is_within_tolerance(resolution_report):
    """Merging two people is worse than failing to merge one, so this is tight."""
    wrong_merge = resolution_report["wrong_merge_rate"]
    assert wrong_merge["denominator"] > 0
    assert wrong_merge["rate"] <= 0.01


def test_false_positive_masking_is_reported(resolution_report):
    """Over-masking degrades usability, so it is measured rather than ignored."""
    false_positive = resolution_report["false_positive_masking"]
    assert false_positive["denominator"] > 0
    assert false_positive["numerator"] == 0


def test_ambiguity_is_detected_where_expected(resolution_report):
    ambiguity = resolution_report["ambiguity_detection"]
    assert ambiguity["denominator"] > 0
    assert ambiguity["numerator"] == ambiguity["denominator"]


def test_report_lists_per_case_rows_for_audit(resolution_report):
    rows = resolution_report["results"]
    assert len(rows) == resolution_report["total_cases"]
    for row in rows:
        assert row["case_id"]
        assert "masked_all_required" in row
        assert "preserved_context" in row


def test_resolution_gate_passes(resolution_report):
    assert resolution_report["gate"] == "pass", resolution_report["gate_reasons"]
