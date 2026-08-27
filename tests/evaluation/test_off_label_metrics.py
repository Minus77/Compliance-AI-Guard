"""D6 + E4: off-label accuracy and the L2 budget must be measured, not asserted.

The plan names three off-label metrics and an L2 latency SLO. Both were implemented
as behaviour and neither reached the report, which is the failure mode this project
keeps guarding against: a property that is claimed in prose but never measured is a
property that regresses silently.

Precision and recall are reported separately on purpose. A single accuracy number
would let a change that stops detecting off-label content look like an improvement,
because most cases are not off-label -- the class imbalance hides exactly the
regression that matters.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_RUN_EVAL_PATH = Path(__file__).resolve().parent / "run_eval.py"


def _load_run_eval():
    spec = importlib.util.spec_from_file_location("cg_eval_offlabel", _RUN_EVAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def report():
    run_eval = _load_run_eval()
    return run_eval.build_eval_report(mode="mock")


# -- D6: off-label accuracy -------------------------------------------------


def test_off_label_precision_is_reported_with_its_denominator(report):
    metric = report["off_label"]["precision"]
    assert metric["denominator"] > 0
    assert 0.0 <= metric["rate"] <= 1.0


def test_off_label_recall_is_reported_with_its_denominator(report):
    metric = report["off_label"]["recall"]
    assert metric["denominator"] > 0


def test_precision_and_recall_are_separate(report):
    """One combined number would let a detection regression look like a win."""
    off_label = report["off_label"]
    assert "precision" in off_label
    assert "recall" in off_label
    assert off_label["precision"] is not off_label["recall"]


def test_unresolved_rate_is_reported(report):
    """Rising unresolved means the ontology is falling behind the vocabulary."""
    metric = report["off_label"]["unresolved_rate"]
    assert metric["denominator"] > 0


def test_off_label_recall_meets_the_target(report):
    """A missed off-label claim is the expensive direction of this error."""
    assert report["off_label"]["recall"]["rate"] >= 0.9


def test_off_label_precision_meets_the_target(report):
    assert report["off_label"]["precision"]["rate"] >= 0.9


def test_off_label_accuracy_is_a_release_gate(report):
    assert "gate_off_label_accuracy" in report["gate_checks"]


def test_the_gate_passes(report):
    assert report["gate_checks"]["gate_off_label_accuracy"] is True


# -- E4: the L2 budget ------------------------------------------------------


def test_l2_latency_is_reported(report):
    assert report["l2_p95_ms"] >= 0
    assert report["l2_budget_ms"] == 3000


def test_l2_latency_is_a_release_gate(report):
    assert "gate_l2_latency" in report["gate_checks"]


def test_l2_measurement_states_which_mode_produced_it(report):
    """A 2ms mock figure must not be mistaken for a live provider result."""
    assert report["l2_latency_mode"] in {"mock", "live"}


def test_both_layer_budgets_are_present(report):
    for key in ("l1_p95_ms", "l1_budget_ms", "l2_p95_ms", "l2_budget_ms"):
        assert key in report
