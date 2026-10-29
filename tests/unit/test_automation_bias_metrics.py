"""C4: measure whether human oversight is actually happening.

EU AI Act Art.14(4)(b) asks that overseers stay aware of the tendency to
over-rely on automated output. That cannot be asserted in a design document; it
has to be observable. The signal used here is the rate at which reviewers depart
from the system's proposed decision.

The unusual part is the direction of the alarm: a *low* override rate is the
warning. If reviewers essentially never disagree, the likely explanation is
rubber-stamping rather than a flawless system, and the tool should say so instead
of quietly reporting a comfortable number.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from compliance_guard.audit.metrics import Metrics, OversightSummary


def _record(metrics: Metrics, *, upheld: int, overridden: int) -> None:
    for _ in range(upheld):
        metrics.record_review_outcome(overridden=False)
    for _ in range(overridden):
        metrics.record_review_outcome(overridden=True)


def test_override_rate_counts_departures_from_the_system_decision():
    metrics = Metrics()
    _record(metrics, upheld=8, overridden=2)
    summary = metrics.oversight_summary()
    assert summary.reviews == 10
    assert summary.overrides == 2
    assert summary.override_rate == 0.2


def test_no_reviews_yet_is_not_reported_as_a_problem():
    """An empty queue is not evidence of rubber-stamping."""
    summary = Metrics().oversight_summary()
    assert summary.reviews == 0
    assert summary.override_rate is None
    assert summary.status == "insufficient_data"


def test_low_override_rate_raises_a_rubber_stamp_warning():
    metrics = Metrics()
    _record(metrics, upheld=200, overridden=1)
    summary = metrics.oversight_summary()
    assert summary.status == "warning"
    assert "流于形式" in summary.message or "rubber" in summary.message.casefold()


def test_healthy_override_rate_reports_healthy():
    metrics = Metrics()
    _record(metrics, upheld=85, overridden=15)
    summary = metrics.oversight_summary()
    assert summary.status == "healthy"


def test_warning_needs_a_meaningful_sample_first():
    """Two reviews with no override must not trigger an alarm."""
    metrics = Metrics()
    _record(metrics, upheld=2, overridden=0)
    summary = metrics.oversight_summary()
    assert summary.status == "insufficient_data"


def test_message_is_plain_language_not_a_metric_name():
    metrics = Metrics()
    _record(metrics, upheld=200, overridden=1)
    summary = metrics.oversight_summary()
    assert summary.message
    assert "human_override_rate" not in summary.message


def test_summary_states_its_denominator():
    metrics = Metrics()
    _record(metrics, upheld=30, overridden=5)
    payload = metrics.oversight_summary().model_dump()
    assert payload["reviews"] == 35
    assert payload["overrides"] == 5


def test_counters_are_exposed_in_the_snapshot_for_the_dashboard():
    metrics = Metrics()
    _record(metrics, upheld=3, overridden=1)
    counters = metrics.snapshot().counters
    assert counters["review_outcomes.total"] == 4
    assert counters["review_outcomes.overridden"] == 1


def test_summary_is_a_typed_model():
    assert isinstance(Metrics().oversight_summary(), OversightSummary)


def test_concurrent_updates_are_not_lost():
    metrics = Metrics()
    workers = 8
    per_worker = 100
    start = threading.Barrier(workers)

    def record(_):
        start.wait()
        for _ in range(per_worker):
            metrics.increment("requests")
            metrics.record_review_outcome(overridden=False)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(record, range(workers)))

    counters = metrics.snapshot().counters
    assert counters["requests"] == workers * per_worker
    assert counters["review_outcomes.total"] == workers * per_worker
