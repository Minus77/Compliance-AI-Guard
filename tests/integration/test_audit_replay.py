"""Append-only audit ledger, correlated tracing, metrics, and snapshot replay."""

import re

import pytest

from compliance_guard.domain.enums import CaseState

_PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def test_replay_uses_recorded_snapshot(app_services, sample_request):
    original = app_services.orchestrator.run_check_case(sample_request("off_label"))
    replay = app_services.orchestrator.replay_case(
        original.case_id, original.knowledge_snapshot_id, original.policy_version
    )
    assert replay.case_id == original.case_id
    assert replay.policy_version == original.policy_version
    assert replay.knowledge_snapshot_id == original.knowledge_snapshot_id


def test_replay_does_not_write_externally(app_services, sample_request):
    original = app_services.orchestrator.run_check_case(sample_request("off_label"))
    ledger_before = app_services.ledger.count()
    model_calls_before = app_services.metrics.snapshot().counters.get("model_calls", 0)
    replay = app_services.orchestrator.replay_case(
        original.case_id, original.knowledge_snapshot_id, original.policy_version
    )
    assert replay.consistent is True
    assert app_services.ledger.count() == ledger_before
    assert app_services.metrics.snapshot().counters.get("model_calls", 0) == model_calls_before


def test_ledger_records_state_transitions_with_trace(app_services, sample_request):
    response = app_services.orchestrator.run_check_case(sample_request("ae"))
    events = app_services.ledger.for_case(response.case_id)
    assert len(events) >= 10
    for event in events:
        assert event.case_id == response.case_id
        assert event.trace_id == response.trace_id
    transitions = [
        event for event in events
        if event.event_type.startswith("transition.") and event.from_state and event.to_state
    ]
    assert transitions
    assert events[-1].event_type == "transition.COMPLETED"


def test_ledger_records_model_call_and_evidence(app_services, sample_request):
    response = app_services.orchestrator.run_check_case(sample_request("off_label"))
    events = app_services.ledger.for_case(response.case_id)
    assert any(event.event_type == "model_call" for event in events)
    assert any(event.event_type == "evidence_retrieved" for event in events)
    evidence_event = next(event for event in events if event.event_type == "evidence_retrieved")
    assert evidence_event.payload["knowledge_snapshot_id"]
    assert evidence_event.payload["evidence_ids"]


def test_metrics_snapshot_has_counts_without_raw_pii(app_services, sample_request):
    response = app_services.orchestrator.run_check_case(sample_request("pii"))
    app_services.orchestrator.run_check_case(sample_request("normal"))
    snap = app_services.metrics.snapshot()
    assert snap.redacted is True
    assert snap.counters["cases_received"] == 2
    assert snap.counters["cases_completed"] == 2
    assert snap.counters["model_calls"] == 2
    assert snap.counters[f"decisions.{response.decision.value}"] >= 1
    # Scan the metric *payload*, not the whole dump.
    #
    # `snapshot_id` is "metrics-<32 random hex>", and a random hex run matches the
    # Chinese mobile pattern 1[3-9]\d{9} about 0.16% of the time -- roughly one run
    # in 600. Scanning the identifier made this test fail intermittently for a
    # reason that has nothing to do with PII, which is the worst kind of test: it
    # trains you to re-run rather than to look.
    #
    # Counter names and gauge names are where a leak could actually appear, since
    # those are the only strings derived from case data.
    payload = snap.model_dump()
    scanned = str(
        {
            "counters": payload["counters"],
            "gauges": payload["gauges"],
        }
    )
    assert not _PHONE_RE.search(scanned)
    assert not _EMAIL_RE.search(scanned)
    # The identifier is machine-generated, so assert its shape instead.
    assert snap.snapshot_id.startswith("metrics-")


def test_trace_spans_are_correlated(app_services, sample_request):
    response = app_services.orchestrator.run_check_case(sample_request("normal"))
    spans = app_services.tracer.spans_for_trace(response.trace_id)
    assert spans
    for span in spans:
        assert span.trace_id == response.trace_id
        assert span.case_id == response.case_id
        assert span.operation
        assert span.ended_at is not None


def test_replay_unknown_case_raises(app_services):
    with pytest.raises(KeyError):
        app_services.orchestrator.replay_case("CASE-NOPE", "snap-x", "CN-COMPLIANCE-2026-01")


def test_replay_reproduces_recorded_snapshot_id(app_services, sample_request):
    original = app_services.orchestrator.run_check_case(sample_request("ae"))
    replay = app_services.orchestrator.replay_case(
        original.case_id, original.knowledge_snapshot_id, original.policy_version
    )
    assert replay.consistent is True
    assert replay.input_hash
    assert replay.route_version == original.route_version
    assert replay.model_profile_id == original.model_profile_id
    assert replay.prompt_version == original.prompt_version
