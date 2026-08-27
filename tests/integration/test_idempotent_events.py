"""Idempotent event bus: duplicate detection, DLQ routing, and replay.

Covers the Task 7 event bus contract:
- duplicate events create exactly one case and one review task
- non-retryable schema/permission errors route to the dead letter queue
- retryable errors carry attempt count and next action
- DLQ replay succeeds without duplicating side effects
- audit events are recorded for bus actions
"""

from datetime import UTC, datetime

import pytest

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.integrations.event_bus import (
    EventBus,
    ExternalEvent,
    RetryableProcessingError,
)


@pytest.fixture
def sample_event() -> ExternalEvent:
    return ExternalEvent(
        event_id="EVT-001",
        tenant_id="TENANT-CN",
        record_id="SR-001",
        version="v3",
        event_type="call_report",
        source="veeva_vault",
        received_at=datetime(2026, 8, 20, tzinfo=UTC),
        payload={"market": "CN", "product_id": "PRODUCT-001"},
    )


@pytest.fixture
def event_bus() -> EventBus:
    return EventBus()


def test_duplicate_event_creates_one_case(event_bus, sample_event):
    first = event_bus.receive_event(sample_event)
    second = event_bus.receive_event(sample_event)
    assert first.case_id == second.case_id
    assert event_bus.created_case_count(sample_event.event_id) == 1


def test_duplicate_event_does_not_create_duplicate_review_tasks(event_bus, sample_event):
    first = event_bus.receive_event(sample_event)
    event_bus.receive_event(sample_event)
    tasks = event_bus.review_tasks_for_event(sample_event.event_id)
    assert len(tasks) == 1
    assert tasks[0].case_id == first.case_id
    assert event_bus.review_task_count(sample_event.event_id) == 1


def test_schema_error_goes_to_dead_letter_queue(event_bus):
    malformed = {
        "event_id": "EVT-BAD",
        "tenant_id": "TENANT-CN",
        "record_id": "SR-001",
        "version": "v3",
        "event_type": "call_report",
        "source": "veeva_vault",
        "received_at": datetime(2026, 8, 20, tzinfo=UTC),
        "surprise": "not-a-known-field",
    }
    result = event_bus.receive_event(malformed)
    assert result.case_id is None
    records = event_bus.read_dlq()
    assert len(records) == 1
    record = records[0]
    assert record.event_id == "EVT-BAD"
    assert record.retryable is False
    assert record.next_action == "manual_review"
    assert record.error_type == "SchemaError"
    assert event_bus.created_case_count("EVT-BAD") == 0


def test_permission_error_goes_to_dead_letter_queue(sample_event):
    def deny(normalized):
        raise PermissionError("write permission denied for tenant")

    bus = EventBus(handler=deny)
    result = bus.receive_event(sample_event)
    assert result.case_id is None
    records = bus.read_dlq()
    assert len(records) == 1
    assert records[0].retryable is False
    assert records[0].next_action == "manual_review"
    assert records[0].error_type == "PermissionError"


def test_retryable_error_carries_attempt_count_and_next_action(sample_event):
    calls = {"n": 0}

    def flaky(normalized):
        calls["n"] += 1
        if calls["n"] < 3:
            raise RetryableProcessingError("source temporarily unavailable")
        return f"CASE-{normalized.event_id}"

    bus = EventBus(handler=flaky)
    bus.receive_event(sample_event)
    bus.receive_event(sample_event)
    records = bus.read_dlq()
    assert len(records) == 1
    assert records[0].attempt_count == 2
    assert records[0].retryable is True
    assert records[0].next_action == "retry"

    result = bus.receive_event(sample_event)
    assert result.case_id == "CASE-EVT-001"
    assert bus.read_dlq() == []
    assert bus.created_case_count(sample_event.event_id) == 1


def test_retryable_attempts_exhaust_to_manual_review(sample_event):
    def always_fail(normalized):
        raise RetryableProcessingError("still unavailable")

    bus = EventBus(handler=always_fail, max_attempts=2)
    bus.receive_event(sample_event)
    bus.receive_event(sample_event)
    bus.receive_event(sample_event)
    records = bus.read_dlq()
    assert len(records) == 1
    assert records[0].attempt_count == 2
    assert records[0].next_action == "manual_review"


def test_dlq_replay_does_not_duplicate_side_effects(sample_event):
    state = {"fail": True}

    def flaky(normalized):
        if state["fail"]:
            raise RetryableProcessingError("transient outage")
        return f"CASE-{normalized.event_id}"

    bus = EventBus(handler=flaky)
    bus.receive_event(sample_event)
    assert bus.created_case_count(sample_event.event_id) == 0

    state["fail"] = False
    replayed = bus.replay_dlq()
    assert len(replayed) == 1
    assert replayed[0].case_id == "CASE-EVT-001"
    assert bus.read_dlq() == []
    assert bus.created_case_count(sample_event.event_id) == 1
    assert bus.review_task_count(sample_event.event_id) == 1

    assert bus.replay_dlq() == []
    again = bus.receive_event(sample_event)
    assert again.case_id == replayed[0].case_id
    assert bus.created_case_count(sample_event.event_id) == 1
    assert bus.review_task_count(sample_event.event_id) == 1


def test_replay_can_target_one_dead_letter_record(sample_event):
    def always_fail(normalized):
        raise RetryableProcessingError("outage")

    bus = EventBus(handler=always_fail)
    bus.receive_event(sample_event)
    record_id = bus.read_dlq()[0].record_id
    with pytest.raises(KeyError):
        bus.replay_dlq(record_id="does-not-exist")
    assert bus.replay_dlq(record_id=record_id) == []


def test_event_bus_records_audit_events(tmp_path, sample_event):
    ledger = AuditLedger(path=tmp_path / "audit.jsonl")
    bus = EventBus(ledger=ledger)
    bus.receive_event(sample_event)
    bus.receive_event(sample_event)
    event_types = [event.event_type for event in ledger.all()]
    assert "event_processed" in event_types
    assert "event_duplicate" in event_types


def test_schema_error_dlq_entry_is_not_replayed(event_bus):
    malformed = {
        "event_id": "EVT-BAD",
        "tenant_id": "TENANT-CN",
        "record_id": "SR-001",
        "version": "v3",
        "event_type": "call_report",
        "source": "veeva_vault",
        "received_at": datetime(2026, 8, 20, tzinfo=UTC),
        "surprise": "not-a-known-field",
    }
    event_bus.receive_event(malformed)
    records = event_bus.read_dlq()
    assert len(records) == 1
    assert records[0].error_type == "SchemaError"
    assert records[0].next_action == "manual_review"

    assert event_bus.replay_dlq() == []
    assert event_bus.created_case_count("EVT-BAD") == 0
    assert event_bus.review_task_count("EVT-BAD") == 0


def test_diagnostics_scoped_by_tenant_and_event(event_bus, sample_event):
    same_event_id = sample_event.model_copy(update={"tenant_id": "TENANT-EU"})
    event_bus.receive_event(sample_event)
    event_bus.receive_event(same_event_id)

    assert event_bus.created_case_count(sample_event.event_id, "TENANT-CN") == 1
    assert event_bus.created_case_count(sample_event.event_id, "TENANT-EU") == 1
    assert event_bus.created_case_count(sample_event.event_id) == 2
    assert event_bus.review_task_count(sample_event.event_id, "TENANT-CN") == 1
    assert event_bus.review_task_count(sample_event.event_id, "TENANT-EU") == 1
    assert event_bus.review_task_count(sample_event.event_id) == 2
    tasks = event_bus.review_tasks_for_event(sample_event.event_id, "TENANT-CN")
    assert len(tasks) == 1
