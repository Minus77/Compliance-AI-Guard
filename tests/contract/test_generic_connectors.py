"""Vendor-neutral connector contracts."""

from datetime import UTC, datetime

import pytest

from compliance_guard.domain.enums import ContentType, Decision
from compliance_guard.integrations import (
    ConnectorAlreadyRegisteredError,
    ConnectorNotFoundError,
    ConnectorRegistry,
    ContentEnvelope,
    ExternalEvent,
    InMemoryContentSource,
    InMemoryReviewExport,
    InMemorySafetyIntake,
    ReviewExportDisabledError,
    ReviewExportRequest,
    SafetyCandidate,
    SafetyIntakeError,
    StaleVersionError,
)
from compliance_guard.integrations.event_bus import EventBus


def _envelope() -> ContentEnvelope:
    return ContentEnvelope(
        record_id="R1",
        version="2",
        text="权威文本",
        content_type=ContentType.OTHER,
    )


def _candidate() -> SafetyCandidate:
    return SafetyCandidate(
        record_id="R1",
        version="2",
        text="疑似安全信号",
        content_type=ContentType.CUSTOMER_INTERACTION_NOTE,
        tenant_id="TENANT-CN",
    )


def test_content_source_rejects_an_old_version_and_accepts_the_current_one():
    source = InMemoryContentSource()
    source.put(_envelope())

    with pytest.raises(StaleVersionError):
        source.fetch("R1", "1")

    assert source.fetch("R1", "2").text == "权威文本"
    assert source.fetch("R1").version == "2"


def test_event_payload_is_never_used_as_authoritative_content():
    source = InMemoryContentSource()
    source.put(_envelope())
    event = ExternalEvent(
        event_id="EV-1",
        tenant_id="TENANT-CN",
        record_id="R1",
        version="2",
        event_type="content_submitted",
        payload={"text": "来自事件的不受信文本"},
    )

    envelope = source.fetch(event.record_id, event.version)

    assert envelope.text == "权威文本"
    assert envelope.text != event.payload["text"]


def test_failed_safety_intake_retains_the_candidate_for_idempotent_retry():
    intake = InMemorySafetyIntake()
    intake.fail_next()

    with pytest.raises(SafetyIntakeError):
        intake.submit(_candidate(), "safety-key-1")

    pending = intake.pending_events()
    assert len(pending) == 1
    assert pending[0].text == "疑似安全信号"

    accepted = intake.submit(_candidate(), "safety-key-1")
    duplicate = intake.submit(_candidate(), "safety-key-1")
    assert accepted.receipt_id == duplicate.receipt_id
    assert intake.pending_events() == []
    assert len(intake.receipts()) == 1


def test_review_export_requires_explicit_enablement_and_is_idempotent():
    export = InMemoryReviewExport()
    request = ReviewExportRequest(
        case_id="CASE-1",
        record_id="R1",
        version="2",
        decision=Decision.ALLOW,
        actor_id="reviewer-1",
    )

    with pytest.raises(ReviewExportDisabledError):
        export.export(request, "export-key-1")

    export.enable()
    first = export.export(request, "export-key-1")
    second = export.export(request, "export-key-1")
    assert first.export_id == second.export_id


def test_registry_exposes_governance_metadata_and_health():
    source = InMemoryContentSource(connector_id="records")
    intake = InMemorySafetyIntake(connector_id="safety")
    export = InMemoryReviewExport(connector_id="export")
    registry = ConnectorRegistry()
    for connector in (source, intake, export):
        registry.register(connector)

    descriptors = {item.connector_id: item for item in registry.list()}
    assert set(descriptors) == {"records", "safety", "export"}
    assert descriptors["records"].capabilities == ["read", "version_check"]
    assert descriptors["records"].allowed_actions == ["read"]
    assert descriptors["records"].data_classes
    assert registry.health("export").status == "disabled"

    with pytest.raises(ConnectorAlreadyRegisteredError):
        registry.register(source)
    with pytest.raises(ConnectorNotFoundError):
        registry.health("missing")


def test_event_bus_uses_neutral_event_types_and_routes_review_roles():
    received_at = datetime(2026, 8, 20, tzinfo=UTC)
    content_bus = EventBus()
    content = content_bus.receive_event(
        ExternalEvent(
            event_id="EV-CONTENT",
            tenant_id="TENANT-CN",
            record_id="R1",
            version="2",
            event_type="content_submitted",
            received_at=received_at,
        )
    )
    content_task = content_bus.review_tasks_for_event(content.event_id)[0]
    assert content_task.required_role.value == "reviewer"

    safety_bus = EventBus()
    safety = safety_bus.receive_event(
        ExternalEvent(
            event_id="EV-SAFETY",
            tenant_id="TENANT-CN",
            record_id="R2",
            version="1",
            event_type="safety_signal",
            received_at=received_at,
        )
    )
    safety_task = safety_bus.review_tasks_for_event(safety.event_id)[0]
    assert safety_task.required_role.value == "safety_reviewer"
