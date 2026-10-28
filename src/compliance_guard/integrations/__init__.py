"""Vendor-neutral external connector and event integration boundary."""

from .connector_registry import (
    ConnectorAlreadyRegisteredError,
    ConnectorNotFoundError,
    ConnectorRegistry,
    ConnectorRegistryError,
)
from .content_source import (
    ContentNotFoundError,
    ContentSource,
    ContentSourceError,
    InMemoryContentSource,
    seed_generic_records,
)
from .contracts import (
    ConnectorContract,
    ConnectorInfo,
    ContentEnvelope,
    ExportReceipt,
    HealthStatus,
    ReviewExportRequest,
    SafetyCandidate,
    SafetyReceipt,
)
from .event_bus import (
    DeadLetterRecord,
    EventBus,
    EventProcessingError,
    ExternalEvent,
    NonRetryableProcessingError,
    NormalizedEvent,
    RetryableProcessingError,
    SchemaError,
    receive_event,
)
from .review_export import (
    InMemoryReviewExport,
    ReviewExport,
    ReviewExportDisabledError,
)
from .safety_intake import InMemorySafetyIntake, SafetyIntake, SafetyIntakeError
from .stale_version import StaleVersionError

__all__ = [
    "ConnectorAlreadyRegisteredError",
    "ConnectorContract",
    "ConnectorInfo",
    "ConnectorNotFoundError",
    "ConnectorRegistry",
    "ConnectorRegistryError",
    "ContentEnvelope",
    "ContentNotFoundError",
    "ContentSource",
    "ContentSourceError",
    "DeadLetterRecord",
    "EventBus",
    "EventProcessingError",
    "ExportReceipt",
    "ExternalEvent",
    "HealthStatus",
    "InMemoryContentSource",
    "InMemoryReviewExport",
    "InMemorySafetyIntake",
    "NonRetryableProcessingError",
    "NormalizedEvent",
    "RetryableProcessingError",
    "ReviewExport",
    "ReviewExportDisabledError",
    "ReviewExportRequest",
    "SafetyCandidate",
    "SafetyIntake",
    "SafetyIntakeError",
    "SafetyReceipt",
    "SchemaError",
    "StaleVersionError",
    "receive_event",
    "seed_generic_records",
]
