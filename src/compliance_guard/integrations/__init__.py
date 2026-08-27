"""External integration boundary: idempotent event bus and adapter contracts.

This package owns the compliance boundary with external systems (Veeva/Vault,
PV, CRM). It provides the idempotent event bus with dead-letter queueing plus
mock adapter contracts for Veeva, PV, and CRM. All live integrations are
future scope; only mock contracts exist here.
"""

from .crm_adapter import CrmAdapter
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
from .pv_adapter import PvAdapter, PvCaseRecord
from .veeva_adapter import (
    AdapterError,
    ApprovalDeniedError,
    ApprovalToken,
    ContentDraft,
    ExternalTaskRef,
    SourceNotFoundError,
    SourceRecord,
    StaleVersionError,
    VeevaAdapter,
    WriteResult,
)

__all__ = [
    "AdapterError",
    "ApprovalDeniedError",
    "ApprovalToken",
    "ContentDraft",
    "CrmAdapter",
    "DeadLetterRecord",
    "EventBus",
    "EventProcessingError",
    "ExternalEvent",
    "ExternalTaskRef",
    "NonRetryableProcessingError",
    "NormalizedEvent",
    "PvAdapter",
    "PvCaseRecord",
    "RetryableProcessingError",
    "SchemaError",
    "SourceNotFoundError",
    "SourceRecord",
    "StaleVersionError",
    "VeevaAdapter",
    "WriteResult",
    "receive_event",
]
