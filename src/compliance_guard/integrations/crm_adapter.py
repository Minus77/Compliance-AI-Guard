"""CRM call-report source normalization adapter contract mock.

Contract-only mock: no live CRM system, license, credential, or network call
is used. Call-report records are re-read through
:meth:`CrmAdapter.get_current_record` with stale-version rejection; event
payloads are never authoritative.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from compliance_guard.audit.ledger import AuditLedger

from .veeva_adapter import (
    SourceRecord,
    SourceStoreMixin,
    StaleVersionError,
)


class CrmAdapter(SourceStoreMixin):
    """CRM source normalization: re-read authoritative call-report records."""

    def __init__(
        self,
        *,
        ledger: AuditLedger | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._init_store(ledger=ledger, now=now)

    def normalize_event(self, event: Any) -> SourceRecord:
        """Normalize an external envelope into a call-report :class:`SourceRecord`.

        The record is always re-read from the store and stale versions are
        rejected; ``event.payload`` is never treated as authoritative.
        """
        return self.get_current_record(event.record_id, version=event.version)


__all__ = ["CrmAdapter", "SourceRecord", "StaleVersionError"]
