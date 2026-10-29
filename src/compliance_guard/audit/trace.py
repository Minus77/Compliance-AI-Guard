"""Correlated spans recorded at every workflow boundary.

Each :class:`TraceSpan` carries a ``trace_id``, ``case_id``, operation name,
status, and timing so audit events, model calls, and transitions can be
correlated by ``case_id`` and ``trace_id``. A single :class:`Tracer` instance
can host many independent traces (one per case) and is safe to share across
the application.
"""

from __future__ import annotations

import threading
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Iterator

from compliance_guard.domain.enums import SpanStatus
from compliance_guard.domain.models import TraceSpan


class Tracer:
    """Records correlated :class:`TraceSpan` objects across multiple traces."""

    def __init__(self, trace_id: str | None = None) -> None:
        self._spans: list[TraceSpan] = []
        self._lock = threading.RLock()
        self._default_trace_id = trace_id or f"trace-{uuid.uuid4().hex}"

    @property
    def default_trace_id(self) -> str:
        return self._default_trace_id

    def new_trace(self) -> str:
        """Allocate a fresh, unique trace id for one case run."""
        return f"trace-{uuid.uuid4().hex}"

    def start(
        self,
        operation: str,
        *,
        case_id: str | None = None,
        trace_id: str | None = None,
        parent_span_id: str | None = None,
    ) -> TraceSpan:
        span = TraceSpan(
            span_id=f"span-{uuid.uuid4().hex}",
            trace_id=trace_id or self._default_trace_id,
            case_id=case_id or "",
            operation=operation,
            status=SpanStatus.UNSET,
            started_at=datetime.now(UTC),
            parent_span_id=parent_span_id,
        )
        with self._lock:
            self._spans.append(span)
        return span

    def finish(
        self,
        span: TraceSpan,
        *,
        status: SpanStatus = SpanStatus.OK,
        attributes: dict | None = None,
    ) -> TraceSpan:
        with self._lock:
            span.ended_at = datetime.now(UTC)
            span.status = status
            if attributes:
                span.attributes.update(attributes)
        return span

    @contextmanager
    def span(
        self,
        operation: str,
        *,
        case_id: str | None = None,
        trace_id: str | None = None,
        parent_span_id: str | None = None,
    ) -> Iterator[TraceSpan]:
        span = self.start(operation, case_id=case_id, trace_id=trace_id, parent_span_id=parent_span_id)
        try:
            yield span
        except Exception:
            self.finish(span, status=SpanStatus.ERROR, attributes={"error": "raised"})
            raise
        else:
            self.finish(span)

    def spans(self, *, case_id: str | None = None, trace_id: str | None = None) -> list[TraceSpan]:
        with self._lock:
            result = self._spans
            if case_id is not None:
                result = [span for span in result if span.case_id == case_id]
            if trace_id is not None:
                result = [span for span in result if span.trace_id == trace_id]
            return list(result)

    def spans_for_trace(self, trace_id: str) -> list[TraceSpan]:
        with self._lock:
            return [span for span in self._spans if span.trace_id == trace_id]


__all__ = ["Tracer"]
