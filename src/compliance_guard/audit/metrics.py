"""Bounded metrics snapshots: counters and gauges without raw PII.

Metrics only ever store aggregate counts and numeric gauges. Raw content and
personal identifiers are never placed into a counter name or value, so a
snapshot is inherently PII-free. Snapshots are bounded in size so the metric
store can never grow without limit.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime

from pydantic import Field

from compliance_guard.domain.models import DomainModel

_MAX_SNAPSHOT_KEYS = 1000
_MAX_RETAINED_SNAPSHOTS = 128


class MetricsSnapshot(DomainModel):
    snapshot_id: str
    recorded_at: datetime
    counters: dict[str, int] = Field(default_factory=dict)
    gauges: dict[str, float] = Field(default_factory=dict)
    bounded: bool = True
    redacted: bool = True


# Below this rate, reviewers are probably not exercising independent judgement.
# The threshold is a prompt for investigation, not a verdict.
_RUBBER_STAMP_RATE = 0.02
# Fewer reviews than this cannot distinguish diligence from rubber-stamping.
_MIN_OVERSIGHT_SAMPLE = 20


class OversightSummary(DomainModel):
    """Whether human review is departing from the system often enough to be real.

    The alarm points downward on purpose (EU AI Act Art.14(4)(b)): a reviewer who
    never disagrees is the failure mode worth surfacing, because approval-shaped
    inaction looks identical to approval in the record.
    """

    reviews: int = 0
    overrides: int = 0
    override_rate: float | None = None
    status: str = "insufficient_data"
    message: str = ""
    threshold: float = _RUBBER_STAMP_RATE
    min_sample: int = _MIN_OVERSIGHT_SAMPLE


# Usability events the server will record. An allowlist rather than free-form
# names: a telemetry endpoint that accepts anything becomes a place arbitrary
# strings from the client accumulate, and one of those strings will eventually be
# narrative text.
USABILITY_EVENTS = frozenset(
    {
        "precheck_shown",     # denominator: a warning was actually displayed
        "rep_abandon",        # numerator: the draft was cleared without submitting
        "rewrite_accepted",   # a suggestion was used
        "followup_completed", # missing ICSR elements were supplied
        "draft_restored",
    }
)

# Below this many displayed warnings, a rate is noise rather than signal.
_MIN_USABILITY_SAMPLE = 4
# Above this share, the tool is plausibly teaching people to write less.
_ABANDON_WARN_RATE = 0.2


class UsabilitySummary(DomainModel):
    """Whether the tool is quietly pushing authors to write less.

    Every other metric here watches for risk getting through. This one watches
    the opposite failure, which is harder to see and just as damaging: a warning
    appears, the paragraph is deleted, and something bland is submitted instead.
    Nothing is blocked, no finding is raised, and the clinical detail the product
    exists to encourage is gone.
    """

    precheck_shown: int = 0
    abandoned: int = 0
    abandon_rate: float | None = None
    status: str = "insufficient_data"
    message: str = ""
    threshold: float = _ABANDON_WARN_RATE
    min_sample: int = _MIN_USABILITY_SAMPLE


class Metrics:
    """Thread-simple aggregate counters and gauges with bounded snapshots."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)
        self._gauges: dict[str, float] = {}
        self._snapshots: list[MetricsSnapshot] = []

    def increment(self, name: str, amount: int = 1) -> None:
        if amount < 0:
            raise ValueError("increment amount must be non-negative")
        self._counters[name] += amount

    def gauge(self, name: str, value: float) -> None:
        self._gauges[name] = float(value)

    def record(self, name: str, value: float) -> None:
        """Record one numeric observation as a gauge (e.g. latency ms)."""
        self._gauges[name] = float(value)

    def snapshot(self, *, bounded: bool = True) -> MetricsSnapshot:
        counters = dict(self._counters)
        if bounded and len(counters) > _MAX_SNAPSHOT_KEYS:
            counters = dict(
                sorted(counters.items(), key=lambda item: -item[1])[:_MAX_SNAPSHOT_KEYS]
            )
        snap = MetricsSnapshot(
            snapshot_id=f"metrics-{uuid.uuid4().hex}",
            recorded_at=datetime.now(UTC),
            counters=counters,
            gauges=dict(self._gauges),
            bounded=bounded,
            redacted=True,
        )
        self._snapshots.append(snap)
        if len(self._snapshots) > _MAX_RETAINED_SNAPSHOTS:
            self._snapshots = self._snapshots[-_MAX_RETAINED_SNAPSHOTS:]
        return snap

    def snapshots(self) -> list[MetricsSnapshot]:
        return list(self._snapshots)

    def record_review_outcome(self, *, overridden: bool) -> None:
        """Record one completed review and whether it departed from the system."""
        self._counters["review_outcomes.total"] += 1
        if overridden:
            self._counters["review_outcomes.overridden"] += 1

    def oversight_summary(self) -> OversightSummary:
        """Report the override rate with a plain-language reading of it."""
        reviews = self._counters.get("review_outcomes.total", 0)
        overrides = self._counters.get("review_outcomes.overridden", 0)

        if reviews < _MIN_OVERSIGHT_SAMPLE:
            return OversightSummary(
                reviews=reviews,
                overrides=overrides,
                override_rate=round(overrides / reviews, 4) if reviews else None,
                status="insufficient_data",
                message=(
                    f"已完成 {reviews} 条审核，样本还不足以判断审核是否充分独立"
                    f"（至少需要 {_MIN_OVERSIGHT_SAMPLE} 条）。"
                ),
            )

        rate = overrides / reviews
        if rate < _RUBBER_STAMP_RATE:
            status = "warning"
            message = (
                f"最近 {reviews} 条审核里只有 {overrides} 条推翻了系统建议"
                f"（{rate:.1%}）。推翻率偏低，请确认审核是否流于形式。"
            )
        else:
            status = "healthy"
            message = (
                f"最近 {reviews} 条审核里有 {overrides} 条推翻了系统建议"
                f"（{rate:.1%}），审核人在独立判断。"
            )
        return OversightSummary(
            reviews=reviews,
            overrides=overrides,
            override_rate=round(rate, 4),
            status=status,
            message=message,
        )

    def record_usability_event(self, event: str) -> None:
        """Count one usability event. Unknown names are refused, not stored."""
        name = str(event).strip()
        if name not in USABILITY_EVENTS:
            raise ValueError(f"unknown usability event {name!r}")
        self._counters[f"usability.{name}"] += 1

    def usability_summary(self) -> UsabilitySummary:
        """Abandonment rate, with its denominator and a plain-language reading."""
        shown = self._counters.get("usability.precheck_shown", 0)
        abandoned = self._counters.get("usability.rep_abandon", 0)

        if shown < _MIN_USABILITY_SAMPLE:
            return UsabilitySummary(
                precheck_shown=shown,
                abandoned=abandoned,
                abandon_rate=None,
                status="insufficient_data",
                message=(
                    f"已展示 {shown} 次提示，样本还不足以判断提示是否让代表放弃记录"
                    f"（至少需要 {_MIN_USABILITY_SAMPLE} 次）。"
                ),
            )

        rate = abandoned / shown
        if rate > _ABANDON_WARN_RATE:
            status = "warning"
            message = (
                f"展示 {shown} 次提示中有 {abandoned} 次代表清空了正文（{rate:.1%}）。"
                "放弃率偏高，说明提示可能过严，正在把人逼回「不敢写」的老问题。"
            )
        else:
            status = "healthy"
            message = (
                f"展示 {shown} 次提示中有 {abandoned} 次代表清空了正文（{rate:.1%}）。"
                "代表仍在正常记录内容。"
            )
        return UsabilitySummary(
            precheck_shown=shown,
            abandoned=abandoned,
            abandon_rate=round(rate, 4),
            status=status,
            message=message,
        )

    def reset(self) -> None:
        self._counters.clear()
        self._gauges.clear()


__all__ = [
    "Metrics",
    "MetricsSnapshot",
    "OversightSummary",
    "USABILITY_EVENTS",
    "UsabilitySummary",
]
