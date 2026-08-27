"""Misclassification feedback: production failures become regression candidates.

A reviewer who notices a false positive or a missed risk holds the only signal
that reliably improves the rules over time. Without a path back into the test set
that signal dies in a queue and the same mistake ships again.

Three constraints shape this module:

**Candidates are not test cases yet.** Entries land in a candidate file and need
confirmation by a *different* person before they can join the golden set. One
reviewer should not be able to reshape the release gate alone.

**De-identified at the door.** Only masked text is accepted. A regression fixture
is a long-lived artefact that gets copied into reports and repositories, so it is
the last place raw identifiers should be able to settle. Submitting unmasked text
is rejected rather than quietly scrubbed, because silent scrubbing hides a
gateway failure upstream.

**Append-only.** Confirmation writes a new line; it never rewrites the original,
matching the ledger's own rule that a later record must not obscure an earlier one.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import Field

from compliance_guard.domain.models import Actor, DomainModel
from compliance_guard.runtime_paths import writable_data_dir
from compliance_guard.security.dlp import DlpScanner


class FeedbackKind(str, Enum):
    """What the reviewer says went wrong."""

    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


# What the system should have concluded, per kind. A false positive means the
# content was fine; a missed risk means it needed a human, and specifically not
# `allow` -- a regression case that expects a release would encode the very
# failure it exists to prevent.
_EXPECTED_DECISION = {
    FeedbackKind.FALSE_POSITIVE: "allow",
    FeedbackKind.FALSE_NEGATIVE: "human_review",
}

_CATEGORY = {
    FeedbackKind.FALSE_POSITIVE: "regression_false_positive",
    FeedbackKind.FALSE_NEGATIVE: "regression_false_negative",
}


class FeedbackEntry(DomainModel):
    """One reported misclassification, pending or confirmed."""

    entry_id: str = Field(default_factory=lambda: f"feedback-{uuid.uuid4().hex}")
    case_id: str
    kind: FeedbackKind
    reason: str
    masked_text: str
    observed_decision: str
    observed_findings: list[str] = Field(default_factory=list)
    expected_decision: str
    category: str
    reported_by: str
    reported_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: str = "candidate"
    confirmed_by: str | None = None
    confirmed_at: datetime | None = None

    def golden_case(self) -> dict[str, Any]:
        """Shape the entry as a golden-set row."""
        return {
            "case_id": f"R-{self.entry_id[-8:]}",
            "category": self.category,
            "scenario": "normal" if self.kind is FeedbackKind.FALSE_POSITIVE else "ae",
            "content": self.masked_text,
            "expected_decision": self.expected_decision,
            "source_case_id": self.case_id,
            "note": (
                f"regression candidate from production feedback "
                f"({self.kind.value}): {self.reason}"
            ),
        }


class FeedbackStore:
    """Append-only JSONL store of misclassification reports."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = (
            Path(path)
            if path is not None
            else writable_data_dir() / "golden_set" / "candidates.jsonl"
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._scanner = DlpScanner()

    @property
    def path(self) -> Path:
        return self._path

    def _append(self, entry: FeedbackEntry) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(entry.model_dump(mode="json"), ensure_ascii=False, sort_keys=True) + "\n"
            )

    def _rows(self) -> list[FeedbackEntry]:
        if not self._path.is_file():
            return []
        entries: list[FeedbackEntry] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(FeedbackEntry(**json.loads(line)))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
        return entries

    def _latest(self) -> dict[str, FeedbackEntry]:
        """Newest state per entry id, since confirmation appends rather than edits."""
        latest: dict[str, FeedbackEntry] = {}
        for entry in self._rows():
            latest[entry.entry_id] = entry
        return latest

    def record(
        self,
        *,
        case_id: str,
        kind: FeedbackKind,
        reason: str,
        actor: Actor,
        masked_text: str,
        observed_decision: str,
        observed_findings: list[str] | None = None,
    ) -> FeedbackEntry:
        """Record a reported misclassification as a candidate regression case."""
        if not reason or not str(reason).strip():
            raise ValueError("feedback requires a non-empty reason")
        if not masked_text or not str(masked_text).strip():
            raise ValueError("feedback requires the masked content")
        leaks = self._scanner.scan(masked_text)
        if leaks:
            raise ValueError(
                "feedback content still contains raw identifiers; submit the masked text"
            )

        entry = FeedbackEntry(
            case_id=case_id,
            kind=kind,
            reason=str(reason).strip(),
            masked_text=masked_text,
            observed_decision=observed_decision,
            observed_findings=list(observed_findings or []),
            expected_decision=_EXPECTED_DECISION[kind],
            category=_CATEGORY[kind],
            reported_by=actor.actor_id,
        )
        self._append(entry)
        return entry

    def confirm(self, entry_id: str, *, actor: Actor) -> FeedbackEntry:
        """Confirm a candidate so it may enter the golden set.

        Requires a different person than the reporter: a regression case changes
        the release gate, so it takes two people to move one in.
        """
        current = self._latest().get(entry_id)
        if current is None:
            raise KeyError(f"unknown feedback entry {entry_id!r}")
        if current.status == "confirmed":
            return current
        if actor.actor_id == current.reported_by:
            raise PermissionError(
                "a regression candidate must be confirmed by someone other than its reporter"
            )
        confirmed = current.model_copy(
            update={
                "status": "confirmed",
                "confirmed_by": actor.actor_id,
                "confirmed_at": datetime.now(UTC),
            }
        )
        self._append(confirmed)
        return confirmed

    def pending(self) -> list[FeedbackEntry]:
        return [entry for entry in self._latest().values() if entry.status == "candidate"]

    def confirmed(self) -> list[FeedbackEntry]:
        return [entry for entry in self._latest().values() if entry.status == "confirmed"]

    def exportable(self) -> list[dict[str, Any]]:
        """Confirmed candidates, shaped as golden-set rows."""
        return [entry.golden_case() for entry in self.confirmed()]

    def summary(self) -> dict[str, Any]:
        """Counts for the quality dashboard.

        A rising false-positive count is the signal that reps are about to start
        working around the tool, so it belongs next to the safety numbers rather
        than in a separate report.
        """
        latest = list(self._latest().values())
        return {
            "total": len(latest),
            "pending": sum(1 for entry in latest if entry.status == "candidate"),
            "confirmed": sum(1 for entry in latest if entry.status == "confirmed"),
            "false_positive": sum(
                1 for entry in latest if entry.kind is FeedbackKind.FALSE_POSITIVE
            ),
            "false_negative": sum(
                1 for entry in latest if entry.kind is FeedbackKind.FALSE_NEGATIVE
            ),
            "path": str(self._path),
        }


__all__ = ["FeedbackEntry", "FeedbackKind", "FeedbackStore"]
