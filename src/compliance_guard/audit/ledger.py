"""Append-only, hash-chained JSONL audit ledger.

Every :class:`AuditEvent` is appended as an immutable record carrying event id,
trace id, case id, actor, component/action, timestamp, configuration versions and
redacted metadata. Events are never rewritten or deleted; :meth:`for_case`
returns a replayable, chronological view.

Append-only alone was not enough (defect D-3). It guaranteed the *program* never
rewrote a record, while saying nothing about anyone editing the file directly --
and a JSONL file whose lines are unrelated cannot reveal that a line changed or
disappeared. Each entry therefore carries::

    entry_hash = sha256(prev_hash + canonical_json(body without entry_hash))

so an edit, deletion, insertion or reordering breaks the chain at a locatable
sequence number. The change remains possible; what it cannot be is invisible,
which is what 21 CFR Part 11 §11.10(e) requires of record changes.

Verification reads the file rather than memory: in-memory state proves nothing
about the artefact an inspector would actually be handed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from compliance_guard.domain.models import AuditEvent, DomainModel
from compliance_guard.runtime_paths import audit_ledger_path


def _default_audit_path() -> Path:
    # Writable state: inside a bundle this resolves to a per-user directory,
    # because a macOS .app (and a typical Windows install dir) is read-only.
    return audit_ledger_path()


def _canonical(payload: dict) -> str:
    """Stable serialisation, so the same body always yields the same digest."""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class ChainVerification(DomainModel):
    """Outcome of verifying the ledger chain.

    ``legacy_entries`` counts leading records written before the chain existed.
    They are named rather than skipped: the chain can only attest to entries
    created after it was switched on, and implying otherwise would be a false
    assurance in the one place assurances have to be exact.
    """

    ok: bool
    checked: int = 0
    first_broken_seq: int | None = None
    reason: str = ""
    legacy_entries: int = 0
    note: str = ""


class AuditLedger:
    """Append-only, hash-chained, JSONL-backed audit event store."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else _default_audit_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._events: list[AuditEvent] = self._load()

    @property
    def path(self) -> Path:
        return self._path

    # -- chain primitives -----------------------------------------------------

    @staticmethod
    def compute_entry_hash(prev_hash: str, event: AuditEvent) -> str:
        """Digest over the predecessor's digest plus this event's body."""
        return hashlib.sha256(
            (prev_hash + _canonical(event.chain_body())).encode("utf-8")
        ).hexdigest()

    def _load(self) -> list[AuditEvent]:
        """Read existing events so a restart continues the chain instead of forking it."""
        if not self._path.is_file():
            return []
        events: list[AuditEvent] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(AuditEvent(**json.loads(line)))
            except (json.JSONDecodeError, TypeError, ValueError):
                # A malformed line is itself evidence of tampering. Verification
                # reports it; loading must not crash the service over it.
                continue
        return events

    # -- append / read --------------------------------------------------------

    def append(self, event: AuditEvent) -> AuditEvent:
        """Append one event, linking it to the current chain head.

        When the file holds only pre-chain records there is no digest to link to,
        so the chain starts at 1 here rather than continuing a sequence that was
        never hashed. Pretending to extend an unhashed history would produce a
        chain that verifies while proving nothing about the entries beneath it.
        """
        head = self._events[-1] if self._events else None
        if head is not None and head.entry_hash:
            prev_hash = head.entry_hash
            seq = head.seq + 1
        else:
            prev_hash = ""
            seq = 1
        linked = event.model_copy(update={"seq": seq, "prev_hash": prev_hash, "entry_hash": ""})
        linked = linked.model_copy(
            update={"entry_hash": self.compute_entry_hash(prev_hash, linked)}
        )
        self._events.append(linked)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(linked.model_dump(mode="json"), ensure_ascii=False, sort_keys=True) + "\n"
            )
        return linked

    def verify(self) -> ChainVerification:
        """Recompute the chain from the file and report the first break.

        ``first_broken_seq`` is the first position that cannot be trusted, i.e.
        one past the last verified entry. It is deliberately not the ``seq`` value
        read from the offending line: that field is attacker-controlled, and after
        a deletion or reorder it points somewhere misleading. "Entries 1..N verify,
        the problem starts at N+1" is what an inspector can act on.
        """
        if not self._path.is_file():
            return ChainVerification(ok=True, checked=0)

        prev_hash = ""
        expected_seq = 1
        checked = 0
        legacy = 0
        started = False

        for line_number, raw in enumerate(
            self._path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = AuditEvent(**json.loads(raw))
            except (json.JSONDecodeError, TypeError, ValueError) as error:
                return ChainVerification(
                    ok=False,
                    checked=checked,
                    first_broken_seq=checked + 1,
                    legacy_entries=legacy,
                    reason=f"line {line_number} is not a valid audit event: {error}",
                )

            if not event.entry_hash:
                # Pre-chain record. Credible only at the front of the file: the
                # same shape appearing after chained entries is what an insertion
                # looks like, so it is a break rather than history.
                if started:
                    return ChainVerification(
                        ok=False,
                        checked=checked,
                        first_broken_seq=checked + 1,
                        legacy_entries=legacy,
                        reason=(
                            f"line {line_number} carries no digest but follows chained "
                            "entries; an unhashed record cannot appear after the chain starts"
                        ),
                    )
                legacy += 1
                continue
            started = True

            if event.seq != expected_seq:
                return ChainVerification(
                    ok=False,
                    checked=checked,
                    first_broken_seq=checked + 1,
                    legacy_entries=legacy,
                    reason=f"sequence gap: expected {expected_seq}, found {event.seq}",
                )
            if event.prev_hash != prev_hash:
                return ChainVerification(
                    ok=False,
                    checked=checked,
                    first_broken_seq=checked + 1,
                    legacy_entries=legacy,
                    reason=f"entry {event.seq} does not link to its predecessor",
                )
            recomputed = self.compute_entry_hash(prev_hash, event)
            if recomputed != event.entry_hash:
                return ChainVerification(
                    ok=False,
                    checked=checked,
                    first_broken_seq=checked + 1,
                    legacy_entries=legacy,
                    reason=f"entry {event.seq} body does not match its digest (payload altered)",
                )

            prev_hash = event.entry_hash
            expected_seq += 1
            checked += 1

        note = ""
        if legacy:
            note = (
                f"{legacy} entries predate the hash chain and carry no digest; "
                "they are counted but cannot be attested to. Verification covers "
                f"the {checked} entries written after the chain was enabled."
            )
        return ChainVerification(
            ok=True, checked=checked, legacy_entries=legacy, note=note
        )

    def for_case(self, case_id: str) -> list[AuditEvent]:
        """Return all events for a case in append order."""
        return [event for event in self._events if event.case_id == case_id]

    def for_trace(self, trace_id: str) -> list[AuditEvent]:
        """Return all events sharing a trace id in append order."""
        return [event for event in self._events if event.trace_id == trace_id]

    def all(self) -> list[AuditEvent]:
        return list(self._events)

    def count(self) -> int:
        return len(self._events)

    def head_hash(self) -> str:
        """Digest of the newest chained entry; empty if there is none."""
        return self._events[-1].entry_hash if self._events else ""


__all__ = ["AuditLedger", "ChainVerification"]
