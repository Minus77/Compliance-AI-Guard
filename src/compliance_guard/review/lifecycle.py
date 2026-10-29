"""Case lifecycle beyond the first submission: notifications, revisions, appeals.

Submission used to be the end of the road. A contributor sent content and
then had no list of what they sent, no word back when a reviewer decided something,
no way to continue from a blocked draft, and no channel to disagree. Every one of
those gaps pushes the same direction: write less, write blander, keep the
interesting clinical detail out of the system. That is precisely the outcome the
product exists to prevent, so these are compliance features, not conveniences.

Three rules shape the implementation:

**Nothing overwrites anything.** A revision is a new case that points at its
parent; an appeal is a new task attached to a case. The original record keeps its
own decision forever, which is what 21 CFR Part 11 §11.10(e) means by a change not
obscuring what came before.

**An appeal does not lift the block.** It creates work for a person. An appeal that
clears itself is a bypass with a polite name.

**Notifications carry no personal data.** They are addressed to the author, who has
already seen the narrative, so there is nothing to gain by repeating it — and a
notification store is one more place a name could settle.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from compliance_guard.domain.models import Actor
from compliance_guard.review.lifecycle_contracts import (
    Appeal,
    AppealStatus,
    Notification,
    NotificationKind,
)


class LifecycleStore:
    """In-memory notifications and appeals for one running instance.

    In-memory to match how cases themselves are held: the demo deliberately keeps
    no raw narrative on disk. Persistence would be a storage decision, not a
    behavioural one, and the interface here is what a real backing store would
    implement.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._notifications: list[Notification] = []
        self._appeals: list[Appeal] = []

    # -- notifications -------------------------------------------------------

    def notify(
        self,
        *,
        case_id: str,
        recipient_id: str,
        kind: NotificationKind,
        title: str,
        body: str = "",
        next_step: str = "",
        decision: str = "",
    ) -> Notification:
        with self._lock:
            note = Notification(
                case_id=case_id,
                recipient_id=recipient_id,
                kind=kind,
                title=title,
                body=body,
                next_step=next_step,
                decision=decision,
            )
            self._notifications.append(note)
            return note

    def notifications(self, recipient_id: str, *, unread_only: bool = False) -> list[Notification]:
        """Newest first: the most recent outcome is the one being waited on."""
        with self._lock:
            items = [note for note in self._notifications if note.recipient_id == recipient_id]
            if unread_only:
                items = [note for note in items if note.unread]
            return sorted(items, key=lambda note: note.created_at, reverse=True)

    def mark_read(self, notification_id: str, *, recipient_id: str) -> Notification:
        with self._lock:
            for note in self._notifications:
                if note.notification_id != notification_id:
                    continue
                if note.recipient_id != recipient_id:
                    raise PermissionError("a notification can only be read by its recipient")
                if note.read_at is None:
                    note.read_at = datetime.now(UTC)
                return note
            raise KeyError(f"unknown notification {notification_id!r}")

    def unread_count(self, recipient_id: str) -> int:
        return len(self.notifications(recipient_id, unread_only=True))

    # -- appeals -------------------------------------------------------------

    def raise_appeal(
        self,
        *,
        case_id: str,
        reason: str,
        actor: Actor,
        decision_at_appeal: str,
    ) -> Appeal:
        """Record a disagreement. The current decision is untouched by design."""
        if not reason or not str(reason).strip():
            raise ValueError("an appeal requires a reason")
        with self._lock:
            appeal = Appeal(
                case_id=case_id,
                reason=str(reason).strip(),
                raised_by=actor.actor_id,
                decision_at_appeal=decision_at_appeal,
            )
            self._appeals.append(appeal)
            return appeal

    def resolve_appeal(
        self,
        appeal_id: str,
        *,
        actor: Actor,
        upheld: bool,
        reason: str,
    ) -> Appeal:
        if not reason or not str(reason).strip():
            raise ValueError("resolving an appeal requires a reason")
        with self._lock:
            for appeal in self._appeals:
                if appeal.appeal_id != appeal_id:
                    continue
                if appeal.status is not AppealStatus.PENDING:
                    return appeal
                appeal.status = AppealStatus.UPHELD if upheld else AppealStatus.OVERTURNED
                appeal.resolved_by = actor.actor_id
                appeal.resolved_at = datetime.now(UTC)
                appeal.resolution_reason = str(reason).strip()
                return appeal
            raise KeyError(f"unknown appeal {appeal_id!r}")

    def appeals(self, *, case_id: str | None = None, pending_only: bool = False) -> list[Appeal]:
        with self._lock:
            items = list(self._appeals)
            if case_id is not None:
                items = [appeal for appeal in items if appeal.case_id == case_id]
            if pending_only:
                items = [appeal for appeal in items if appeal.status is AppealStatus.PENDING]
            return sorted(items, key=lambda appeal: appeal.created_at, reverse=True)

    # -- retention -----------------------------------------------------------

    def purge_expired(
        self,
        *,
        now: datetime | None = None,
        keep_unread: bool = False,
    ) -> dict[str, int]:
        """Drop records past their declared retention, and report what went.

        A retention period nothing enforces is worse than none: it reads as a
        control to anyone reviewing the design while the store grows forever.

        Two exemptions, both deliberate:

        **A pending appeal never expires.** It is outstanding work, and expiring it
        would close it by neglect -- the author would be left believing someone is
        still looking.

        **With ``keep_unread``, an unseen notification never expires.** Purging an
        outcome the author has not read loses the outcome silently, which is the
        exact dead end the notification exists to prevent.

        The audit ledger is not swept here and has no equivalent method. Retention
        there must equal or exceed the business records it describes, and deleting
        entries would defeat the chain that makes deletion detectable.
        """
        from compliance_guard.runtime_config import retention_policy

        with self._lock:
            policy = retention_policy()
            moment = now or datetime.now(UTC)
            removed = {"notifications": 0, "appeals": 0}

            note_days = policy.get("notification", {}).get("retain_days")
            if note_days is not None:
                cutoff = moment - timedelta(days=int(note_days))
                keep: list[Notification] = []
                for note in self._notifications:
                    expired = note.created_at < cutoff
                    if expired and keep_unread and note.unread:
                        expired = False
                    if expired:
                        removed["notifications"] += 1
                    else:
                        keep.append(note)
                self._notifications = keep

            # Appeals follow the notification period: both are records of an outcome
            # already delivered, and neither is the authoritative case record.
            appeal_days = policy.get("notification", {}).get("retain_days")
            if appeal_days is not None:
                cutoff = moment - timedelta(days=int(appeal_days))
                keep_appeals: list[Appeal] = []
                for appeal in self._appeals:
                    resolved_at = appeal.resolved_at
                    # Pending appeals are outstanding work, never swept.
                    if appeal.status is AppealStatus.PENDING or resolved_at is None:
                        keep_appeals.append(appeal)
                        continue
                    if resolved_at < cutoff:
                        removed["appeals"] += 1
                    else:
                        keep_appeals.append(appeal)
                self._appeals = keep_appeals

            return removed

    def appeal_summary(self) -> dict[str, Any]:
        """Counts for the quality dashboard.

        A high sustained rate of overturned appeals is not a story about appeals;
        it says the rules are too tight and should be fixed at the rule, rather
        than absorbed case by case by whoever is on the queue.
        """
        with self._lock:
            total = len(self._appeals)
            pending = sum(1 for a in self._appeals if a.status is AppealStatus.PENDING)
            overturned = sum(1 for a in self._appeals if a.status is AppealStatus.OVERTURNED)
            resolved = total - pending
            return {
                "total": total,
                "pending": pending,
                "upheld": sum(1 for a in self._appeals if a.status is AppealStatus.UPHELD),
                "overturned": overturned,
                # Denominator attached: a rate over three appeals means little, and a
                # bare percentage would hide that.
                "overturn_rate": round(overturned / resolved, 4) if resolved else None,
                "resolved": resolved,
            }


__all__ = [
    "Appeal",
    "AppealStatus",
    "LifecycleStore",
    "Notification",
    "NotificationKind",
]
