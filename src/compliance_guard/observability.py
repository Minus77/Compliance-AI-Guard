"""Structured logging with identifier scrubbing.

Two problems this solves.

**Correlation.** A single case touches masking, resolution, retrieval, a model
call, the policy engine and the review queue. Without one id threaded through
those steps, diagnosing "what happened to this submission" means reading
timestamps and guessing. Every log line carries a ``request_id``.

**Logs as a leak path.** A log file is the easiest place for a name to end up by
accident: it is written from everywhere, read casually, copied into tickets, and
retained longer than anyone intends. So log payloads pass the same detector the
gateway uses on model output. Scrubbing here is a backstop, not the control --
the gateway upstream is the control -- but a backstop that catches the case where
someone logs a raw field in a hurry.

JSON Lines because a log an operator cannot filter is a log nobody reads.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from compliance_guard.security.name_lexicon import find_mentions
from compliance_guard.security.pii_gateway import EMAIL_RE, PATIENT_ID_RE, PHONE_RE

REDACTION = "[redacted]"

_PATTERNS = (PHONE_RE, EMAIL_RE, PATIENT_ID_RE)

# Keys whose value is never safe to log verbatim, regardless of content. Matched
# on substring so `api_key`, `authorization_header` and `raw_content` are all
# covered without maintaining an exhaustive list.
_FORBIDDEN_KEY_PARTS = (
    "password",
    "secret",
    "api_key",
    "apikey",
    "token_value",
    "credential",
    "authorization",
    "raw_content",
)


def _is_forbidden_key(key: str) -> bool:
    lowered = str(key).casefold()
    return any(part in lowered for part in _FORBIDDEN_KEY_PARTS)


def scrub_text(value: str) -> str:
    """Replace identifiers in a string with a fixed marker.

    Person names use the same surname-anchored detector as the gateway, so a name
    the gateway would mask is a name the log refuses to keep. Only the name span
    is replaced: context words survive, for the same reason they survive masking
    (they carry meaning and are not identifiers).
    """
    text = str(value)
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTION, text)

    mentions = find_mentions(text)
    if mentions:
        # Right to left, so earlier offsets stay valid as we splice.
        for mention in sorted(mentions, key=lambda m: m.start, reverse=True):
            text = text[: mention.start] + REDACTION + text[mention.end :]
    return text


def scrub_value(value: Any) -> Any:
    """Recursively scrub a log field, preserving non-string values."""
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return {
            key: (REDACTION if _is_forbidden_key(key) else scrub_value(item))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [scrub_value(item) for item in value]
    return value


def build_log_record(
    event: str,
    *,
    request_id: str = "",
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble one scrubbed log record."""
    record: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": str(event),
        "request_id": str(request_id or ""),
    }
    for key, value in (fields or {}).items():
        if key in record:
            # Never let a caller overwrite the correlation fields.
            continue
        record[key] = REDACTION if _is_forbidden_key(key) else scrub_value(value)
    return record


def format_log_record(
    event: str,
    *,
    request_id: str = "",
    fields: dict[str, Any] | None = None,
) -> str:
    """One JSON Lines log entry, scrubbed."""
    return json.dumps(
        build_log_record(event, request_id=request_id, fields=fields),
        ensure_ascii=False,
        sort_keys=True,
    )


__all__ = ["REDACTION", "build_log_record", "format_log_record", "scrub_text", "scrub_value"]
