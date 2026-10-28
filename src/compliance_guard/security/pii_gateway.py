"""PII/PHI sanitization gateway: mask personal identifiers before any model request.

Masked spans are replaced with tenant-stable tokens; the token -> char:start-end
span map refers to the sanitized text, and safe context is preserved. Raw masked
values never appear in ordinary returned objects or normal logs.

Two invariants drive the design:

**Resolve, then mask.** Entity resolution runs first, on raw text, so every
mention of one person shares a single canonical id and therefore a single token
(defect D-2). Masking as-you-scan cannot do this: at the moment it replaces
"章三" it does not yet know that "章医生" later in the sentence is the same doctor.

**Mask the identifier, not its context.** Candidate spans cover the name only;
"患者" and "医生" survive (defect D-1). Those words are not identifiers, and they
carry the role signal that downstream adverse-event logic depends on.

Candidate precedence, highest first:

1. resolved name mentions — name-only spans with a resolved canonical id
2. roster literal values — phone numbers, emails, ids, and names never detected as mentions
3. pattern matches — phone / email / patient-id regexes with per-value pseudonyms

Resolution failure never suppresses masking: an unresolvable mention still gets
masked under a case-local identity.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

from compliance_guard.domain.enums import SecurityAction, Severity
from compliance_guard.domain.models import DomainModel, Entity, SecurityFinding
from compliance_guard.policy.spans import (
    OffsetSegment,
    SanitizationIntegrityError,
    TextOffsetMap,
)

from .coreference import CoreferenceResult, resolve_mentions
from .token_service import TokenService

AuditCallback = Callable[[str, dict[str, Any]], None]

PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PATIENT_ID_RE = re.compile(r"(?<![A-Za-z0-9])(?:PATIENT|HCP)-\d{4,}(?![A-Za-z0-9])")

_PRIORITY_MENTION = 3
_PRIORITY_ROSTER = 2
_PRIORITY_PATTERN = 1

_DEFAULT_TOKEN_SERVICE = TokenService()


def _default_token_service() -> TokenService:
    return _DEFAULT_TOKEN_SERVICE


def _pseudonym(value: str) -> str:
    """Deterministic stand-in canonical id for a value absent from master data."""
    return f"unknown:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"


class KnownIdentifier(DomainModel):
    """A subject whose raw identifiers may appear in content."""

    entity_type: str
    canonical_id: str
    values: list[str] = []


class SanitizeContext(DomainModel):
    tenant_id: str
    audit_callback: AuditCallback | None = None
    known_identifiers: list[KnownIdentifier] = []
    case_id: str | None = None


class SanitizedContent(DomainModel):
    model_text: str
    spans: dict[str, list[str]]
    offset_map: TextOffsetMap
    findings: list[SecurityFinding] = []
    entities: list[Entity] = []
    resolution: dict[str, Any] = {}
    ambiguous_entities: bool = False


class _Candidate(DomainModel):
    start: int
    end: int
    entity_type: str
    canonical_id: str
    priority: int
    basis: str


class PiiGateway:
    """Masks known and pattern-detected personal identifiers with stable tokens."""

    def __init__(self, token_service: TokenService | None = None) -> None:
        self._token_service = token_service or _default_token_service()

    def _resolve(self, content: str, context: SanitizeContext) -> CoreferenceResult:
        return resolve_mentions(
            content,
            known_identifiers=context.known_identifiers,
            case_id=context.case_id,
        )

    def _candidates(
        self,
        content: str,
        context: SanitizeContext,
        resolution: CoreferenceResult,
    ) -> list[_Candidate]:
        candidates: list[_Candidate] = []

        for cluster in resolution.clusters:
            for mention in cluster.members:
                candidates.append(
                    _Candidate(
                        start=mention.start,
                        end=mention.end,
                        entity_type=cluster.entity_type,
                        canonical_id=cluster.canonical_id,
                        priority=_PRIORITY_MENTION,
                        basis=f"{cluster.resolution_basis}/{mention.basis}",
                    )
                )

        lookup: dict[str, tuple[str, str]] = {}
        for known in context.known_identifiers:
            for value in known.values:
                lookup[value] = (known.entity_type, known.canonical_id)
        for value, (entity_type, canonical_id) in lookup.items():
            for match in re.finditer(re.escape(value), content):
                candidates.append(
                    _Candidate(
                        start=match.start(),
                        end=match.end(),
                        entity_type=entity_type,
                        canonical_id=canonical_id,
                        priority=_PRIORITY_ROSTER,
                        basis="roster_literal",
                    )
                )

        for pattern, default_type in (
            (PHONE_RE, "patient"),
            (EMAIL_RE, "patient"),
            (PATIENT_ID_RE, None),
        ):
            for match in pattern.finditer(content):
                entity_type = default_type
                if pattern is PATIENT_ID_RE:
                    entity_type = "hcp" if match.group(0).startswith("HCP") else "patient"
                candidates.append(
                    _Candidate(
                        start=match.start(),
                        end=match.end(),
                        entity_type=entity_type or "patient",
                        canonical_id=_pseudonym(match.group(0)),
                        priority=_PRIORITY_PATTERN,
                        basis="pattern",
                    )
                )
        return candidates

    def sanitize(self, content: str, context: SanitizeContext) -> SanitizedContent:
        resolution = self._resolve(content, context)
        candidates = self._candidates(content, context, resolution)

        chosen: list[_Candidate] = []
        for priority in (_PRIORITY_MENTION, _PRIORITY_ROSTER, _PRIORITY_PATTERN):
            ordered = sorted(
                (c for c in candidates if c.priority == priority),
                key=lambda c: (c.start, -c.end),
            )
            for candidate in ordered:
                if any(
                    not (candidate.end <= taken.start or candidate.start >= taken.end)
                    for taken in chosen
                ):
                    continue
                chosen.append(candidate)
        chosen.sort(key=lambda c: c.start)

        segments: list[str] = []
        offset_segments: list[OffsetSegment] = []
        previous = 0
        running = 0
        masked: list[tuple[str, str, str]] = []
        for candidate in chosen:
            unchanged = content[previous : candidate.start]
            segments.append(unchanged)
            if unchanged:
                offset_segments.append(
                    OffsetSegment(
                        original_start=previous,
                        original_end=candidate.start,
                        masked_start=running,
                        masked_end=running + len(unchanged),
                    )
                )
            running += candidate.start - previous
            token = self._token_service.tokenize(
                candidate.entity_type, candidate.canonical_id, context.tenant_id
            ).token
            segments.append(token)
            offset_segments.append(
                OffsetSegment(
                    original_start=candidate.start,
                    original_end=candidate.end,
                    masked_start=running,
                    masked_end=running + len(token),
                    replaced=True,
                )
            )
            span = f"char:{running}-{running + len(token)}"
            masked.append((token, candidate.entity_type, span))
            running += len(token)
            previous = candidate.end
        tail = content[previous:]
        segments.append(tail)
        if tail:
            offset_segments.append(
                OffsetSegment(
                    original_start=previous,
                    original_end=len(content),
                    masked_start=running,
                    masked_end=running + len(tail),
                )
            )
        model_text = "".join(segments)
        try:
            offset_map = TextOffsetMap(
                original=content,
                masked=model_text,
                segments=offset_segments,
            )
        except ValueError as error:
            raise SanitizationIntegrityError(
                "sanitization produced an inconsistent offset map"
            ) from error

        spans: dict[str, list[str]] = {}
        findings: list[SecurityFinding] = []
        entities: list[Entity] = []
        for token, entity_type, span in masked:
            spans.setdefault(token, []).append(span)
            findings.append(
                SecurityFinding(
                    type="pii",
                    severity=Severity.S2,
                    action=SecurityAction.REDACT,
                    blocked=True,
                    reason=f"masked {entity_type} identifier before model request",
                    spans=[span],
                )
            )
            entities.append(Entity(type=entity_type, token=token, span=span))

        resolution_audit = resolution.audit_payload()
        if context.audit_callback is not None:
            context.audit_callback(
                "sanitize",
                {
                    "tenant_id": context.tenant_id,
                    "masked_count": len(masked),
                    "tokens": [item[0] for item in masked],
                    "resolution": resolution_audit,
                },
            )

        return SanitizedContent(
            model_text=model_text,
            spans=spans,
            offset_map=offset_map,
            findings=findings,
            entities=entities,
            resolution=resolution_audit,
            ambiguous_entities=resolution.ambiguous,
        )


def sanitize(content: str, context: SanitizeContext) -> SanitizedContent:
    """Mask personal identifiers before a model request and return safe text."""
    return PiiGateway().sanitize(content, context)
