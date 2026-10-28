"""Unicode-safe character spans and verified masked-to-original offsets."""

from __future__ import annotations

import re

from pydantic import Field, model_validator

from compliance_guard.domain.models import CharacterSpan, DomainModel


class SanitizationIntegrityError(RuntimeError):
    """Raised when sanitized text cannot be reconstructed from its offset map."""


class OffsetSegment(DomainModel):
    """A contiguous mapping between one original and one sanitized range."""

    original_start: int = Field(ge=0)
    original_end: int = Field(ge=0)
    masked_start: int = Field(ge=0)
    masked_end: int = Field(ge=0)
    replaced: bool = False

    @model_validator(mode="after")
    def _valid_ranges(self) -> "OffsetSegment":
        if self.original_end < self.original_start:
            raise ValueError("original offset range is reversed")
        if self.masked_end < self.masked_start:
            raise ValueError("masked offset range is reversed")
        if not self.replaced:
            original_length = self.original_end - self.original_start
            masked_length = self.masked_end - self.masked_start
            if original_length != masked_length:
                raise ValueError("unchanged segments must have equal lengths")
        return self


class TextOffsetMap(DomainModel):
    """Maps ranges in sanitized text back to their source text."""

    original: str
    masked: str
    segments: list[OffsetSegment]

    @model_validator(mode="after")
    def _segments_cover_both_texts(self) -> "TextOffsetMap":
        original_cursor = 0
        masked_cursor = 0
        original_parts: list[str] = []
        masked_parts: list[str] = []
        for segment in self.segments:
            if (
                segment.original_start != original_cursor
                or segment.masked_start != masked_cursor
            ):
                raise ValueError("offset segments must be contiguous")
            original_slice = self.original[segment.original_start : segment.original_end]
            masked_slice = self.masked[segment.masked_start : segment.masked_end]
            if not segment.replaced and original_slice != masked_slice:
                raise ValueError("unchanged segment text differs")
            original_parts.append(original_slice)
            masked_parts.append(masked_slice)
            original_cursor = segment.original_end
            masked_cursor = segment.masked_end
        if original_cursor != len(self.original) or masked_cursor != len(self.masked):
            raise ValueError("offset segments do not cover the complete text")
        if "".join(original_parts) != self.original:
            raise ValueError("original text reconstruction failed")
        if "".join(masked_parts) != self.masked:
            raise ValueError("masked text reconstruction failed")
        return self

    def to_original(self, start: int, end: int) -> CharacterSpan | None:
        """Map a wholly unchanged sanitized range, or reject an unsafe range."""
        if start < 0 or end < start or end > len(self.masked):
            return None
        for segment in self.segments:
            if segment.replaced:
                continue
            if segment.masked_start <= start and end <= segment.masked_end:
                offset = segment.original_start - segment.masked_start
                return CharacterSpan(start=start + offset, end=end + offset)
        return None


def find_spans(text: str, patterns: list[str]) -> list[CharacterSpan]:
    """Return deterministic, de-duplicated literal matches in Unicode order."""
    found: list[CharacterSpan] = []
    seen: set[tuple[int, int]] = set()
    for pattern in patterns:
        if not pattern:
            continue
        for match in re.finditer(re.escape(pattern), text, re.IGNORECASE):
            key = (match.start(), match.end())
            if key in seen:
                continue
            seen.add(key)
            found.append(CharacterSpan(start=match.start(), end=match.end()))
    return sorted(found, key=lambda span: (span.start, span.end))


__all__ = [
    "OffsetSegment",
    "SanitizationIntegrityError",
    "TextOffsetMap",
    "find_spans",
]
