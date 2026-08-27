"""Deterministic paragraph/character-window chunking for label content."""

from __future__ import annotations

import re

_BLANK_LINE_RE = re.compile(r"\n[ \t]*\n")


def chunk_text(text: str, max_chars: int = 300) -> list[tuple[str, str]]:
    """Split text into ``(location, chunk_text)`` pairs.

    Paragraphs are separated on blank lines. Consecutive paragraphs are merged
    into a single chunk while the combined span stays within ``max_chars``.
    Each returned location is a ``char:start-end`` span where
    ``text[start:end] == chunk_text``.
    """
    if not text:
        return []
    if not text.strip():
        return []

    spans: list[tuple[int, int]] = []
    pos = 0
    for match in _BLANK_LINE_RE.finditer(text):
        if text[pos : match.start()].strip():
            spans.append((pos, match.start()))
        pos = match.end()
    if text[pos:].strip():
        spans.append((pos, len(text)))
    if not spans:
        spans.append((0, len(text)))

    chunks: list[tuple[int, int]] = []
    start: int | None = None
    end: int | None = None
    for span_start, span_end in spans:
        if start is None:
            start, end = span_start, span_end
        elif span_end - start <= max_chars:
            end = span_end
        else:
            chunks.append((start, end))
            start, end = span_start, span_end
    if start is not None and end is not None:
        chunks.append((start, end))

    return [(f"char:{start}-{end}", text[start:end]) for start, end in chunks]