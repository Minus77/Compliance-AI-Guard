"""Surname-anchored Chinese person-name detection.

Two properties matter more than raw accuracy here, and they pull in opposite
directions from the old regex approach:

**Source fidelity.** A detected mention exposes the span of the *name only*.
Context words ("患者", "医生") are never part of the span, so masking can replace
the identifier without corrupting the narrative that downstream adverse-event
keyword matching reads (defect D-1).

**Position invariance.** Name starts are anchored on a surname dictionary rather
than a fixed-width backward capture, so "章主任" resolves to 章 whether it sits at
the start of a sentence or after "后来" (defect D-2). The old
``([\\u4e00-\\u9fa5]{1,2})(?:医生|主任|...)`` captured "来章" in the latter case and
then dropped the mention entirely, making masking depend on the preceding
character.

Detection is local and deterministic: no model call, no network. That is a hard
constraint, because this runs on *unmasked* text.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from compliance_guard.runtime_paths import config_dir

MentionKind = Literal["patient", "hcp"]

_MAX_GIVEN_NAME_LEN = 2


@dataclass(frozen=True)
class NameMention:
    """One person mention found in raw text.

    ``start``/``end`` bound the name itself. ``title`` and ``prefix`` record the
    surrounding context words that identified it, and are deliberately excluded
    from the span so they survive masking.
    """

    start: int
    end: int
    text: str
    entity_type: MentionKind
    surname: str
    title: str = ""
    prefix: str = ""
    basis: str = "surname_anchor"

    @property
    def span(self) -> tuple[int, int]:
        return (self.start, self.end)


class NameLexicon:
    """Surname, title and boundary vocabulary loaded from ``config/surnames.json``."""

    def __init__(self, payload: dict) -> None:
        self.single_surnames: frozenset[str] = frozenset(payload.get("single_char_surnames", []))
        self.compound_surnames: tuple[str, ...] = tuple(
            sorted(payload.get("compound_surnames", []), key=len, reverse=True)
        )
        self.hcp_titles: tuple[str, ...] = tuple(
            sorted(payload.get("hcp_titles", []), key=len, reverse=True)
        )
        self.patient_prefixes: tuple[str, ...] = tuple(
            sorted(payload.get("patient_prefixes", []), key=len, reverse=True)
        )
        self.visit_verbs: tuple[str, ...] = tuple(
            sorted(payload.get("visit_verbs", []), key=len, reverse=True)
        )
        self.mention_verbs: tuple[str, ...] = tuple(
            sorted(payload.get("mention_verbs", []), key=len, reverse=True)
        )
        self.coordinators: tuple[str, ...] = tuple(
            sorted(payload.get("coordinators", []), key=len, reverse=True)
        )
        # Coordinators end a name: in "章三和章丽" the 和 belongs to the sentence,
        # not to 章三, and swallowing it would hide the second person entirely.
        self.boundary_words: frozenset[str] = frozenset(
            list(payload.get("boundary_words", [])) + list(payload.get("coordinators", []))
        )
        self.version: str = str(payload.get("version", "unknown"))

    def is_surname(self, char: str) -> bool:
        return char in self.single_surnames

    def compound_at(self, text: str, index: int) -> str | None:
        for candidate in self.compound_surnames:
            if text.startswith(candidate, index):
                return candidate
        return None

    def title_at(self, text: str, index: int) -> str | None:
        for title in self.hcp_titles:
            if text.startswith(title, index):
                return title
        return None


@lru_cache(maxsize=1)
def load_lexicon() -> NameLexicon:
    path = config_dir() / "surnames.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return NameLexicon(payload)


def _is_cjk(char: str) -> bool:
    return "\u4e00" <= char <= "\u9fa5"


def _given_name_length(text: str, start: int, lexicon: NameLexicon, *, limit: int) -> int:
    """Longest run of CJK characters after the surname that still looks like a name.

    Stops before any boundary word, so "李四出现皮疹" yields 四 rather than 四出.
    """
    length = 0
    while length < limit:
        index = start + length
        if index >= len(text) or not _is_cjk(text[index]):
            break
        # A boundary word starting here ends the name.
        if any(
            text.startswith(word, index)
            for word in lexicon.boundary_words
            if len(word) <= len(text) - index
        ):
            break
        # A title starting here ends the name (章医生 -> 章).
        if lexicon.title_at(text, index) is not None:
            break
        length += 1
    return length


def _mention_at(
    text: str,
    index: int,
    lexicon: NameLexicon,
    *,
    entity_type: MentionKind,
    prefix: str,
    basis: str,
    require_given_name: bool,
    max_given: int = _MAX_GIVEN_NAME_LEN,
) -> NameMention | None:
    compound = lexicon.compound_at(text, index)
    if compound is not None:
        surname = compound
    elif index < len(text) and lexicon.is_surname(text[index]):
        surname = text[index]
    else:
        return None

    given_start = index + len(surname)
    given_len = _given_name_length(text, given_start, lexicon, limit=max_given)
    if require_given_name and given_len == 0:
        return None

    end = given_start + given_len
    title = lexicon.title_at(text, end) or ""
    return NameMention(
        start=index,
        end=end,
        text=text[index:end],
        entity_type=entity_type,
        surname=surname,
        title=title,
        prefix=prefix,
        basis=basis,
    )


def find_mentions(text: str) -> list[NameMention]:
    """All person-name mentions in ``text``, ordered by position, non-overlapping.

    Three independent cues, in descending precision:

    1. ``患者X`` / ``病人X`` — patient prefix.
    2. ``X医生`` / ``X主任`` — HCP title following a surname-anchored name.
    3. ``拜访了X`` / ``X反馈`` — visit and mention verbs around a surname.

    A final pass follows coordinators ("和", "与", "、") so a second person named
    only by coordination is still detected.
    """
    lexicon = load_lexicon()
    found: list[NameMention] = []

    def claim(mention: NameMention | None) -> None:
        if mention is None or mention.end <= mention.start:
            return
        for existing in found:
            if not (mention.end <= existing.start or mention.start >= existing.end):
                return
        found.append(mention)

    # Cue 1: explicit patient prefix.
    for prefix in lexicon.patient_prefixes:
        start = 0
        while True:
            index = text.find(prefix, start)
            if index < 0:
                break
            start = index + len(prefix)
            claim(
                _mention_at(
                    text,
                    start,
                    lexicon,
                    entity_type="patient",
                    prefix=prefix,
                    basis="patient_prefix",
                    require_given_name=True,
                )
            )

    # Cue 2: HCP title. Anchor the surname by scanning left over at most
    # one compound or one single surname plus its given name.
    for title in lexicon.hcp_titles:
        start = 0
        while True:
            title_index = text.find(title, start)
            if title_index < 0:
                break
            start = title_index + 1
            for name_len in range(1 + _MAX_GIVEN_NAME_LEN, 0, -1):
                name_start = title_index - name_len
                if name_start < 0:
                    continue
                candidate = _mention_at(
                    text,
                    name_start,
                    lexicon,
                    entity_type="hcp",
                    prefix="",
                    basis="hcp_title",
                    require_given_name=False,
                )
                if candidate is not None and candidate.end == title_index:
                    claim(candidate)
                    break

    # Cue 3: visit verbs ("拜访了X") and mention verbs ("X反馈").
    for verb in lexicon.visit_verbs:
        start = 0
        while True:
            index = text.find(verb, start)
            if index < 0:
                break
            start = index + len(verb)
            claim(
                _mention_at(
                    text,
                    start,
                    lexicon,
                    entity_type="hcp",
                    prefix=verb,
                    basis="visit_verb",
                    require_given_name=True,
                )
            )

    for verb in lexicon.mention_verbs:
        start = 0
        while True:
            verb_index = text.find(verb, start)
            if verb_index < 0:
                break
            start = verb_index + 1
            for name_len in range(1 + _MAX_GIVEN_NAME_LEN, 1, -1):
                name_start = verb_index - name_len
                if name_start < 0:
                    continue
                candidate = _mention_at(
                    text,
                    name_start,
                    lexicon,
                    entity_type="hcp",
                    prefix="",
                    basis="mention_verb",
                    require_given_name=True,
                )
                if candidate is not None and candidate.end == verb_index:
                    claim(candidate)
                    break

    # Coordinator chaining: in "拜访了章三和章丽" the second name carries no cue of
    # its own — it inherits the role of the mention it is coordinated with. Without
    # this pass 章丽 goes undetected and therefore unmasked.
    cursor = 0
    while cursor < len(found):
        anchor_mention = found[cursor]
        cursor += 1
        for coordinator in lexicon.coordinators:
            if not text.startswith(coordinator, anchor_mention.end):
                continue
            claim(
                _mention_at(
                    text,
                    anchor_mention.end + len(coordinator),
                    lexicon,
                    entity_type=anchor_mention.entity_type,
                    prefix=coordinator,
                    basis="coordinator_chain",
                    require_given_name=True,
                )
            )

    found.sort(key=lambda mention: mention.start)
    return found


__all__ = ["NameLexicon", "NameMention", "find_mentions", "load_lexicon"]
