"""Chinese person-name lexicon and mention data contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from compliance_guard.runtime_paths import config_dir

MentionKind = Literal["patient", "hcp"]


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
