"""Single source of truth for user-facing vocabulary.

The requirement is that everything a user reads is plain language, with any
professional term explained where it appears. That only holds if there is exactly
one place the wording lives: the moment an explanation is duplicated in the UI, the
API and a report, the three copies start to drift, and the one a reviewer quotes
in an audit is whichever happens to be stalest.

So ``config/glossary.json`` is the source and this module is the only reader.
Nothing here invents wording; a missing entry is reported as missing rather than
silently replaced by a machine code, because a bare ``CN-009`` on screen is the
exact failure this file exists to prevent.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field

from compliance_guard.domain.models import DomainModel
from compliance_guard.runtime_paths import config_dir

DEFAULT_LOCALE = "zh-CN"
FALLBACK_LOCALE = "en"


class FindingExplanation(DomainModel):
    """The three sentences a user needs, in a fixed order.

    Order is deliberate and never varies: what happened, why it matters, what to
    do next. A reader acting under time pressure should be able to stop after the
    third sentence and still be correct.
    """

    title: str = ""
    why: str = ""
    what_to_do: str = ""
    term_label: str = ""
    term_plain: str = ""
    # The machine code stays available for audit reconciliation, but never as the
    # only thing shown.
    finding_type: str = ""
    rule_id: str | None = None


class DecisionExplanation(DomainModel):
    label: str = ""
    plain: str = ""
    next_step: str = ""
    decision: str = ""


class TermExplanation(DomainModel):
    key: str = ""
    label: str = ""
    plain: str = ""
    why_it_matters: str = ""


def _default_path() -> Path:
    return config_dir() / "glossary.json"


@lru_cache(maxsize=4)
def _load(path_text: str) -> dict[str, Any]:
    return json.loads(Path(path_text).read_text(encoding="utf-8"))


class Glossary:
    """Reader for the vocabulary file."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else _default_path()

    @property
    def data(self) -> dict[str, Any]:
        return _load(str(self._path))

    @property
    def version(self) -> str:
        return str(self.data.get("glossary_version", "unknown"))

    @property
    def locales(self) -> list[str]:
        return list(self.data.get("locales", [DEFAULT_LOCALE]))

    @staticmethod
    def _localised(entry: dict[str, Any], locale: str) -> dict[str, Any]:
        for candidate in (locale, DEFAULT_LOCALE, FALLBACK_LOCALE):
            value = entry.get(candidate)
            if isinstance(value, dict):
                return value
        return {}

    def term(self, key: str, locale: str = DEFAULT_LOCALE) -> TermExplanation:
        entry = self.data.get("terms", {}).get(key)
        if not isinstance(entry, dict):
            return TermExplanation(key=key)
        localised = self._localised(entry, locale)
        return TermExplanation(
            key=key,
            label=str(localised.get("label", "")),
            plain=str(localised.get("plain", "")),
            why_it_matters=str(localised.get("why_it_matters", "")),
        )

    def explain_finding(
        self,
        finding_type: str,
        locale: str = DEFAULT_LOCALE,
        *,
        rule_id: str | None = None,
    ) -> FindingExplanation:
        """Plain-language card for one finding type."""
        entry = self.data.get("finding_types", {}).get(finding_type)
        if not isinstance(entry, dict):
            return FindingExplanation(finding_type=finding_type, rule_id=rule_id)
        localised = self._localised(entry, locale)
        term = self.term(str(entry.get("term", "")), locale) if entry.get("term") else TermExplanation()
        return FindingExplanation(
            title=str(localised.get("title", "")),
            why=str(localised.get("why", "")),
            what_to_do=str(localised.get("what_to_do", "")),
            term_label=term.label,
            term_plain=term.plain,
            finding_type=finding_type,
            rule_id=rule_id,
        )

    def explain_decision(self, decision: str, locale: str = DEFAULT_LOCALE) -> DecisionExplanation:
        entry = self.data.get("decisions", {}).get(decision)
        if not isinstance(entry, dict):
            return DecisionExplanation(decision=decision)
        localised = self._localised(entry, locale)
        return DecisionExplanation(
            label=str(localised.get("label", "")),
            plain=str(localised.get("plain", "")),
            next_step=str(localised.get("next_step", "")),
            decision=decision,
        )

    def explain_severity(self, severity: str, locale: str = DEFAULT_LOCALE) -> dict[str, str]:
        entry = self.data.get("severities", {}).get(severity)
        if not isinstance(entry, dict):
            return {"label": "", "plain": "", "severity": severity}
        localised = self._localised(entry, locale)
        return {
            "label": str(localised.get("label", "")),
            "plain": str(localised.get("plain", "")),
            "severity": severity,
        }

    def missing_finding_types(self, finding_types: list[str]) -> list[str]:
        """Finding types with no explanation. Used as a coverage gate in tests."""
        known = set(self.data.get("finding_types", {}))
        return sorted({value for value in finding_types if value not in known})

    def payload(self, locale: str = DEFAULT_LOCALE) -> dict[str, Any]:
        """Everything the client needs to render tooltips in one response."""
        return {
            "glossary_version": self.version,
            "locale": locale,
            "locales": self.locales,
            "terms": {
                key: self.term(key, locale).model_dump(mode="json")
                for key in self.data.get("terms", {})
            },
            "finding_types": {
                key: self.explain_finding(key, locale).model_dump(mode="json")
                for key in self.data.get("finding_types", {})
            },
            "decisions": {
                key: self.explain_decision(key, locale).model_dump(mode="json")
                for key in self.data.get("decisions", {})
            },
            "severities": {
                key: self.explain_severity(key, locale)
                for key in self.data.get("severities", {})
            },
        }


_DEFAULT = Glossary()


def default_glossary() -> Glossary:
    return _DEFAULT


__all__ = [
    "DEFAULT_LOCALE",
    "DecisionExplanation",
    "FindingExplanation",
    "Glossary",
    "TermExplanation",
    "default_glossary",
]
