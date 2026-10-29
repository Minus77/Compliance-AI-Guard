"""Server-side derivation of label-comparable facts from narrative text.

This module exists to break a circular trust problem (defect P-1). Off-label
judgment needs structured fields, the client was the only source of them, and so
content effectively vouched for itself: declaring ``indication_id=IND-001``
suppressed off-label detection on a narrative that plainly promoted another
disease.

The fix is to derive those fields here, from the text, deterministically:

* ``claimed_fields`` — what the client said. Useful for prefilling forms and for
  cross-checking, never an input to the decision.
* ``resolved_fields`` — what the server found in the narrative. The only facts
  judgment reads.

A disagreement between the two is not discarded, it is *reported*: declaring one
indication while describing another is exactly the pattern worth a human look, so
P-1 turns from a bypass into a detection.

Extraction is intentionally conservative. Only clearly present values are
asserted, because a fabricated field would create a false off-label finding, and
an unasserted field is silence rather than contradiction downstream.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from compliance_guard.knowledge.field_contracts import FieldResolution
from .indication_resolver import IndicationMatch, IndicationResolver

# Patterns cover the shapes business content actually uses. Each maps a surface form
# to the canonical vocabulary the label facts are written in, so comparison stays
# a string equality check on normalised values.
_POPULATION_TERMS = (
    ("成人", "成人"),
    ("成年", "成人"),
    ("儿童", "儿童"),
    ("小儿", "儿童"),
    ("青少年", "青少年"),
    ("老年", "老年"),
    ("孕妇", "孕妇"),
    ("妊娠", "孕妇"),
    ("哺乳期", "哺乳期"),
)

_ROUTE_TERMS = (
    ("口服", "口服"),
    ("静脉注射", "静脉注射"),
    ("静脉滴注", "静脉滴注"),
    ("皮下注射", "皮下注射"),
    ("肌肉注射", "肌肉注射"),
    ("外用", "外用"),
    ("舌下", "舌下"),
    ("吸入", "吸入"),
)

_LINE_TERMS = (
    ("一线", "一线"),
    ("二线", "二线"),
    ("三线", "三线"),
    ("末线", "末线"),
)

_DURATION_TERMS = (
    ("长期", "长期"),
    ("短期", "短期"),
    ("单次", "单次"),
    ("终身", "终身"),
)

_COMBINATION_TERMS = (
    ("单药", "单药"),
    ("单独使用", "单药"),
    ("联合用药", "联用"),
    ("联合使用", "联用"),
    ("联用", "联用"),
    ("合用", "联用"),
)

# ``\b`` is useless as a closing boundary here: CJK counts as a word character,
# so "80mg口服" would not match and the dose would silently go unresolved.
_DOSE_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*(mg|g|ml|ug|μg|mcg|IU)(?![A-Za-z0-9])",
    re.IGNORECASE,
)

_COMPARABLE_FIELDS = (
    "indication_id",
    "population",
    "line",
    "dose",
    "route",
    "duration",
    "combination",
)


def _normalize(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", "", str(value)).casefold()


def _first_term(text: str, terms: tuple[tuple[str, str], ...]) -> tuple[str | None, str | None]:
    """Earliest matching surface form, with the canonical value it maps to.

    Longest-first within one starting position, so 联合用药 is not read as 联用.
    """
    best: tuple[int, int, str, str] | None = None
    for surface, canonical in terms:
        index = text.find(surface)
        if index < 0:
            continue
        key = (index, -len(surface))
        if best is None or key < (best[0], best[1]):
            best = (index, -len(surface), canonical, surface)
    if best is None:
        return None, None
    return best[2], best[3]


class FieldResolver:
    """Derives label-comparable fields from narrative text, without a model."""

    def __init__(self, indication_resolver: IndicationResolver | None = None) -> None:
        self._indications = indication_resolver or IndicationResolver()

    def resolve(
        self,
        text: str,
        *,
        market: str,
        as_of: datetime | None = None,
        claimed_fields: dict[str, Any] | None = None,
        model_fields: dict[str, Any] | None = None,
    ) -> FieldResolution:
        """Resolve fields from ``text``, then cross-check the client's claims.

        ``model_fields`` are the extractor's candidates. They are treated like
        another observation of the text — they can *add* a field the patterns
        missed, but never overwrite one the server derived itself, and they never
        carry a decision.
        """
        content = text or ""
        resolved: dict[str, Any] = {}
        basis: dict[str, str] = {}

        match = self._indications.resolve(content, market=market, as_of=as_of)
        if match.resolved:
            resolved["indication_id"] = match.indication_id
            resolved["indication"] = match.canonical_name
            basis["indication"] = match.basis
        else:
            model_indication = (model_fields or {}).get("indication")
            if model_indication:
                # The model saw an indication the ontology cannot place. Record
                # that as unresolved so the workflow asks, rather than treating
                # silence and "unknown disease" as the same thing.
                remapped = self._indications.resolve(
                    str(model_indication), market=market, as_of=as_of
                )
                if remapped.resolved:
                    resolved["indication_id"] = remapped.indication_id
                    resolved["indication"] = remapped.canonical_name
                    basis["indication"] = f"model_text/{remapped.basis}"
                    match = remapped
                else:
                    basis["indication"] = "unresolved_mention"

        for field, terms in (
            ("population", _POPULATION_TERMS),
            ("route", _ROUTE_TERMS),
            ("line", _LINE_TERMS),
            ("duration", _DURATION_TERMS),
            ("combination", _COMBINATION_TERMS),
        ):
            canonical, surface = _first_term(content, terms)
            if canonical is not None:
                resolved[field] = canonical
                basis[field] = f"pattern:{surface}"

        dose = _DOSE_RE.search(content)
        if dose is not None:
            resolved["dose"] = f"{dose.group(1)}{dose.group(2).lower()}"
            basis["dose"] = "pattern:dose"

        for field, value in (model_fields or {}).items():
            if field in {"indication", "indication_id"}:
                continue
            if field in resolved or value in (None, ""):
                continue
            resolved[field] = value
            basis[field] = "model_candidate"

        claimed = dict(claimed_fields or {})
        discrepancies = self._discrepancies(claimed, resolved)

        return FieldResolution(
            resolved_fields=resolved,
            claimed_fields=claimed,
            discrepancies=discrepancies,
            indication_match=match,
            basis=basis,
        )

    @staticmethod
    def _discrepancies(claimed: dict[str, Any], resolved: dict[str, Any]) -> list[str]:
        """Fields where client and server both spoke and disagreed.

        Silence on either side is not a conflict: an incomplete form is normal,
        and a field the narrative never mentions cannot contradict anything.
        """
        conflicts: list[str] = []
        for field in _COMPARABLE_FIELDS:
            claim = claimed.get(field)
            fact = resolved.get(field)
            if field == "indication_id" and not claim:
                claim = claimed.get("indication")
                if claim and fact:
                    # A textual claim is compared on the concept it denotes.
                    continue
            if not claim or not fact:
                continue
            if _normalize(claim) != _normalize(fact):
                conflicts.append(field)
        return conflicts


__all__ = ["FieldResolution", "FieldResolver"]
