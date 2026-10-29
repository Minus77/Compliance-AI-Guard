"""Structured, versioned label facts and closed-world label field comparison."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .label_contracts import LabelComparison, LabelFacts

_COMPARED_FIELDS = ("indication", "population", "line", "dose", "route", "duration", "combination")


def _normalize(value: Any) -> str:
    """Canonical form for comparison: whitespace-free and case-folded.

    Hedges are deliberately *not* stripped here. A recognized hedge makes the
    field unasserted (see :func:`_is_asserted`), so a hedged value never reaches
    an equality comparison; handling it in both places would be redundant and
    would invite the two rules to drift apart.
    """
    if value is None:
        return ""
    return "".join(str(value).strip().casefold().split())


# Values a model uses to mean "the content does not say". They are absences, not
# assertions, and must never be compared against the approved label. Observed
# from a live provider on a single case: "未指定", "未明确说明", "不详".
_UNASSERTED = frozenset(
    {
        "",
        "null",
        "none",
        "n/a",
        "na",
        "unknown",
        "not specified",
        "not stated",
        "未知",
        "无",
        "不详",
        "未提及",
        "未指定",
        "未说明",
        "未明确",
        "未明确说明",
        "未记录",
        "不适用",
    }
)

# Hedges a model appends when it inferred a value rather than reading it. A live
# provider returned route as "口服（推断）" and "口服（未明确说明）" for content
# that never stated a route. Comparing the decorated string against the label's
# "口服" produced a false off-label mismatch, so the hedge is separated from the
# value before comparison: the bare value is compared, and a hedge that means
# "not stated" makes the field unasserted.
_HEDGE_RE = re.compile(r"[（(]\s*([^（()）]*)\s*[)）]\s*$")

_INFERENCE_HEDGES = frozenset({"推断", "推测", "推定", "隐含", "假设", "inferred", "assumed", "implied"})


def _recognized_hedge(hedge: str) -> bool:
    """True only for parentheticals that mean "inferred" or "not stated".

    Deliberately narrow. Any other parenthetical is treated as part of the claim,
    because a qualifier can be clinically meaningful -- "成人（18岁以上）" is a
    population claim, not a hedge. Discounting unknown parentheticals would
    silently widen what counts as on-label, so the conservative direction is to
    compare them verbatim and let a reviewer see the difference.
    """
    folded = hedge.casefold()
    return folded in _INFERENCE_HEDGES or folded in _UNASSERTED


def _strip_hedge(value: str) -> tuple[str, str | None]:
    """Split a *recognized* trailing hedge from a value.

    Returns ``(bare_value, hedge)`` when the trailing parenthetical is a
    recognized hedge, otherwise ``(value, None)`` so the value is compared as
    written. Only a trailing parenthetical is ever considered.
    """
    text = value.strip()
    match = _HEDGE_RE.search(text)
    if match is None:
        return text, None

    hedge = match.group(1).strip()
    if not _recognized_hedge(hedge):
        return text, None

    return text[: match.start()].strip(), hedge


def _is_asserted(value: Any) -> bool:
    """True when the extraction actually claims something for this field.

    Silence is not a contradiction. If content never mentions the dose,
    that is not an off-label dose claim -- it is simply a field the
    representative did not talk about. Comparing unasserted fields would turn
    every short, perfectly compliant note into an off-label finding, which is
    exactly the false-positive pattern that makes representatives distrust the
    tool.

    A value whose hedge says the model inferred it, or whose bare value is one of
    the "not stated" markers, is also treated as unasserted: an inference is not
    something the representative wrote, so it must not create a label finding.
    """
    if value is None:
        return False
    if isinstance(value, (list, dict)):
        return bool(value)

    text = str(value).strip()
    bare, hedge = _strip_hedge(text)

    # A recognized hedge means the model inferred the value or admitted the
    # content never stated it. Either way the representative did not claim it, so
    # it must not create a label finding.
    if hedge is not None:
        return False

    return bare.casefold() not in _UNASSERTED


# Fields whose value is meaningless without a quantity. A dose is always
# quantitative, so a value carrying no digit is not a dose claim.
_QUANTITATIVE_FIELDS = frozenset({"dose"})

_DIGIT_RE = re.compile(r"\d")


def _is_asserted_for(field: str, value: Any) -> bool:
    """Field-aware version of :func:`_is_asserted`.

    Regression guard for a live-model extraction defect: on "推荐口服给药，一次。"
    the model placed the frequency "一次" into ``dose``. Compared against the
    approved "80mg" that read as an off-label dose claim and turned a compliant
    sentence into an S1 finding.

    A dose without a digit cannot be a dose, so it is treated as unasserted
    rather than as a contradiction. Non-quantitative fields are unaffected.
    """
    if not _is_asserted(value):
        return False
    if field in _QUANTITATIVE_FIELDS and not _DIGIT_RE.search(str(value)):
        return False
    return True


def compare_label_fields(extracted: dict[str, Any], label_facts: LabelFacts) -> LabelComparison:
    """Compare structured label fields as closed-world facts.

    Indication is matched by ``indication_id`` when the extraction provides
    one, otherwise by indication text. Every compared field is deterministic;
    a mismatch is reported per field and never overridden by semantic signals.

    Only *asserted* fields are compared. A field the extraction did not claim is
    reported as ``asserted: False`` in ``details`` and never counted as a
    mismatch, so an incomplete note cannot fabricate an off-label finding. The
    comparison stays closed-world for everything actually claimed: an asserted
    value that is absent from the label is still a mismatch.
    """
    mismatches: list[str] = []
    details: dict[str, dict[str, Any]] = {}

    for field in _COMPARED_FIELDS:
        if field == "indication":
            expected_id = label_facts.indication_id
            expected_text = label_facts.indication
            actual = extracted.get("indication_id", extracted.get("indication"))
            expected = expected_id or expected_text
            asserted = _is_asserted_for("indication", actual)
            matched = False
            if asserted:
                if expected_id and str(actual) == str(expected_id):
                    matched = True
                elif _normalize(actual) and _normalize(actual) == _normalize(expected_text):
                    matched = True
            elif not expected_id and not expected_text:
                matched = True
        else:
            expected = getattr(label_facts, field)
            actual = extracted.get(field)
            asserted = _is_asserted_for(field, actual)
            if not asserted:
                matched = not _normalize(expected)
            else:
                matched = _normalize(actual) == _normalize(expected)

        # An unasserted field is silence, not a contradiction; never a mismatch.
        if not matched and asserted:
            mismatches.append(field)
        details[field] = {
            "expected": expected,
            "actual": actual,
            "matched": matched,
            "asserted": asserted,
        }

    return LabelComparison(matches=len(mismatches) == 0, mismatches=mismatches, details=details)


def _fixtures_dir() -> Path:
    from compliance_guard.runtime_paths import fixtures_dir

    # Read-only resource: ships inside the bundle when frozen.
    return fixtures_dir()


class LabelFactsStore:
    """Versioned LabelFacts repository backed by the fixtures file."""

    def __init__(self, fixtures_path: str | Path | None = None) -> None:
        path = Path(fixtures_path) if fixtures_path else _fixtures_dir() / "label_facts.json"
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        self._labels = [LabelFacts.model_validate(item) for item in raw["labels"]]

    def _candidates(self, product_id: str, market: str) -> list[LabelFacts]:
        return [
            label
            for label in self._labels
            if label.product_id == product_id and label.market == market
        ]

    def current(
        self,
        product_id: str,
        market: str,
        version: str | None = None,
    ) -> LabelFacts:
        candidates = self._candidates(product_id, market)
        if not candidates:
            raise ValueError(
                f"unknown label facts for product {product_id!r} in market {market!r}"
            )
        if version is not None:
            for label in candidates:
                if label.version == version:
                    return label
            raise ValueError(
                f"unknown label facts version {version!r} for product {product_id!r} in market {market!r}"
            )
        return max(
            candidates,
            key=lambda label: (
                label.effective_to is None,
                label.effective_from or datetime.min.replace(tzinfo=UTC),
            ),
        )

    def products(self, market: str | None = None, as_of: datetime | None = None) -> list[LabelFacts]:
        """Current label per product/market pair.

        Only the version in force is returned. Offering a retired version in a
        product picker would let someone write against a label that no longer
        applies, which is an off-label claim created by the tool itself.
        """
        moment = as_of or datetime.now(UTC)
        pairs = sorted({(label.product_id, label.market) for label in self._labels})
        current: list[LabelFacts] = []
        for product_id, label_market in pairs:
            if market is not None and label_market != market:
                continue
            candidates = [
                label
                for label in self._candidates(product_id, label_market)
                if (label.effective_from is None or label.effective_from <= moment)
                and (label.effective_to is None or label.effective_to >= moment)
            ]
            if not candidates:
                continue
            current.append(
                max(
                    candidates,
                    key=lambda label: (
                        label.effective_to is None,
                        label.effective_from or datetime.min.replace(tzinfo=UTC),
                    ),
                )
            )
        return current

    def markets(self) -> list[str]:
        return sorted({label.market for label in self._labels})

    def compare_label_fields(
        self,
        extracted: dict[str, Any],
        label_facts: LabelFacts,
    ) -> LabelComparison:
        return compare_label_fields(extracted, label_facts)
