"""Deterministic indication normalisation against a local ontology.

This is the answer to "our products have many long labels" (defect D-5). The
naive approach — put the label text in the prompt — fails three ways at once:
context dilution, latency that scales with document length, and cost that scales
with product count. Instead the model only extracts candidate indication *text*,
and this module maps that text to a concept id using a local synonym and
hierarchy table.

Consequences worth being explicit about:

* **What reaches a model stays constant.** One product's structured facts, never
  label prose. Going from 1 product to 500 grows this JSON file, not the prompt.
* **The resolver never judges on-label or off-label.** It answers "which concept
  is this?" and nothing else; the closed-world comparison lives in the policy
  layer, so every off-label conclusion is reproducible and points at a concept id.
* **No match is a real answer.** An unrecognised indication returns ``None`` so
  the workflow can ask a question. Guessing here would be the one failure mode
  that is both silent and wrong.

Hierarchy is deliberately not transitive downward: matching the broad category
心血管疾病 is flagged via ``is_broader_match`` and never satisfies a specific
label, and a child concept such as 儿童原发性高血压 does not satisfy an
adult-only label. Same disease, different population, different approval.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field

from compliance_guard.domain.models import DomainModel
from compliance_guard.runtime_paths import fixtures_dir

CANONICAL_CONFIDENCE = 0.99
SYNONYM_CONFIDENCE = 0.95
BROADER_CONFIDENCE = 0.60


class IndicationConcept(DomainModel):
    """One versioned, market-scoped indication concept."""

    indication_id: str
    canonical_name: str
    synonyms: list[str] = Field(default_factory=list)
    parent_id: str | None = None
    market: str
    version: str
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    note: str = ""

    def is_effective(self, as_of: datetime) -> bool:
        if self.effective_from is not None and as_of < self.effective_from:
            return False
        if self.effective_to is not None and as_of > self.effective_to:
            return False
        return True

    def surface_forms(self) -> list[tuple[str, str]]:
        """Matchable strings paired with the basis they establish."""
        forms = [(self.canonical_name, "canonical_name")]
        forms.extend((synonym, "synonym") for synonym in self.synonyms)
        return forms


class IndicationMatch(DomainModel):
    """Outcome of one resolution attempt.

    ``indication_id is None`` means unresolved, which is a legitimate answer and
    must route to a clarifying question rather than a conclusion.
    """

    indication_id: str | None = None
    canonical_name: str | None = None
    basis: str = "unresolved"
    confidence: float = 0.0
    matched_text: str | None = None
    ontology_version: str | None = None
    parent_id: str | None = None
    is_broader_category: bool = False

    @property
    def resolved(self) -> bool:
        return self.indication_id is not None

    @property
    def is_broader_match(self) -> bool:
        """True when only a broader category matched, which cannot imply on-label."""
        return self.is_broader_category

    def covers(self, label_indication_id: str | None) -> bool:
        """Whether this match satisfies the label's approved indication.

        Exact concept identity only. A broader category is too coarse to imply
        approval, and a narrower child concept (paediatric versus adult) is a
        different approval question, so neither direction of the hierarchy is
        treated as coverage.
        """
        if not self.resolved or not label_indication_id:
            return False
        if self.is_broader_category:
            return False
        return self.indication_id == label_indication_id

    def audit_payload(self) -> dict[str, Any]:
        return {
            "indication_id": self.indication_id,
            "basis": self.basis,
            "confidence": self.confidence,
            "ontology_version": self.ontology_version,
            "is_broader_category": self.is_broader_category,
        }


def _default_ontology_path() -> Path:
    return fixtures_dir() / "indication_ontology.json"


@lru_cache(maxsize=4)
def _load_concepts(path_text: str) -> tuple[IndicationConcept, ...]:
    payload = json.loads(Path(path_text).read_text(encoding="utf-8"))
    return tuple(IndicationConcept(**raw) for raw in payload.get("concepts", []))


class IndicationResolver:
    """Maps free-text indication mentions to versioned concept ids."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else _default_ontology_path()

    @property
    def concepts(self) -> tuple[IndicationConcept, ...]:
        return _load_concepts(str(self._path))

    def _candidates(self, market: str, as_of: datetime) -> list[IndicationConcept]:
        return [
            concept
            for concept in self.concepts
            if concept.market == market and concept.is_effective(as_of)
        ]

    def resolve(
        self,
        text: str | None,
        *,
        market: str,
        as_of: datetime | None = None,
    ) -> IndicationMatch:
        """Resolve ``text`` to a concept, or return an unresolved match."""
        if not text or not str(text).strip():
            return IndicationMatch()

        haystack = str(text)
        folded = haystack.casefold()
        moment = as_of or datetime.now(UTC)

        # Longest surface form first: 儿童高血压 is its own concept and must not
        # collapse into the substring 高血压.
        best: tuple[int, IndicationConcept, str, str] | None = None
        for concept in self._candidates(market, moment):
            for form, basis in concept.surface_forms():
                if not form:
                    continue
                if form.casefold() not in folded:
                    continue
                length = len(form)
                if best is None or length > best[0]:
                    best = (length, concept, form, basis)

        if best is None:
            return IndicationMatch()

        _, concept, form, basis = best
        is_broader = concept.parent_id is None and any(
            other.parent_id == concept.indication_id
            for other in self._candidates(market, moment)
        )
        confidence = CANONICAL_CONFIDENCE if basis == "canonical_name" else SYNONYM_CONFIDENCE
        if is_broader:
            confidence = BROADER_CONFIDENCE
        return IndicationMatch(
            indication_id=concept.indication_id,
            canonical_name=concept.canonical_name,
            basis=basis,
            confidence=confidence,
            matched_text=form,
            ontology_version=concept.version,
            parent_id=concept.parent_id,
            is_broader_category=is_broader,
        )


__all__ = [
    "BROADER_CONFIDENCE",
    "CANONICAL_CONFIDENCE",
    "IndicationConcept",
    "IndicationMatch",
    "IndicationResolver",
    "SYNONYM_CONFIDENCE",
]
