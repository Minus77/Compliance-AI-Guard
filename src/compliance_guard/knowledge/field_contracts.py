"""Server-derived field facts and the client claims they are checked against."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from compliance_guard.domain.models import DomainModel

from .indication_resolver import IndicationMatch


class FieldResolution(DomainModel):
    """Server-derived facts, the client's claims, and where they disagree."""

    resolved_fields: dict[str, Any] = Field(default_factory=dict)
    claimed_fields: dict[str, Any] = Field(default_factory=dict)
    discrepancies: list[str] = Field(default_factory=list)
    indication_match: IndicationMatch = Field(default_factory=IndicationMatch)
    basis: dict[str, str] = Field(default_factory=dict)

    @property
    def indication_unresolved(self) -> bool:
        """True when the text names an indication the ontology does not know.

        Distinct from "no indication mentioned": both leave ``indication_id``
        empty, but only this one warrants asking the author which indication they
        meant instead of drawing a conclusion.
        """
        return self.basis.get("indication") == "unresolved_mention"

    @property
    def indication_broader_only(self) -> bool:
        return self.indication_match.is_broader_category

    def audit_payload(self) -> dict[str, Any]:
        """Audit view. Field values are label vocabulary, never personal data."""
        return {
            "resolved": dict(self.resolved_fields),
            "claimed": dict(self.claimed_fields),
            "discrepancies": list(self.discrepancies),
            "basis": dict(self.basis),
            "indication": self.indication_match.audit_payload(),
        }


__all__ = ["FieldResolution"]
