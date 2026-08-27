"""Constrained extraction agent.

The model request is built only from sanitized structured fields and evidence IDs.
Model input is untrusted data, never instructions: raw content parts and reserved
server-controlled fields are never placed into the structured payload.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from compliance_guard.domain.models import CandidateFinding, Entity, ExtractedData
from compliance_guard.llm.types import ModelConstraints, ModelRequest, RawModelResult

_REFUSED_MARKER = "model_refused_or_failed"

_RESERVED_KEYS = frozenset(
    {
        "approval_status",
        "decision",
        "routing",
        "severity",
        "tool_permissions",
        "api_key",
        "secret_key",
        "password",
    }
)

_FORBIDDEN_SUBSTRINGS = ("secret", "password", "credential", "token", "apikey")


def _is_empty_value(value: Any) -> bool:
    """True when a model-reported field carries no assertion.

    A live model commonly answers with the full field template and ``null`` for
    everything it could not find. Those are *absences*, not claims, and they must
    be dropped before policy evaluation: the label comparison treats a present
    key as an assertion to compare, so a null-filled template would be read as
    "every label field contradicts the approved label" and fabricate an
    off-label finding. Offline fixtures returned ``{}`` and never exposed this.
    """
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip() or value.strip().casefold() in {"null", "none", "n/a", "未知", "无", "不详"}
    if isinstance(value, (list, dict)):
        return not value
    return False


def _is_forbidden_key(key: str) -> bool:
    folded = key.casefold()
    if folded in _RESERVED_KEYS:
        return True
    return any(marker in folded for marker in _FORBIDDEN_SUBSTRINGS)


class ExtractorAgent:
    """Deterministic boundary that builds safe model requests and parses candidates."""

    def build_request(
        self,
        *,
        task_type: str,
        sanitized_text: str,
        structured_fields: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
        evidence_excerpts: list[dict[str, Any]] | None = None,
        label_facts: dict[str, Any] | None = None,
    ) -> ModelRequest:
        safe_fields = {
            key: value
            for key, value in (structured_fields or {}).items()
            if not _is_forbidden_key(key)
        }
        return ModelRequest(
            scenario=task_type,
            task_type=task_type,
            content=sanitized_text,
            evidence_excerpts=list(evidence_excerpts or []),
            evidence_ids=sorted(set(evidence_ids or [])),
            structured_payload=safe_fields,
            label_facts=dict(label_facts or {}),
        )

    def parse(self, raw: RawModelResult) -> ExtractedData:
        payload = raw.raw_json or {}
        missing = list(payload.get("missing_information", []))
        if raw.error_category is not None or not payload:
            missing.append(_REFUSED_MARKER)
        extracted_fields = payload.get("extracted_fields", {})
        if not isinstance(extracted_fields, dict):
            missing.append(_REFUSED_MARKER)
            extracted_fields = {}
        else:
            # Keep only real assertions; see _is_empty_value.
            extracted_fields = {
                key: value
                for key, value in extracted_fields.items()
                if not _is_empty_value(value)
            }
        try:
            entities = [
                Entity(type=str(item.get("type", "unknown")), token=item.get("token"))
                for item in payload.get("entities", [])
                if isinstance(item, dict) and not _is_empty_value(item.get("token"))
            ]
            candidate_findings = [
                CandidateFinding(
                    type=str(item.get("type", "")),
                    confidence=item.get("confidence"),
                    reason=item.get("reason"),
                    evidence_refs=list(item.get("evidence_refs", [])),
                    missing_information=list(item.get("missing_information", [])),
                )
                for item in payload.get("findings", [])
                if isinstance(item, dict) and item.get("type")
            ]
            return ExtractedData(
                entities=entities,
                findings=candidate_findings,
                extracted_fields=dict(extracted_fields),
                evidence_refs=list(payload.get("evidence_refs", [])),
                missing_information=missing,
                confidence=payload.get("confidence"),
            )
        except ValidationError:
            return ExtractedData(
                entities=[],
                findings=[],
                extracted_fields={},
                evidence_refs=[],
                missing_information=[_REFUSED_MARKER],
                confidence=None,
            )


__all__ = ["ExtractorAgent", "_REFUSED_MARKER"]
