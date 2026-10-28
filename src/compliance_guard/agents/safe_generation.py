"""Build constrained conversation requests and extract buffered model text."""

from __future__ import annotations

import os

from compliance_guard.domain.enums import Entrypoint
from compliance_guard.llm.types import ModelConstraints, ModelRequest, RawModelResult
from compliance_guard.policy.bundles import PolicyRule
from compliance_guard.workflow.conversations import ConversationSession


CONVERSATION_TASK_TYPE = "conversation_generation"
MAX_GENERATED_TEXT_CHARS = 20_000


class GenerationFailure(ValueError):
    """A model result cannot be treated as an answer candidate."""


def _applicable_rule_summary(rules: list[PolicyRule]) -> list[dict[str, object]]:
    summary: list[dict[str, object]] = []
    for rule in rules:
        if not rule.scope.entrypoints:
            entrypoints = [Entrypoint.INPUT.value, Entrypoint.OUTPUT.value]
        else:
            entrypoints = [entrypoint.value for entrypoint in rule.scope.entrypoints]
        if not {
            Entrypoint.INPUT.value,
            Entrypoint.OUTPUT.value,
        }.intersection(entrypoints):
            continue
        summary.append(
            {
                "rule_id": rule.rule_id,
                "version": rule.version,
                "category": rule.category,
                "severity": rule.severity.value,
                "entrypoints": entrypoints,
                "allow_publish": rule.allow_publish,
            }
        )
    return summary


def build_constrained_request(
    session: ConversationSession,
    rules: list[PolicyRule],
) -> ModelRequest:
    """Build a request from server-held safe text and policy metadata only."""
    return ModelRequest(
        scenario=CONVERSATION_TASK_TYPE,
        task_type=CONVERSATION_TASK_TYPE,
        content=session.safe_content,
        evidence_ids=[],
        evidence_excerpts=[],
        structured_payload={
            "conversation_id": session.conversation_id,
            "content_version": session.content_version,
            "rule_version": session.rule_version,
            "allowed_constraints": dict(session.allowed_constraints),
            "applicable_rules": _applicable_rule_summary(rules),
            "output_contract": {
                "format": "json",
                "text_field": "text",
                "refused_field": "refused",
                "publish_after_server_check": True,
                "streaming": False,
            },
        },
    )


def generation_constraints(session: ConversationSession) -> ModelConstraints:
    """Apply the limits bound to the checked input, with no caller overrides."""
    return ModelConstraints(
        mode=os.getenv("LLM_MODE", "mock"),
        timeout_ms=5_000,
        token_budget=2_048,
        data_class=str(session.allowed_constraints.get("data_class") or "protected"),
        region=str(session.allowed_constraints.get("region") or "local"),
        allowed_data_classes=["protected"],
        allowed_regions=[str(session.allowed_constraints.get("region") or "local")],
    )


def extract_buffered_text(result: RawModelResult) -> str:
    """Return the complete candidate text or raise without echoing the body."""
    if result.error_category is not None:
        raise GenerationFailure(result.error_category)
    if result.raw_json.get("refused") is True:
        raise GenerationFailure("refused")

    text = result.raw_json.get("text")
    if not isinstance(text, str) or not text.strip():
        raise GenerationFailure("missing_text")
    if len(text) > MAX_GENERATED_TEXT_CHARS:
        raise GenerationFailure("text_too_large")
    return text


__all__ = [
    "CONVERSATION_TASK_TYPE",
    "GenerationFailure",
    "MAX_GENERATED_TEXT_CHARS",
    "build_constrained_request",
    "extract_buffered_text",
    "generation_constraints",
]
