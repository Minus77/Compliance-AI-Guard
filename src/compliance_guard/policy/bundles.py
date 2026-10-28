"""Versioned, JSON-backed deterministic policy bundles.

Rule conditions and thresholds live in policy bundles (JSON), never in prompts.
Bundles are validated into typed :class:`PolicyRule` objects at load time so the
engine can rely on well-formed rules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field, model_validator

from compliance_guard.domain.enums import (
    ContentType,
    Decision,
    Entrypoint,
    Role,
    Severity,
)
from compliance_guard.domain.models import CharacterSpan, DomainModel, PolicyBundle


class RuleScope(DomainModel):
    """Context in which a rule applies; empty dimensions are unrestricted."""

    tenant_ids: list[str] = Field(default_factory=list)
    markets: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    product_ids: list[str] = Field(default_factory=list)
    therapeutic_areas: list[str] = Field(default_factory=list)
    content_types: list[ContentType] = Field(default_factory=list)
    entrypoints: list[Entrypoint] = Field(default_factory=list)


class RuleTestCase(DomainModel):
    text: str
    expected_match: bool
    expected_spans: list[CharacterSpan] = Field(default_factory=list)


class PolicyRule(DomainModel):
    """A single deterministic rule with explicit condition patterns."""

    rule_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = ""
    category: str = ""
    type: str = Field(min_length=1)
    severity: Severity
    decision: Decision
    scope: RuleScope = Field(default_factory=RuleScope)
    patterns: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    conditions: dict[str, Any] = Field(default_factory=dict)
    span_locator: str = "char"
    allow_save: bool = True
    allow_generate: bool = True
    allow_publish: bool = True
    notification_message: str = ""
    remediation_guidance: str = ""
    required_roles: list[Role] = Field(default_factory=list)
    sla_label: str = ""
    next_action: str = ""
    suppression_policy: str = "none"
    evidence_requirements: list[str] = Field(default_factory=list)
    test_cases: list[RuleTestCase] = Field(default_factory=list)
    requires_span: bool = False
    requires_evidence: bool = True
    evidence_gap_acceptable: bool = False
    reversible: bool = True

    @model_validator(mode="after")
    def _protect_redlines_and_test_cases(self) -> "PolicyRule":
        if self.suppression_policy.casefold() == "silent" and (
            self.severity is Severity.S0 or self.decision is Decision.BLOCKED
        ):
            raise ValueError("S0 and blocked rules cannot use silent suppression")
        for case in self.test_cases:
            for span in case.expected_spans:
                if span.end > len(case.text):
                    raise ValueError("test case span exceeds its text")
        return self


def parse_bundle_rules(bundle: PolicyBundle) -> list[PolicyRule]:
    """Validate and convert a bundle's raw rule map into typed rules."""
    rules: list[PolicyRule] = []
    for rule_id, raw in bundle.rules.items():
        if isinstance(raw, PolicyRule):
            rules.append(raw)
            continue
        values = dict(raw)
        values.pop("rule_id", None)
        values.setdefault("version", str(raw.get("version", bundle.policy_version)))
        values.setdefault("title", str(raw.get("title") or raw.get("type") or rule_id))
        rules.append(PolicyRule(rule_id=rule_id, **values))
    return rules


def _repo_config_dir() -> Path:
    from compliance_guard.runtime_paths import config_dir

    # Read-only resource: ships inside the bundle when frozen.
    return config_dir()


def _default_bundle_path() -> Path:
    return _repo_config_dir() / "policies" / "general-medical-demo.json"


class PolicyBundleStore:
    """Repository for a versioned, general medical compliance bundle."""

    def __init__(self, path: str | Path | None = None) -> None:
        bundle_path = Path(path) if path else _default_bundle_path()
        with bundle_path.open("r", encoding="utf-8") as handle:
            raw: dict[str, Any] = json.load(handle)
        raw_rules = raw.pop("rules")
        self._bundle = PolicyBundle(rules=raw_rules, **raw)
        parse_bundle_rules(self._bundle)
        self._lifecycle: Any | None = None

    def bind_lifecycle(self, lifecycle: Any) -> None:
        """Use one published rule snapshot across checks and the workbench."""
        lifecycle.ensure_published(self._bundle)
        self._lifecycle = lifecycle

    def load(self, version: str | None = None) -> PolicyBundle:
        if self._lifecycle is not None:
            if version is None:
                return self._lifecycle.current()
            try:
                return self._lifecycle.bundle(version)
            except KeyError:
                if version != self._bundle.policy_version:
                    raise ValueError(f"unknown policy bundle version {version!r}") from None
        if version is not None and version != self._bundle.policy_version:
            raise ValueError(f"unknown policy bundle version {version!r}")
        if not self._bundle.enabled:
            raise ValueError(f"policy bundle {self._bundle.policy_version} is disabled")
        return self._bundle

    def current(self) -> PolicyBundle:
        if self._lifecycle is not None:
            return self._lifecycle.current()
        if not self._bundle.enabled:
            raise ValueError(f"policy bundle {self._bundle.policy_version} is disabled")
        return self._bundle


__all__ = ["PolicyBundleStore", "PolicyRule", "RuleScope", "RuleTestCase", "parse_bundle_rules"]
