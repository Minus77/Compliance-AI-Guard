"""Versioned, JSON-backed deterministic policy bundles.

Rule conditions and thresholds live in policy bundles (JSON), never in prompts.
Bundles are validated into typed :class:`PolicyRule` objects at load time so the
engine can rely on well-formed rules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field

from compliance_guard.domain.enums import Decision, Role, Severity
from compliance_guard.domain.models import DomainModel, PolicyBundle


class PolicyRule(DomainModel):
    """A single deterministic rule with explicit condition patterns."""

    rule_id: str
    type: str
    severity: Severity
    decision: Decision
    patterns: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    required_roles: list[Role] = Field(default_factory=list)
    sla_label: str = ""
    next_action: str = ""
    requires_evidence: bool = True
    evidence_gap_acceptable: bool = False
    reversible: bool = True


def parse_bundle_rules(bundle: PolicyBundle) -> list[PolicyRule]:
    """Validate and convert a bundle's raw rule map into typed rules."""
    rules: list[PolicyRule] = []
    for rule_id, raw in bundle.rules.items():
        rules.append(PolicyRule(rule_id=rule_id, **raw))
    return rules


def _repo_config_dir() -> Path:
    from compliance_guard.runtime_paths import config_dir

    # Read-only resource: ships inside the bundle when frozen.
    return config_dir()


def _default_bundle_path() -> Path:
    return _repo_config_dir() / "policies" / "cn-demo.json"


class PolicyBundleStore:
    """Repository for the versioned China demo policy bundle."""

    def __init__(self, path: str | Path | None = None) -> None:
        bundle_path = Path(path) if path else _default_bundle_path()
        with bundle_path.open("r", encoding="utf-8") as handle:
            raw: dict[str, Any] = json.load(handle)
        raw_rules = raw.pop("rules")
        self._bundle = PolicyBundle(rules=raw_rules, **raw)
        parse_bundle_rules(self._bundle)

    def load(self, version: str | None = None) -> PolicyBundle:
        if version is not None and version != self._bundle.policy_version:
            raise ValueError(f"unknown policy bundle version {version!r}")
        if not self._bundle.enabled:
            raise ValueError(f"policy bundle {self._bundle.policy_version} is disabled")
        return self._bundle

    def current(self) -> PolicyBundle:
        if not self._bundle.enabled:
            raise ValueError(f"policy bundle {self._bundle.policy_version} is disabled")
        return self._bundle


__all__ = ["PolicyBundleStore", "PolicyRule", "parse_bundle_rules"]
