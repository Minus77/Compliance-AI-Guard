"""Startup configuration validation and declared retention periods.

A malformed policy bundle used to be discovered by the first request that needed
it, which means the first *user* discovers it, mid-sentence, as an opaque error.
Worse, a bundle whose validity window has closed would keep deciding cases
silently. Both are checked at boot instead, and a bad configuration refuses to
start with a message naming the file.

Retention is declared here rather than left implicit. The asymmetry is the point:
drafts, notifications and pre-check logs are transient and bounded, while the
audit ledger has no expiry at all. Append-only means append-only — a retention
sweep that deleted audit entries would defeat the chain that exists to make
deletion detectable.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from compliance_guard.domain.models import DomainModel
from compliance_guard.runtime_paths import config_dir as default_config_dir
from compliance_guard.runtime_paths import fixtures_dir as default_fixtures_dir


class ConfigurationError(RuntimeError):
    """Raised when the shipped configuration cannot be trusted to serve traffic."""


class ConfigCheck(DomainModel):
    name: str
    ok: bool
    version: str = ""
    detail: str = ""


class ConfigReport(DomainModel):
    ok: bool = True
    checked: list[ConfigCheck] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)

    def dependency_payload(self) -> list[dict[str, Any]]:
        return [check.model_dump(mode="json") for check in self.checked]


def _load_json(path: Path) -> Any:
    """Read a JSON file, raising a message that names the file.

    "Invalid configuration" tells an operator nothing; the filename tells them
    what to open.
    """
    if not path.is_file():
        raise ConfigurationError(f"missing configuration file: {path.name} ({path})")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ConfigurationError(
            f"{path.name} is not valid JSON: line {error.lineno}, column {error.colno}"
        ) from error
    except OSError as error:
        raise ConfigurationError(f"{path.name} could not be read: {error}") from error


def _parse_moment(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


POLICY_BUNDLE_FILENAME = "general-medical-demo.json"


def _check_policy_bundle(config_root: Path, now: datetime) -> ConfigCheck:
    path = config_root / "policies" / POLICY_BUNDLE_FILENAME
    payload = _load_json(path)
    version = str(payload.get("policy_version") or "")
    if not version:
        raise ConfigurationError(f"{path.name} has no policy_version")
    if not payload.get("rules"):
        raise ConfigurationError(f"{path.name} declares no rules")
    if payload.get("enabled") is False:
        raise ConfigurationError(f"policy bundle {version} is disabled; it cannot serve traffic")

    starts = _parse_moment(payload.get("effective_from"))
    ends = _parse_moment(payload.get("effective_until"))
    if starts is not None and now < starts:
        raise ConfigurationError(
            f"policy bundle {version} is not effective until {starts.isoformat()}"
        )
    if ends is not None and now > ends:
        raise ConfigurationError(
            f"policy bundle {version} expired at {ends.isoformat()}; "
            "an expired bundle must not keep deciding cases"
        )
    return ConfigCheck(
        name="policy_bundle",
        ok=True,
        version=version,
        detail=f"{len(payload['rules'])} rules",
    )


def _check_label_facts(fixtures_root: Path) -> ConfigCheck:
    path = fixtures_root / "label_facts.json"
    payload = _load_json(path)
    labels = payload.get("labels") or []
    if not labels:
        raise ConfigurationError(f"{path.name} contains no labels")
    pairs = {(item.get("product_id"), item.get("market")) for item in labels}
    return ConfigCheck(
        name="label_facts",
        ok=True,
        version=str(len(labels)),
        detail=f"{len(pairs)} product/market pairs",
    )


def _check_ontology(fixtures_root: Path) -> ConfigCheck:
    path = fixtures_root / "indication_ontology.json"
    payload = _load_json(path)
    concepts = payload.get("concepts") or []
    if not concepts:
        raise ConfigurationError(f"{path.name} contains no indication concepts")
    missing_parents = [
        concept["parent_id"]
        for concept in concepts
        if concept.get("parent_id")
        and concept["parent_id"] not in {item.get("indication_id") for item in concepts}
    ]
    if missing_parents:
        raise ConfigurationError(
            f"{path.name} references unknown parent concepts: {sorted(set(missing_parents))}"
        )
    return ConfigCheck(
        name="indication_ontology",
        ok=True,
        version=str(payload.get("ontology_version") or ""),
        detail=f"{len(concepts)} concepts",
    )


def _check_glossary(config_root: Path) -> ConfigCheck:
    path = config_root / "glossary.json"
    payload = _load_json(path)
    if not payload.get("finding_types"):
        raise ConfigurationError(f"{path.name} declares no finding_types")
    if not payload.get("decisions"):
        raise ConfigurationError(f"{path.name} declares no decisions")

    # Every rule a user can meet must have wording. A rule added without an
    # explanation would surface as a bare code, which is the failure the glossary
    # exists to prevent -- so it is a startup error, not a cosmetic gap.
    bundle_path = config_root / "policies" / POLICY_BUNDLE_FILENAME
    if bundle_path.is_file():
        rules = (_load_json(bundle_path).get("rules") or {}).values()
        types = {rule.get("type") for rule in rules if rule.get("type")}
        missing = sorted(types - set(payload["finding_types"]))
        if missing:
            raise ConfigurationError(
                f"{path.name} has no plain-language explanation for: {', '.join(missing)}"
            )
    return ConfigCheck(
        name="glossary",
        ok=True,
        version=str(payload.get("glossary_version") or ""),
        detail=f"{len(payload['finding_types'])} finding types",
    )


def _check_model_routes(config_root: Path) -> ConfigCheck:
    profiles = _load_json(config_root / "model_profiles.json")
    routes = _load_json(config_root / "task_routes.json")
    if not profiles:
        raise ConfigurationError("model_profiles.json declares no profiles")
    if not routes:
        raise ConfigurationError("task_routes.json declares no routes")

    unknown: list[str] = []
    for task, route in routes.items():
        primary = route.get("primary_profile_id")
        if primary and primary not in profiles:
            unknown.append(f"{task} -> {primary}")
        for fallback in route.get("fallback_profile_ids") or []:
            if fallback not in profiles:
                unknown.append(f"{task} -> {fallback}")
    if unknown:
        raise ConfigurationError(
            "task_routes.json points at profiles that do not exist: " + ", ".join(unknown)
        )
    versions = {str(route.get("route_version") or "") for route in routes.values()}
    return ConfigCheck(
        name="model_routes",
        ok=True,
        version=sorted(versions)[0] if versions else "",
        detail=f"{len(routes)} routes over {len(profiles)} profiles",
    )


def _check_surnames(config_root: Path) -> ConfigCheck:
    path = config_root / "surnames.json"
    payload = _load_json(path)
    if not payload.get("single_char_surnames"):
        raise ConfigurationError(f"{path.name} contains no surnames; name masking would silently weaken")
    return ConfigCheck(
        name="name_lexicon",
        ok=True,
        version=str(payload.get("version") or ""),
        detail=f"{len(payload['single_char_surnames'])} surnames",
    )


def validate_configuration(
    *,
    config_dir: str | Path | None = None,
    fixtures_dir: str | Path | None = None,
    now: datetime | None = None,
) -> ConfigReport:
    """Validate every configuration file the service depends on.

    Collects problems rather than raising, so an operator sees everything that is
    wrong in one pass instead of fixing one file at a time.
    """
    config_root = Path(config_dir) if config_dir is not None else default_config_dir()
    fixtures_root = Path(fixtures_dir) if fixtures_dir is not None else default_fixtures_dir()
    moment = now or datetime.now(UTC)

    report = ConfigReport()
    checks = (
        lambda: _check_policy_bundle(config_root, moment),
        lambda: _check_label_facts(fixtures_root),
        lambda: _check_ontology(fixtures_root),
        lambda: _check_glossary(config_root),
        lambda: _check_model_routes(config_root),
        lambda: _check_surnames(config_root),
    )
    for check in checks:
        try:
            report.checked.append(check())
        except ConfigurationError as error:
            report.ok = False
            report.problems.append(str(error))
    return report


def require_valid_configuration(
    *,
    config_dir: str | Path | None = None,
    fixtures_dir: str | Path | None = None,
) -> ConfigReport:
    """Validate, or refuse to start.

    Failing at boot is the whole point: the alternative is a service that appears
    healthy and then errors on the first real submission.
    """
    report = validate_configuration(config_dir=config_dir, fixtures_dir=fixtures_dir)
    if not report.ok:
        raise ConfigurationError(
            "configuration is not usable:\n  - " + "\n  - ".join(report.problems)
        )
    return report


def retention_policy() -> dict[str, dict[str, Any]]:
    """How long each store keeps data, and why.

    ``retain_days = None`` means never automatically deleted.

    ``enforced`` distinguishes a period a sweep honours from one that is only
    declared. The distinction matters more than the numbers: a retention statement
    nothing implements reads as a control to anyone reviewing the design, so it is
    reported honestly rather than implied.

    Drafts are marked enforced because the browser expires them; the server never
    holds them. The audit ledger and confirmed feedback candidates are enforced
    ``False`` deliberately -- nothing sweeps either.
    """
    return {
        "audit_ledger": {
            "retain_days": None,
            # No sweep exists for this store, and that absence is the control.
            "enforced": False,
            "basis": (
                "append-only; retention must equal or exceed the business records it "
                "describes (21 CFR Part 11 §11.10(e)). A sweep that deleted entries "
                "would defeat the chain that makes deletion detectable."
            ),
        },
        "precheck_log": {
            "enforced": False,
            "retain_days": 7,
            "basis": "operational telemetry for latency SLOs; no case decision depends on it",
        },
        "notification": {
            "enforced": True,
            "retain_days": 90,
            "basis": "long enough to act on an outcome, short enough not to become a second record store",
        },
        "draft": {
            "enforced": True,
            "retain_days": 7,
            "basis": "browser-local only and never uploaded; expires so an abandoned draft does not linger",
        },
        "feedback_candidate": {
            "enforced": False,
            "retain_days": None,
            "basis": "confirmed candidates become regression cases; discarding them would lose the signal",
        },
    }


__all__ = [
    "ConfigCheck",
    "ConfigReport",
    "ConfigurationError",
    "require_valid_configuration",
    "retention_policy",
    "validate_configuration",
]
