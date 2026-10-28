"""Immutable, file-backed rule lifecycle with atomic publication changes."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from compliance_guard.domain.enums import RuleStatus
from compliance_guard.domain.models import CharacterSpan, DomainModel, PolicyBundle
from compliance_guard.runtime_paths import writable_data_dir

from .bundles import PolicyRule, parse_bundle_rules


class RuleTestFailure(DomainModel):
    rule_id: str
    case_index: int
    message: str


class RuleTestReport(DomainModel):
    version: str
    passed: bool
    failures: list[RuleTestFailure] = Field(default_factory=list)


class RuleVersion(DomainModel):
    version: str
    status: RuleStatus
    rules: dict[str, PolicyRule]
    created_at: datetime
    published_at: datetime | None = None
    market: str = "GLOBAL"
    product_id: str | None = None
    channel: str | None = None
    effective_from: datetime | None = None
    effective_until: datetime | None = None
    source_version: str = ""
    last_test_passed: bool = False
    published_by: str | None = None

    model_config = DomainModel.model_config | {"frozen": True}


def _default_store_path() -> Path:
    return writable_data_dir() / "rules" / "rule_versions.json"


def _matching_spans(text: str, patterns: list[str]) -> list[CharacterSpan]:
    spans: list[CharacterSpan] = []
    seen: set[tuple[int, int]] = set()
    for pattern in patterns:
        if not pattern:
            continue
        for match in re.finditer(re.escape(pattern), text, re.IGNORECASE):
            key = (match.start(), match.end())
            if key not in seen:
                seen.add(key)
                spans.append(CharacterSpan(start=match.start(), end=match.end()))
    return sorted(spans, key=lambda span: (span.start, span.end))


class RuleLifecycleStore:
    """Draft, test, publish and roll back immutable rule snapshots."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else _default_store_path()
        self._lock = threading.RLock()
        self._versions, self._current_version = self._load()

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> tuple[list[RuleVersion], str | None]:
        if not self._path.exists():
            return [], None
        with self._path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        versions = [RuleVersion.model_validate(item) for item in raw.get("versions", [])]
        current_version = raw.get("current_version")
        published = [item.version for item in versions if item.status is RuleStatus.PUBLISHED]
        if current_version is None and published:
            current_version = published[-1]
        return versions, current_version

    def _persist(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "1",
            "current_version": self._current_version,
            "versions": [
                item.model_dump(mode="json", exclude_none=False)
                for item in self._versions
            ],
        }
        descriptor, temp_name = tempfile.mkstemp(
            prefix=f".{self._path.name}.",
            suffix=".tmp",
            dir=self._path.parent,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self._path)
        except BaseException:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise

    def _require(self, version: str) -> tuple[int, RuleVersion]:
        for index, item in enumerate(self._versions):
            if item.version == version:
                return index, item
        raise KeyError(f"unknown rule version {version!r}")

    def draft(self, bundle: PolicyBundle) -> RuleVersion:
        """Create and persist a new draft snapshot without altering history."""
        with self._lock:
            typed_rules = parse_bundle_rules(bundle)
            version = f"demo-v{len(self._versions) + 1}"
            snapshot = RuleVersion(
                version=version,
                status=RuleStatus.DRAFT,
                rules={rule.rule_id: rule for rule in typed_rules},
                created_at=datetime.now(UTC),
                market=bundle.market,
                product_id=bundle.product_id,
                channel=bundle.channel,
                effective_from=bundle.effective_from,
                effective_until=bundle.effective_until,
                source_version=bundle.policy_version,
            )
            self._versions.append(snapshot)
            self._persist()
            return snapshot

    @staticmethod
    def _evaluate_rule_test(rule: PolicyRule, case: Any, case_index: int) -> list[RuleTestFailure]:
        spans = _matching_spans(case.text, rule.patterns)
        matched = bool(spans)
        failures: list[RuleTestFailure] = []
        if matched != case.expected_match:
            failures.append(
                RuleTestFailure(
                    rule_id=rule.rule_id,
                    case_index=case_index,
                    message=(
                        f"expected match={case.expected_match}, observed match={matched}"
                    ),
                )
            )
            return failures
        expected = sorted(
            ((span.start, span.end) for span in case.expected_spans),
        )
        observed = [(span.start, span.end) for span in spans]
        if case.expected_spans and expected != observed:
            failures.append(
                RuleTestFailure(
                    rule_id=rule.rule_id,
                    case_index=case_index,
                    message=f"expected spans={expected}, observed spans={observed}",
                )
            )
        return failures

    def _run_snapshot_tests(self, snapshot: RuleVersion) -> RuleTestReport:
        failures: list[RuleTestFailure] = []
        for rule in snapshot.rules.values():
            for index, case in enumerate(rule.test_cases):
                failures.extend(self._evaluate_rule_test(rule, case, index))
        return RuleTestReport(
            version=snapshot.version,
            passed=not failures,
            failures=failures,
        )

    def test(self, version: str) -> RuleTestReport:
        """Execute the snapshotted rule cases and record a passing gate."""
        with self._lock:
            index, snapshot = self._require(version)
            report = self._run_snapshot_tests(snapshot)
            next_status = RuleStatus.PASSED if report.passed else RuleStatus.DRAFT
            self._versions[index] = snapshot.model_copy(
                update={"status": next_status, "last_test_passed": report.passed}
            )
            self._persist()
            return report

    def publish(self, version: str, actor_id: str) -> RuleVersion:
        """Publish only a tested snapshot, marking the prior release superseded."""
        with self._lock:
            index, snapshot = self._require(version)
            report = self._run_snapshot_tests(snapshot)
            if not report.passed or not snapshot.last_test_passed:
                raise ValueError(f"rule version {version!r} has not passed its tests")
            now = datetime.now(UTC)
            for item_index, item in enumerate(self._versions):
                if item.status is RuleStatus.PUBLISHED:
                    self._versions[item_index] = item.model_copy(
                        update={"status": RuleStatus.ROLLED_BACK}
                    )
            published = snapshot.model_copy(
                update={
                    "status": RuleStatus.PUBLISHED,
                    "published_at": now,
                    "published_by": actor_id,
                }
            )
            self._versions[index] = published
            self._current_version = published.version
            self._persist()
            return published

    def rollback(self, version: str, actor_id: str) -> RuleVersion:
        """Reactivate an immutable prior release and supersede the current one."""
        with self._lock:
            index, snapshot = self._require(version)
            if snapshot.published_at is None and snapshot.status is not RuleStatus.PUBLISHED:
                raise ValueError(f"rule version {version!r} was never published")
            report = self._run_snapshot_tests(snapshot)
            if not report.passed:
                raise ValueError(f"rule version {version!r} no longer passes its tests")
            for item_index, item in enumerate(self._versions):
                if item.status is RuleStatus.PUBLISHED and item_index != index:
                    self._versions[item_index] = item.model_copy(
                        update={"status": RuleStatus.ROLLED_BACK}
                    )
            restored = snapshot.model_copy(
                update={
                    "status": RuleStatus.PUBLISHED,
                    "published_at": datetime.now(UTC),
                    "published_by": actor_id,
                }
            )
            self._versions[index] = restored
            self._current_version = restored.version
            self._persist()
            return restored

    def current(self) -> PolicyBundle:
        """Return the currently published bundle as typed rules."""
        with self._lock:
            if self._current_version is None:
                raise ValueError("no rule version has been published")
            _, snapshot = self._require(self._current_version)
            return PolicyBundle(
                policy_version=snapshot.version,
                market=snapshot.market,
                product_id=snapshot.product_id,
                channel=snapshot.channel,
                effective_from=snapshot.effective_from,
                effective_until=snapshot.effective_until,
                rules=dict(snapshot.rules),
            )

    def history(self) -> list[RuleVersion]:
        """Return immutable snapshots newest-first, including superseded releases."""
        with self._lock:
            return list(reversed(self._versions))


__all__ = [
    "RuleLifecycleStore",
    "RuleTestFailure",
    "RuleTestReport",
    "RuleVersion",
]
