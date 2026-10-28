from __future__ import annotations

import pytest

from compliance_guard.domain.enums import ContentType, Decision, Entrypoint, RuleStatus, Severity
from compliance_guard.domain.models import CharacterSpan, PolicyBundle
from compliance_guard.policy.bundles import PolicyRule, RuleScope, RuleTestCase
from compliance_guard.policy.publishing import RuleLifecycleStore


def _bundle(version: str, patterns: list[str]) -> PolicyBundle:
    return PolicyBundle(
        policy_version=version,
        market="GLOBAL",
        product_id=None,
        channel="content",
        rules={
            "GEN-001": PolicyRule(
                rule_id="GEN-001",
                version=version,
                title="Unsupported promotional claim",
                description="Flags unsupported promotional wording.",
                category="promotional",
                type="unsupported_claim",
                severity=Severity.S1,
                decision=Decision.HUMAN_REVIEW,
                scope=RuleScope(
                    content_types=[ContentType.PROMOTIONAL_CONTENT],
                    entrypoints=[Entrypoint.CONTENT],
                ),
                patterns=patterns,
                test_cases=[
                    RuleTestCase(
                        text=patterns[0],
                        expected_match=True,
                        expected_spans=[CharacterSpan(start=0, end=len(patterns[0]))],
                    ),
                    RuleTestCase(text="supported evidence", expected_match=False),
                ],
            ).model_dump(mode="json")
        },
    )


def test_publish_and_rollback_preserve_previous_rule_versions(tmp_path):
    store = RuleLifecycleStore(tmp_path / "rules.json")
    first = store.draft(_bundle("demo-v1", patterns=["unsupported"]))
    assert store.test(first.version).passed is True
    published_one = store.publish(first.version, "compliance-admin")

    second = store.draft(
        _bundle("demo-v2", patterns=["unsupported", "guaranteed cure"])
    )
    store.test(second.version)
    published_two = store.publish(second.version, "compliance-admin")
    rolled_back = store.rollback(published_one.version, "compliance-admin")

    assert published_two.version != published_one.version
    assert rolled_back.version == published_one.version
    assert [item.status for item in store.history()] == [
        RuleStatus.ROLLED_BACK,
        RuleStatus.PUBLISHED,
    ]
    assert [rule.rule_id for rule in store.current().rules.values()] == ["GEN-001"]


def test_failed_rule_test_prevents_publication(tmp_path):
    store = RuleLifecycleStore(tmp_path / "rules.json")
    bundle = _bundle("demo-v1", patterns=["unsupported"])
    raw = bundle.rules["GEN-001"]
    raw["test_cases"][0]["expected_match"] = False
    version = store.draft(bundle)

    report = store.test(version.version)

    assert report.passed is False
    with pytest.raises(ValueError, match="not passed"):
        store.publish(version.version, "compliance-admin")


def test_lifecycle_history_survives_restart(tmp_path):
    path = tmp_path / "rules.json"
    first = RuleLifecycleStore(path).draft(_bundle("demo-v1", patterns=["unsupported"]))
    RuleLifecycleStore(path).test(first.version)
    RuleLifecycleStore(path).publish(first.version, "compliance-admin")

    reopened = RuleLifecycleStore(path)

    assert reopened.current().policy_version == "demo-v1"
    assert reopened.history()[0].status is RuleStatus.PUBLISHED
