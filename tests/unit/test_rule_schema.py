import pytest
from pydantic import ValidationError

from compliance_guard.domain.enums import ContentType, Decision, Entrypoint, Severity
from compliance_guard.domain.models import CharacterSpan
from compliance_guard.policy.bundles import PolicyRule, RuleScope, RuleTestCase


def test_rule_requires_version_title_behavior_and_scope():
    rule = PolicyRule(
        rule_id="GEN-001",
        version="1",
        title="Unsupported promotional claim",
        description="Detects unsupported promotional wording.",
        category="promotional",
        type="unsupported_claim",
        severity=Severity.S2,
        decision=Decision.HUMAN_REVIEW,
        scope=RuleScope(
            content_types=[ContentType.PROMOTIONAL_CONTENT],
            entrypoints=[Entrypoint.CONTENT],
        ),
        span_locator="char",
        allow_save=True,
        allow_generate=False,
        allow_publish=False,
        test_cases=[
            RuleTestCase(
                text="best in class",
                expected_match=True,
                expected_spans=[CharacterSpan(start=0, end=13)],
            )
        ],
    )
    assert rule.version == "1"
    assert rule.scope.entrypoints == [Entrypoint.CONTENT]
    assert rule.test_cases[0].expected_spans[0].end == 13


def test_redline_rule_cannot_be_silently_suppressed():
    with pytest.raises(ValidationError):
        PolicyRule(
            rule_id="GEN-002",
            version="1",
            title="Serious safety event",
            description="Detects a serious safety event.",
            category="adverse_event",
            type="adverse_event",
            severity=Severity.S0,
            decision=Decision.BLOCKED,
            span_locator="char",
            allow_save=False,
            allow_generate=False,
            allow_publish=False,
            suppression_policy="silent",
        )
