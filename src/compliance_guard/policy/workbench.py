"""Rule-level tests, batch evaluation and immutable version comparison."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from compliance_guard.domain.enums import ContentType, Decision, Entrypoint
from compliance_guard.domain.models import (
    CaseContext,
    CharacterSpan,
    DomainModel,
    PolicyBundle,
)

from .bundles import PolicyRule, parse_bundle_rules
from .engine import PolicyEngine
from .publishing import RuleLifecycleStore


MAX_BATCH_CASES = 500
MAX_CASE_CHARS = 20_000


class RuleCase(DomainModel):
    text: str = Field(min_length=1, max_length=MAX_CASE_CHARS)
    expected_decision: Decision
    expected_rule_ids: list[str] = Field(default_factory=list)
    expected_spans: list[CharacterSpan] = Field(default_factory=list)


class RuleCaseResult(DomainModel):
    case_index: int = Field(ge=0)
    expected_decision: Decision
    actual_decision: Decision
    expected_rule_ids: list[str] = Field(default_factory=list)
    actual_rule_ids: list[str] = Field(default_factory=list)
    expected_spans: list[CharacterSpan] = Field(default_factory=list)
    actual_spans: list[CharacterSpan] = Field(default_factory=list)
    decision_match: bool
    rule_ids_match: bool
    spans_match: bool
    passed: bool
    reasons: list[str] = Field(default_factory=list)


class BatchEvaluation(DomainModel):
    version: str
    total: int = Field(ge=0)
    passed: int = Field(ge=0)
    failures: int = Field(ge=0)
    dangerous_allow_count: int = Field(ge=0)
    overblock_count: int = Field(ge=0)
    span_failures: int = Field(ge=0)
    results: list[RuleCaseResult] = Field(default_factory=list)


class RuleDiff(DomainModel):
    before: str
    after: str
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    modified: list[str] = Field(default_factory=list)


_DECISION_STRICTNESS = {
    Decision.ALLOW: 0,
    Decision.NEEDS_INFO: 1,
    Decision.HUMAN_REVIEW: 2,
    Decision.BLOCKED: 3,
    Decision.REFUSED: 4,
}


def _enum_value(value: object) -> str:
    return value.value if isinstance(value, Enum) else str(value)


def _span_keys(spans: list[CharacterSpan]) -> list[tuple[int, int]]:
    return sorted((span.start, span.end) for span in spans)


class RuleWorkbench:
    """Evaluate rule cases without granting a model control over decisions."""

    def __init__(self, lifecycle: RuleLifecycleStore) -> None:
        self._lifecycle = lifecycle

    @staticmethod
    def _context_for(text: str, rules: list[PolicyRule]) -> tuple[CaseContext, Entrypoint]:
        scopes = [rule.scope for rule in rules]
        content_types = next(
            (scope.content_types for scope in scopes if scope.content_types),
            [ContentType.OTHER],
        )
        entrypoints = next(
            (scope.entrypoints for scope in scopes if scope.entrypoints),
            [Entrypoint.CONTENT],
        )
        markets = next((scope.markets for scope in scopes if scope.markets), ["GLOBAL"])
        languages = next((scope.languages for scope in scopes if scope.languages), ["zh-CN"])
        products = next((scope.product_ids for scope in scopes if scope.product_ids), [""])
        entrypoint = (
            Entrypoint.CONTENT if Entrypoint.CONTENT in entrypoints else entrypoints[0]
        )
        context = CaseContext(
            case_id="rule-workbench",
            trace_id="rule-workbench",
            tenant_id="",
            market=markets[0],
            language=languages[0],
            product_id=products[0],
            channel=content_types[0].value,
            content_type=content_types[0],
        )
        return context, entrypoint

    def _evaluate(
        self,
        bundle: PolicyBundle,
        case: RuleCase,
        index: int,
    ) -> RuleCaseResult:
        rules = parse_bundle_rules(bundle)
        context, entrypoint = self._context_for(case.text, rules)
        result = PolicyEngine(bundle).evaluate_text(
            case.text,
            context=context,
            entrypoint=entrypoint,
            evidence_gap=False,
        )
        actual_rule_ids = sorted(result.rule_ids)
        expected_rule_ids = sorted(case.expected_rule_ids)
        actual_spans = sorted(
            {
                (span.start, span.end): span
                for finding in result.findings
                for span in finding.spans
            }.values(),
            key=lambda span: (span.start, span.end),
        )
        decision_match = result.decision is case.expected_decision
        rule_ids_match = actual_rule_ids == expected_rule_ids
        spans_match = _span_keys(actual_spans) == _span_keys(case.expected_spans)
        reasons: list[str] = []
        if not decision_match:
            reasons.append(
                f"expected decision {case.expected_decision.value}, observed {result.decision.value}"
            )
        if not rule_ids_match:
            reasons.append(
                f"expected rules {expected_rule_ids}, observed {actual_rule_ids}"
            )
        if not spans_match:
            reasons.append(
                "expected spans "
                f"{_span_keys(case.expected_spans)}, observed {_span_keys(actual_spans)}"
            )
        return RuleCaseResult(
            case_index=index,
            expected_decision=case.expected_decision,
            actual_decision=result.decision,
            expected_rule_ids=expected_rule_ids,
            actual_rule_ids=actual_rule_ids,
            expected_spans=case.expected_spans,
            actual_spans=actual_spans,
            decision_match=decision_match,
            rule_ids_match=rule_ids_match,
            spans_match=spans_match,
            passed=decision_match and rule_ids_match and spans_match,
            reasons=reasons,
        )

    def test_rule(self, rule: PolicyRule, case: RuleCase) -> RuleCaseResult:
        bundle = PolicyBundle(
            policy_version="single-rule-test",
            market="GLOBAL",
            channel="content",
            rules={rule.rule_id: rule},
        )
        return self._evaluate(bundle, case, 0)

    def evaluate_batch(self, cases: list[RuleCase], version: str) -> BatchEvaluation:
        if len(cases) > MAX_BATCH_CASES:
            raise ValueError(f"batch exceeds the {MAX_BATCH_CASES}-case limit")
        bundle = self._lifecycle.bundle(version)
        results = [
            self._evaluate(bundle, case, index)
            for index, case in enumerate(cases)
        ]
        failures = sum(not result.passed for result in results)
        dangerous_allow_count = sum(
            result.expected_decision
            in {Decision.NEEDS_INFO, Decision.HUMAN_REVIEW, Decision.BLOCKED}
            and result.actual_decision is Decision.ALLOW
            for result in results
        )
        overblock_count = sum(
            _DECISION_STRICTNESS[result.actual_decision]
            > _DECISION_STRICTNESS[result.expected_decision]
            for result in results
        )
        span_failures = sum(not result.spans_match for result in results)
        return BatchEvaluation(
            version=version,
            total=len(results),
            passed=len(results) - failures,
            failures=failures,
            dangerous_allow_count=dangerous_allow_count,
            overblock_count=overblock_count,
            span_failures=span_failures,
            results=results,
        )

    def diff_versions(self, before: str, after: str) -> RuleDiff:
        old_rules = self._lifecycle.bundle(before).rules
        new_rules = self._lifecycle.bundle(after).rules
        old_ids = set(old_rules)
        new_ids = set(new_rules)
        return RuleDiff(
            before=before,
            after=after,
            added=sorted(new_ids - old_ids),
            removed=sorted(old_ids - new_ids),
            modified=sorted(
                rule_id
                for rule_id in old_ids & new_ids
                if old_rules[rule_id] != new_rules[rule_id]
            ),
        )


__all__ = [
    "BatchEvaluation",
    "MAX_BATCH_CASES",
    "MAX_CASE_CHARS",
    "RuleCase",
    "RuleCaseResult",
    "RuleDiff",
    "RuleWorkbench",
]
