"""RACI review routing tests: roles, SLA labels, review tasks, immutability."""

from datetime import UTC, datetime

import pytest

from compliance_guard.domain.enums import Role, Severity
from compliance_guard.domain.models import (
    CandidateFinding,
    CaseContext,
    Entity,
    Evidence,
    ExtractedData,
)
from compliance_guard.knowledge.evidence_pack import EvidenceGap, EvidencePack
from compliance_guard.knowledge.label_facts import LabelFacts
from compliance_guard.policy.bundles import PolicyBundleStore
from compliance_guard.policy.engine import PolicyEngine
from compliance_guard.policy.routing import (
    RaciEntry,
    RaciMatrix,
    ReviewPlan,
    default_raci,
    route_review,
)

CN_PRODUCT = "PRODUCT-001"


def case_for(text):
    return CaseContext(
        case_id="case-routing-1",
        trace_id="trace-routing-1",
        tenant_id="TENANT-CN",
        market="CN",
        language="zh-CN",
        product_id=CN_PRODUCT,
        channel="call_report",
        source="call_report",
        source_version="v1",
    )


def extracted_for(text, fields=None, findings=None, entities=True):
    return ExtractedData(
        entities=[Entity(type="patient", token="患者")] if entities else [],
        findings=findings or [],
        extracted_fields=fields or {},
        missing_information=[],
    )


def evidence_for(text):
    item = Evidence(
        evidence_id="EV-CN-2026-001",
        source_id="CN-PI-2026-01",
        version="CN-PI-2026-01",
        market="CN",
        product_id=CN_PRODUCT,
        language="zh-CN",
        status="active",
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=None,
    )
    return EvidencePack(
        snapshot_id="snap-1",
        query=text,
        items=[item],
        supporting=[item],
        contradictions=[],
        gaps=[],
        evidence_gap=False,
    )


def empty_evidence(text="某主张"):
    return EvidencePack(
        snapshot_id="snap-empty",
        query=text,
        items=[],
        supporting=[],
        contradictions=[],
        gaps=[EvidenceGap(topic="claim", reason="no evidence retrieved")],
        evidence_gap=True,
    )


@pytest.fixture
def policy():
    store = PolicyBundleStore()
    label_facts = LabelFacts(
        product_id=CN_PRODUCT,
        market="CN",
        version="CN-PI-2026-01",
        indication_id="IND-001",
        indication="成人原发性高血压",
        population="成人",
        line="一线",
        dose="80mg",
        route="口服",
        duration="长期",
        combination="单药",
    )
    engine = PolicyEngine(bundle=store.current(), label_facts=label_facts)

    class _Policy:
        def evaluate_policy(self, context, extracted, evidence, security_findings=()):
            return engine.evaluate(context, extracted, list(security_findings), evidence)

    return _Policy()


def test_route_review_creates_one_task_per_required_role(policy):
    result = policy.evaluate_policy(case_for("患者死亡"), extracted_for("患者死亡"), evidence_for("患者死亡"))
    plan = route_review(result)
    assert isinstance(plan, ReviewPlan)
    roles = {task.required_role for task in plan.review_tasks}
    assert Role.PHARMACOVIGILANCE in roles
    assert Role.MEDICAL_REVIEW in roles
    for task in plan.review_tasks:
        assert task.finding_ids
        assert task.status == "pending"


def test_route_review_sla_escalates_with_severity(policy):
    s0 = policy.evaluate_policy(case_for("患者死亡"), extracted_for("患者死亡"), evidence_for("患者死亡"))
    assert route_review(s0).sla_label == "4h"
    s1 = policy.evaluate_policy(case_for("安排宴请并帮忙安排处方"), extracted_for("安排宴请并帮忙安排处方"), evidence_for("安排宴请并帮忙安排处方"))
    assert route_review(s1).sla_label == "8h"
    s2 = policy.evaluate_policy(case_for("某主张"), extracted_for("某主张"), empty_evidence())
    assert route_review(s2).sla_label == "24h"


def test_route_review_category_routing(policy):
    cases = [
        ("患者身份证号110101199001011234", {}, Role.SECURITY),
        ("比竞品更安全", {}, Role.COMPLIANCE),
        ("推荐剂量100mg", {"dose": "100mg"}, Role.COMPLIANCE),
        ("安排宴请并帮忙安排处方", {}, Role.COMPLIANCE),
    ]
    for text, fields, role in cases:
        result = policy.evaluate_policy(case_for(text), extracted_for(text, fields=fields), evidence_for(text))
        plan = route_review(result)
        assert role in plan.required_roles, text


def test_route_review_evidence_gap_to_business_and_professional(policy):
    result = policy.evaluate_policy(case_for("某主张"), extracted_for("某主张"), empty_evidence())
    plan = route_review(result)
    assert Role.REPRESENTATIVE in plan.required_roles
    assert Role.MEDICAL_REVIEW in plan.required_roles
    assert plan.sla_label == "24h"


def test_route_review_s3_low_risk_guidance(policy):
    extracted = extracted_for("某主张", findings=[CandidateFinding(type="formatting", confidence=1.0)])
    result = policy.evaluate_policy(case_for("某主张"), extracted, evidence_for("某主张"))
    assert any(finding.severity == "S3" for finding in result.findings)
    assert result.decision == "allow"
    plan = route_review(result)
    assert Role.REVIEWER in plan.required_roles
    assert plan.sla_label == "72h"


def test_route_review_immutable_and_auditable(policy):
    result = policy.evaluate_policy(case_for("患者死亡"), extracted_for("患者死亡"), evidence_for("患者死亡"))
    plan = route_review(result)
    assert plan.immutable is True
    assert plan.route_version
    assert plan.routing_basis
    assert plan.next_actions


def test_route_review_raci_override_wins(policy):
    custom = RaciMatrix(
        entries=[
            RaciEntry(
                categories=["potential_adverse_event"],
                roles=[Role.LEGAL],
                sla_label="48h",
                next_actions=["custom legal review"],
            ),
        ]
    )
    result = policy.evaluate_policy(
        case_for("患者服药两天后出现皮疹，已停药"),
        extracted_for("患者服药两天后出现皮疹，已停药"),
        evidence_for("患者服药两天后出现皮疹，已停药"),
    )
    plan = route_review(result, custom)
    assert Role.LEGAL in plan.required_roles
    assert plan.sla_label == "48h"


def test_default_raci_covers_every_severity():
    matrix = default_raci()
    for severity in Severity:
        assert matrix.roles_for_severity(severity), severity.value


def test_raci_sla_matches_bundle_for_high_risk_rules():
    from types import SimpleNamespace

    from compliance_guard.domain.enums import Decision
    from compliance_guard.policy.bundles import parse_bundle_rules

    bundle = PolicyBundleStore().current()
    matrix = default_raci()
    for rule in parse_bundle_rules(bundle):
        if rule.severity in {Severity.S0, Severity.S1} or rule.decision in {
            Decision.BLOCKED,
            Decision.HUMAN_REVIEW,
        }:
            entry = matrix.resolve(SimpleNamespace(type=rule.type, severity=rule.severity))
            assert entry.sla_label == rule.sla_label, rule.rule_id
