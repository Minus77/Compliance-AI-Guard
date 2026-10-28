"""Rule workbench API contracts."""

from __future__ import annotations

from compliance_guard.domain.models import PolicyBundle
from compliance_guard.policy.bundles import PolicyRule


ADMIN = {"x-demo-role": "compliance_admin"}
AUDITOR = {"x-demo-role": "auditor"}
AUTHOR = {"x-demo-role": "field_rep"}


def _current_version(client) -> str:
    response = client.get("/api/rules", headers=AUDITOR)
    assert response.status_code == 200
    return response.json()["current_version"]


def test_rules_are_readable_by_auditors_and_manageable_by_admins(client):
    readable = client.get("/api/rules", headers=AUDITOR)
    denied = client.get("/api/rules", headers=AUTHOR)
    publish_denied = client.post(
        "/api/rules/publish",
        headers=AUTHOR,
        json={"version": "demo-v1"},
    )

    assert readable.status_code == 200
    assert readable.json()["current_version"].startswith("demo-v")
    assert len(readable.json()["rules"]) == 21
    assert denied.status_code == 403
    assert publish_denied.status_code == 403


def test_batch_evaluation_reports_a_dangerous_allow_and_unicode_spans(client):
    version = _current_version(client)
    response = client.post(
        "/api/rules/evaluate",
        headers=AUDITOR,
        json={
            "version": version,
            "cases": [
                {
                    "text": "该药保证治愈。",
                    "expected_decision": "blocked",
                    "expected_rule_ids": [],
                    "expected_spans": [],
                },
                {
                    "text": "赠送礼品给医生。",
                    "expected_decision": "blocked",
                    "expected_rule_ids": ["CN-003"],
                    "expected_spans": [{"start": 2, "end": 4}],
                },
            ],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["version"] == version
    assert body["total"] == 2
    assert body["passed"] == 1
    assert body["failures"] == 1
    assert body["dangerous_allow_count"] == 1
    assert body["overblock_count"] == 0
    assert body["span_failures"] == 0
    assert body["results"][1]["actual_spans"] == [{"start": 2, "end": 4, "quote_hash": None}]


def test_single_rule_test_compares_decision_rules_and_spans(client):
    version = _current_version(client)
    response = client.post(
        "/api/rules/test",
        headers=ADMIN,
        json={
            "version": version,
            "rule_id": "CN-003",
            "case": {
                "text": "赠送礼品给医生。",
                "expected_decision": "blocked",
                "expected_rule_ids": ["CN-003"],
                "expected_spans": [{"start": 2, "end": 4}],
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["passed"] is True
    assert response.json()["actual_decision"] == "blocked"


def test_batch_limit_is_enforced_without_evaluating_the_payload(client):
    version = _current_version(client)
    case = {
        "text": "普通内容",
        "expected_decision": "allow",
        "expected_rule_ids": [],
        "expected_spans": [],
    }
    response = client.post(
        "/api/rules/evaluate",
        headers=ADMIN,
        json={"version": version, "cases": [case] * 501},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_version_diff_reports_added_removed_and_modified_rules(client):
    lifecycle = client.app.state.services.rule_lifecycle
    before = _current_version(client)
    current = lifecycle.bundle(before)
    changed_rules = dict(current.rules)
    changed = PolicyRule.model_validate(changed_rules["CN-003"]).model_copy(
        update={"title": "Bribery and improper inducement"}
    )
    changed_rules["CN-003"] = changed
    changed_rules["TEST-001"] = PolicyRule(
        rule_id="TEST-001",
        version="1",
        title="Temporary test rule",
        description="Added only for the version diff contract.",
        category="test",
        type="temporary_test",
        severity="S3",
        decision="allow",
        patterns=["temporary phrase"],
    )
    changed_rules.pop("CN-021")
    after = lifecycle.draft(
        PolicyBundle(
            policy_version="diff-test",
            market=current.market,
            product_id=current.product_id,
            channel=current.channel,
            rules=changed_rules,
        )
    ).version

    response = client.get(
        "/api/rules/diff",
        headers=AUDITOR,
        params={"before": before, "after": after},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["added"] == ["TEST-001"]
    assert body["removed"] == ["CN-021"]
    assert body["modified"] == ["CN-003"]


def test_publishing_a_tested_version_changes_the_shared_check_version(client):
    lifecycle = client.app.state.services.rule_lifecycle
    before = _current_version(client)
    bundle = lifecycle.bundle(before)
    version = lifecycle.draft(
        PolicyBundle(
            policy_version="publish-test",
            market=bundle.market,
            product_id=bundle.product_id,
            channel=bundle.channel,
            rules=dict(bundle.rules),
        )
    ).version

    published = client.post(
        "/api/rules/publish",
        headers=ADMIN,
        json={"version": version},
    )
    check = client.post(
        "/api/checks/precheck",
        json={
            "tenant_id": "TENANT-RULES",
            "content_type": "promotional_content",
            "market": "CN",
            "language": "zh-CN",
            "content": "赠送礼品给医生。",
        },
    )

    assert published.status_code == 200
    assert published.json()["version"] == version
    assert check.status_code == 200
    assert check.json()["policy_version"] == version
