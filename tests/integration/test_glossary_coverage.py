"""F1: every machine code a user can see has a plain-language explanation.

The requirement is that nothing reaches a reader as a bare code. That is only
enforceable as a coverage test: rules get added over time, and the failure mode is
silent — a new rule ships, the UI renders "CN-022", and nobody notices until a
representative asks what it means.

So this walks the policy bundle and asserts the glossary covers every finding type
and every decision it can produce.
"""

from __future__ import annotations

import json

import pytest

from compliance_guard.domain.enums import Decision, Severity
from compliance_guard.knowledge.glossary import Glossary, default_glossary
from compliance_guard.runtime_paths import config_dir


@pytest.fixture(scope="module")
def glossary() -> Glossary:
    return default_glossary()


@pytest.fixture(scope="module")
def policy_rules() -> dict:
    path = config_dir() / "policies" / "cn-demo.json"
    return json.loads(path.read_text(encoding="utf-8"))["rules"]


def test_every_policy_finding_type_is_explained(glossary, policy_rules):
    types = sorted({rule["type"] for rule in policy_rules.values()})
    assert glossary.missing_finding_types(types) == []


def test_every_decision_is_explained(glossary):
    for decision in Decision:
        card = glossary.explain_decision(decision.value)
        assert card.label, f"decision {decision.value} has no label"
        assert card.plain
        assert card.next_step


def test_every_severity_is_explained(glossary):
    for severity in Severity:
        card = glossary.explain_severity(severity.value)
        assert card["label"], f"severity {severity.value} has no label"
        assert card["plain"]


def test_each_finding_card_has_all_three_sentences(glossary, policy_rules):
    for rule in policy_rules.values():
        card = glossary.explain_finding(rule["type"])
        assert card.title, f"{rule['type']} has no title"
        assert card.why, f"{rule['type']} does not say why it matters"
        assert card.what_to_do, f"{rule['type']} does not say what to do"


def test_cards_do_not_leak_internal_codes(glossary, policy_rules):
    """A reader should never meet CN-009 or S1 as the explanation itself."""
    for rule_id, rule in policy_rules.items():
        card = glossary.explain_finding(rule["type"])
        prose = " ".join([card.title, card.why, card.what_to_do])
        assert rule_id not in prose
        assert rule["severity"] not in prose


def test_professional_terms_carry_a_definition(glossary):
    """Terms like AE and ICSR must be explained where they appear."""
    for key in ("adverse_event", "serious_adverse_event", "off_label", "pii", "icsr", "pseudonymisation"):
        term = glossary.term(key)
        assert term.label, f"{key} has no label"
        assert term.plain, f"{key} has no plain-language definition"


def test_english_locale_is_complete_for_finding_types(glossary, policy_rules):
    for rule in policy_rules.values():
        card = glossary.explain_finding(rule["type"], "en")
        assert card.title
        assert card.why
        assert card.what_to_do


def test_unknown_locale_falls_back_rather_than_returning_empty(glossary):
    card = glossary.explain_finding("potential_adverse_event", "de")
    assert card.title


def test_glossary_endpoint_serves_every_section(client):
    body = client.get("/api/glossary").json()
    assert body["glossary_version"]
    assert body["terms"]
    assert body["finding_types"]
    assert body["decisions"]
    assert body["severities"]


def test_glossary_endpoint_supports_english(client):
    body = client.get("/api/glossary", params={"locale": "en"}).json()
    card = body["finding_types"]["potential_adverse_event"]
    assert card["title"]
    assert "adverse" in card["term_label"].casefold()


def test_precheck_findings_reuse_the_same_wording(client):
    """One source of truth: the panel text must equal the glossary text."""
    glossary_body = client.get("/api/glossary").json()
    expected = glossary_body["finding_types"]["potential_adverse_event"]
    precheck = client.post(
        "/api/cases/precheck",
        json={"tenant_id": "TENANT-CN", "content": "患者服药后出现皮疹。", "product_id": "PRODUCT-001"},
    ).json()
    finding = next(f for f in precheck["findings"] if f["type"] == "potential_adverse_event")
    assert finding["title"] == expected["title"]
    assert finding["what_to_do"] == expected["what_to_do"]
