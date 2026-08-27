"""F2: the result reads as three sentences, not as a severity code.

A representative should not need to know what ``S1`` or ``CN-009`` means to act
correctly. Every result therefore carries, in a fixed order: what happened, why it
matters, and what to do next.

The machine codes are kept — an auditor reconciling a case needs them — but they
move into a technical section rather than being the headline. That split is the
whole point: the same response serves a rep who needs to act and a reviewer who
needs to verify.
"""

from __future__ import annotations

import re

from conftest import build_sample_request

_CODE_RE = re.compile(r"\b(?:CN-\d{3}|S[0-3])\b")


def _check(client, scenario: str) -> dict:
    payload = build_sample_request(scenario).model_dump(mode="json")
    response = client.post("/api/cases/check", json=payload)
    assert response.status_code == 200
    return response.json()


def test_response_carries_a_headline_and_next_step(client):
    body = _check(client, "ae")
    guidance = body["guidance"]
    assert guidance["decision_label"]
    assert guidance["decision_plain"]
    assert guidance["next_step"]


def test_each_finding_has_the_three_sentences(client):
    body = _check(client, "ae")
    assert body["guidance"]["findings"]
    for card in body["guidance"]["findings"]:
        assert card["title"]
        assert card["why"]
        assert card["what_to_do"]


def test_headline_prose_contains_no_machine_codes(client):
    body = _check(client, "ae")
    guidance = body["guidance"]
    prose = " ".join(
        [guidance["decision_label"], guidance["decision_plain"], guidance["next_step"]]
        + [c["title"] for c in guidance["findings"]]
        + [c["why"] for c in guidance["findings"]]
        + [c["what_to_do"] for c in guidance["findings"]]
    )
    assert not _CODE_RE.search(prose), f"machine code leaked into user prose: {prose}"


def test_machine_codes_remain_available_for_audit(client):
    """Plain language for the reader, exact codes for the record."""
    body = _check(client, "ae")
    assert body["policy_version"]
    for finding in body["findings"]:
        assert finding["severity"]
    technical = body["guidance"]["technical"]
    assert technical["policy_version"] == body["policy_version"]
    assert technical["rule_ids"]


def test_finding_cards_carry_the_term_definition(client):
    body = _check(client, "ae")
    card = next(
        c for c in body["guidance"]["findings"] if c["type"] == "potential_adverse_event"
    )
    assert card["term_label"]
    assert card["term_plain"]


def test_clean_content_says_it_is_ready(client):
    body = _check(client, "normal")
    assert body["guidance"]["decision_label"]
    assert body["guidance"]["next_step"]


def test_guidance_wording_matches_the_glossary(client):
    """One source of truth across pre-check, submit and the glossary endpoint."""
    expected = client.get("/api/glossary").json()["finding_types"]["potential_adverse_event"]
    body = _check(client, "ae")
    card = next(
        c for c in body["guidance"]["findings"] if c["type"] == "potential_adverse_event"
    )
    assert card["title"] == expected["title"]
    assert card["why"] == expected["why"]
    assert card["what_to_do"] == expected["what_to_do"]


def test_blocked_result_offers_a_way_forward(client):
    body = _check(client, "redline")
    assert body["guidance"]["next_step"]


def test_guidance_lists_who_needs_to_act(client):
    body = _check(client, "ae")
    assert body["guidance"]["review_roles"]
