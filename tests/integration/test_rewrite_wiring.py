"""F3 wiring: a blocked result carries the verified rewrite, or none at all."""

from __future__ import annotations

from conftest import build_sample_request


def _check(client, scenario: str) -> dict:
    payload = build_sample_request(scenario).model_dump(mode="json")
    response = client.post("/api/cases/check", json=payload)
    assert response.status_code == 200
    return response.json()


def test_blocked_case_offers_a_way_forward(client):
    body = _check(client, "redline")
    rewrite = body["guidance"]["rewrite"]
    assert rewrite["guidance"] or rewrite["available"]


def test_shown_suggestion_was_verified(client):
    """Nothing is displayed unless it passed the second deterministic check."""
    for scenario in ("redline", "pii", "injection", "off_label", "ae", "normal"):
        rewrite = _check(client, scenario)["guidance"]["rewrite"]
        if rewrite["available"]:
            assert rewrite["verified"] is True
            assert rewrite["residual_findings"] == []


def test_safety_content_is_never_rewritten_away(client):
    body = _check(client, "ae")
    rewrite = body["guidance"]["rewrite"]
    assert rewrite["available"] is False


def test_clean_case_needs_no_rewrite(client):
    body = _check(client, "normal")
    assert body["guidance"]["rewrite"]["available"] is False


def test_rewrite_decision_is_audited(client):
    body = _check(client, "redline")
    trail = client.get(
        "/api/audit-trail",
        params={"case_id": body["case_id"]},
        headers={"x-demo-role": "auditor"},
    ).json()
    assert any(event["event_type"] == "rewrite_offered" for event in trail["events"])
