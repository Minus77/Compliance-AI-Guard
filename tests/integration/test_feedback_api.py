"""C3 API: reviewers can report a misclassification, and it takes two to confirm.

The loop only closes if reporting is reachable from where the mistake is seen, so
these routes sit next to the case rather than in a separate admin tool.
"""

from __future__ import annotations


def _submit(client, scenario: str = "ae") -> str:
    from conftest import build_sample_request

    payload = build_sample_request(scenario).model_dump(mode="json")
    response = client.post("/api/cases/check", json=payload)
    assert response.status_code == 200
    return response.json()["case_id"]


def test_reviewer_can_report_a_false_positive(client):
    case_id = _submit(client)
    response = client.post(
        f"/api/cases/{case_id}/feedback",
        json={"kind": "false_positive", "reason": "常规拜访记录被误判"},
        headers={"x-demo-role": "compliance_admin"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "candidate"
    assert body["expected_decision"] == "allow"


def test_report_requires_a_reason(client):
    case_id = _submit(client)
    response = client.post(
        f"/api/cases/{case_id}/feedback",
        json={"kind": "false_positive", "reason": "  "},
        headers={"x-demo-role": "compliance_admin"},
    )
    assert response.status_code == 422


def test_field_rep_cannot_reshape_the_regression_set(client):
    case_id = _submit(client)
    response = client.post(
        f"/api/cases/{case_id}/feedback",
        json={"kind": "false_negative", "reason": "漏检"},
        headers={"x-demo-role": "field_rep"},
    )
    assert response.status_code == 403


def test_unknown_case_is_rejected(client):
    response = client.post(
        "/api/cases/CASE-does-not-exist/feedback",
        json={"kind": "false_positive", "reason": "误判"},
        headers={"x-demo-role": "compliance_admin"},
    )
    assert response.status_code == 404


def test_stored_candidate_carries_only_masked_text(client):
    case_id = _submit(client, "pii")
    client.post(
        f"/api/cases/{case_id}/feedback",
        json={"kind": "false_positive", "reason": "误判"},
        headers={"x-demo-role": "compliance_admin"},
    )
    listing = client.get("/api/feedback", headers={"x-demo-role": "compliance_admin"}).json()
    entry = listing["entries"][0]
    assert "13800138000" not in entry["masked_text"]


def test_confirmation_requires_a_second_person(client):
    case_id = _submit(client)
    created = client.post(
        f"/api/cases/{case_id}/feedback",
        json={"kind": "false_positive", "reason": "误判"},
        headers={"x-demo-role": "compliance_admin"},
    ).json()
    again = client.post(
        f"/api/feedback/{created['entry_id']}/confirm",
        headers={"x-demo-role": "compliance_admin"},
    )
    assert again.status_code == 403


def test_a_different_role_can_confirm(client):
    case_id = _submit(client)
    created = client.post(
        f"/api/cases/{case_id}/feedback",
        json={"kind": "false_negative", "reason": "漏检了不良事件"},
        headers={"x-demo-role": "compliance_admin"},
    ).json()
    confirmed = client.post(
        f"/api/feedback/{created['entry_id']}/confirm",
        headers={"x-demo-role": "pv_reviewer"},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "confirmed"


def test_listing_reports_counts_for_the_dashboard(client):
    case_id = _submit(client)
    client.post(
        f"/api/cases/{case_id}/feedback",
        json={"kind": "false_positive", "reason": "误判"},
        headers={"x-demo-role": "compliance_admin"},
    )
    listing = client.get("/api/feedback", headers={"x-demo-role": "compliance_admin"}).json()
    assert listing["summary"]["pending"] == 1
    assert listing["summary"]["false_positive"] == 1


def test_feedback_report_is_audited(client):
    case_id = _submit(client)
    client.post(
        f"/api/cases/{case_id}/feedback",
        json={"kind": "false_positive", "reason": "误判"},
        headers={"x-demo-role": "compliance_admin"},
    )
    trail = client.get(
        "/api/audit-trail", params={"case_id": case_id}, headers={"x-demo-role": "auditor"}
    ).json()
    assert any(event["event_type"] == "feedback_reported" for event in trail["events"])
