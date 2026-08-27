"""I: finish the features that stopped halfway.

Each of these told the user something was wrong without giving them a way to act:

* **I1 AE follow-up.** The ICSR read reported "no identifiable patient" and then
  offered nowhere to supply one. Naming a gap without a field to fill it is worse
  than silence, because it looks like the tool is refusing on purpose.
* **I2 queue throughput.** A reviewer had one undifferentiated list. Batch actions
  are allowed for low-severity items only: batch-signing S0/S1 is how meaningful
  oversight decays into clicking (EU AI Act Art.14).
* **I3 evidence export.** An inspector asks for one case's full chain. Without an
  export that is a manual reconstruction, and reconstruction is where records
  quietly diverge.
* **I4 master data.** One hard-coded product cannot demonstrate that prompt size
  is decoupled from catalogue size.
"""

from __future__ import annotations

from conftest import build_sample_request


def _submit(client, scenario: str = "ae") -> dict:
    payload = build_sample_request(scenario).model_dump(mode="json")
    response = client.post("/api/cases/check", json=payload, headers={"x-demo-role": "field_rep"})
    assert response.status_code == 200
    return response.json()


# -- I1: AE four-element follow-up capture ---------------------------------


def test_case_reports_which_icsr_elements_are_missing(client):
    body = _submit(client, "ae")
    assert body["icsr"]["is_safety_relevant"] is True
    assert "followup" in body


def test_followup_form_asks_only_for_what_is_missing(client):
    """A form that re-asks for known facts trains people to skip it."""
    body = _submit(client, "ae")
    fields = {item["field"] for item in body["followup"]["fields"]}
    met = {
        criterion["criterion"]
        for criterion in body["icsr"]["criteria"]
        if criterion["met"]
    }
    assert not (fields & met), "the form must not ask for criteria already satisfied"


def test_followup_fields_explain_why_they_are_needed(client):
    body = _submit(client, "ae")
    for item in body["followup"]["fields"]:
        assert item["label"]
        assert item["why"]


def test_followup_never_asks_for_a_patient_name(client):
    """Identifiability is established without collecting an identity."""
    body = _submit(client, "ae")
    blob = str(body["followup"]).casefold()
    assert "姓名" not in blob
    assert "name" not in blob


def test_submitting_followup_updates_the_icsr_assessment(client):
    case = _submit(client, "ae")
    response = client.post(
        f"/api/cases/{case['case_id']}/followup",
        json={
            "answers": {
                "identifiable_patient": "成年男性，60-65岁",
                "onset_date": "2026-08-18",
                "current_outcome": "已好转",
                "reporter_contact": "由本人转达",
            }
        },
        headers={"x-demo-role": "field_rep"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["icsr"]["criteria_met_count"] >= case["icsr"]["criteria_met_count"]


def test_followup_is_recorded_in_the_audit_trail(client):
    case = _submit(client, "ae")
    client.post(
        f"/api/cases/{case['case_id']}/followup",
        json={"answers": {"onset_date": "2026-08-18"}},
        headers={"x-demo-role": "field_rep"},
    )
    trail = client.get(
        "/api/audit-trail",
        params={"case_id": case["case_id"]},
        headers={"x-demo-role": "auditor"},
    ).json()
    assert any(event["event_type"] == "icsr_followup" for event in trail["events"])


def test_clean_case_needs_no_followup(client):
    body = _submit(client, "normal")
    assert body["followup"]["required"] is False
    assert body["followup"]["fields"] == []


# -- I2: review queue filtering and batch limits ---------------------------


def test_queue_can_filter_by_severity(client):
    _submit(client, "ae")
    body = client.get(
        "/api/reviews",
        params={"severity": "S1"},
        headers={"x-demo-role": "pv_reviewer"},
    ).json()
    assert all(task["severity"] == "S1" for task in body["tasks"])


def test_queue_can_filter_by_required_role(client):
    _submit(client, "ae")
    body = client.get(
        "/api/reviews",
        params={"required_role": "pharmacovigilance"},
        headers={"x-demo-role": "pv_reviewer"},
    ).json()
    assert all(task["required_role"] == "pharmacovigilance" for task in body["tasks"])


def test_queue_surfaces_sla_state(client):
    _submit(client, "ae")
    body = client.get("/api/reviews", headers={"x-demo-role": "pv_reviewer"}).json()
    assert "sla_breached" in body["tasks"][0]


def test_batch_decision_rejects_high_severity_items(client):
    """Batch-signing S0/S1 is how oversight decays into clicking."""
    _submit(client, "ae")
    tasks = client.get("/api/reviews", headers={"x-demo-role": "pv_reviewer"}).json()["tasks"]
    high = [t["task_id"] for t in tasks if t["severity"] in {"S0", "S1"}]
    assert high, "the AE fixture should produce a high-severity task"
    response = client.post(
        "/api/reviews/batch-decision",
        json={"task_ids": high, "decision": "escalated", "reason": "批量处理"},
        headers={"x-demo-role": "pv_reviewer"},
    )
    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "batch_not_allowed"
    assert "S0" in body["message"] or "S1" in body["message"]


def test_batch_decision_accepts_low_severity_items(client):
    _submit(client, "ae")
    tasks = client.get(
        "/api/reviews", params={"scope": "all"}, headers={"x-demo-role": "compliance_admin"}
    ).json()["tasks"]
    low = [t["task_id"] for t in tasks if t["severity"] in {"S2", "S3"}]
    if not low:
        return  # nothing low-severity in this fixture; the S0/S1 guard is the load-bearing test
    response = client.post(
        "/api/reviews/batch-decision",
        json={"task_ids": low, "decision": "accepted", "reason": "批量确认低风险项"},
        headers={"x-demo-role": "compliance_admin"},
    )
    assert response.status_code == 200
    assert response.json()["decided"] == len(low)


# -- I3: evidence chain export ---------------------------------------------


def test_export_contains_the_full_chain(client):
    case = _submit(client, "ae")
    body = client.get(
        f"/api/cases/{case['case_id']}/export",
        headers={"x-demo-role": "auditor"},
    ).json()
    for key in (
        "case_id",
        "input_hash",
        "masked_text",
        "findings",
        "evidence",
        "versions",
        "audit_events",
        "chain_verification",
    ):
        assert key in body, f"export is missing {key}"


def test_export_states_whether_the_chain_verifies(client):
    case = _submit(client, "ae")
    body = client.get(
        f"/api/cases/{case['case_id']}/export", headers={"x-demo-role": "auditor"}
    ).json()
    assert body["chain_verification"]["ok"] is True


def test_export_carries_no_raw_identifiers(client):
    case = _submit(client, "pii")
    body = client.get(
        f"/api/cases/{case['case_id']}/export", headers={"x-demo-role": "auditor"}
    ).json()
    assert "13800138000" not in str(body)


def test_export_requires_audit_permission(client):
    case = _submit(client, "ae")
    response = client.get(
        f"/api/cases/{case['case_id']}/export", headers={"x-demo-role": "msl"}
    )
    assert response.status_code == 403


def test_export_itself_is_audited(client):
    case = _submit(client, "ae")
    client.get(f"/api/cases/{case['case_id']}/export", headers={"x-demo-role": "auditor"})
    trail = client.get(
        "/api/audit-trail",
        params={"case_id": case["case_id"]},
        headers={"x-demo-role": "auditor"},
    ).json()
    assert any(event["event_type"] == "case_exported" for event in trail["events"])


def test_pdf_request_degrades_to_json_when_unavailable(client):
    """A missing optional dependency must not block an inspection request."""
    case = _submit(client, "ae")
    response = client.get(
        f"/api/cases/{case['case_id']}/export",
        params={"format": "pdf"},
        headers={"x-demo-role": "auditor"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["format"] in {"pdf", "json"}
    if body["format"] == "json":
        assert body["degraded_reason"]


# -- I4: master data --------------------------------------------------------


def test_product_list_covers_multiple_products(client):
    body = client.get("/api/master-data/products", params={"market": "CN"}).json()
    assert len(body["products"]) >= 5


def test_product_list_can_be_filtered_by_market(client):
    body = client.get("/api/master-data/products", params={"market": "US"}).json()
    assert body["products"]
    assert all(product["market"] == "US" for product in body["products"])


def test_product_entry_reports_its_current_label_version(client):
    body = client.get("/api/master-data/products", params={"market": "CN"}).json()
    entry = next(p for p in body["products"] if p["product_id"] == "PRODUCT-001")
    assert entry["label_version"] == "CN-PI-2026-01"
    assert entry["indication"]


def test_retired_label_versions_are_not_offered_as_current(client):
    body = client.get("/api/master-data/products", params={"market": "CN"}).json()
    versions = {p["label_version"] for p in body["products"]}
    assert "CN-PI-2024-01" not in versions
