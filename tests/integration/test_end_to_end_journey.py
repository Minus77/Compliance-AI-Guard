"""L1: one representative, one report, all the way through.

Every other test checks a component. This one checks that the components form a
loop a person can actually complete: write, get warned, submit, be reviewed, hear
back, revise, get released, and hand the evidence to an auditor.

The reason it exists as a single test is that the gaps this project set out to fix
were all *between* steps. Each piece worked; the seam between them was where the
report vanished. A test per component would have passed the whole time.
"""

from __future__ import annotations

from conftest import build_sample_request

REP = {"x-demo-role": "field_rep"}
PV = {"x-demo-role": "pv_reviewer"}
AUDIT = {"x-demo-role": "auditor"}


def test_full_journey_from_draft_to_evidence_export(client):
    # --- 1. warned while writing, before anything is committed -------------
    precheck = client.post(
        "/api/cases/precheck",
        json={
            "tenant_id": "TENANT-CN",
            "content": "今天拜访了章三，患者李四服药后出现皮疹。",
            "product_id": "PRODUCT-001",
        },
    ).json()
    assert precheck["model_called"] is False, "the typing path must not call a model"
    assert "potential_adverse_event" in {f["type"] for f in precheck["findings"]}
    # Identifiers are already masked, and the narrative around them survives.
    assert "李四" not in precheck["masked_text"]
    assert "出现皮疹" in precheck["masked_text"]

    # --- 2. submit ---------------------------------------------------------
    submitted = client.post(
        "/api/cases/check",
        json=build_sample_request("ae").model_dump(mode="json"),
        headers=REP,
    ).json()
    case_id = submitted["case_id"]
    assert submitted["decision"] == "human_review"
    # Plain language leads; the codes are available but not the headline.
    assert submitted["guidance"]["decision_label"]
    assert submitted["guidance"]["next_step"]
    assert submitted["guidance"]["technical"]["rule_ids"]

    # --- 3. the report is findable ----------------------------------------
    mine = client.get("/api/cases", params={"scope": "mine"}, headers=REP).json()
    assert case_id in [row["case_id"] for row in mine["cases"]]

    # --- 4. missing safety elements are collectable, not just reported -----
    if submitted["followup"]["required"]:
        updated = client.post(
            f"/api/cases/{case_id}/followup",
            json={"answers": {"identifiable_patient": "成年男性，60-65岁",
                              "onset_date": "2026-08-18",
                              "current_outcome": "已好转"}},
            headers=REP,
        ).json()
        assert updated["icsr"]["criteria_met_count"] >= submitted["icsr"]["criteria_met_count"]

    # --- 5. a reviewer decides, with a signature --------------------------
    task = client.get("/api/reviews", headers=PV).json()["tasks"][0]
    decision = client.post(
        f"/api/reviews/{task['task_id']}/decision",
        json={"decision": "escalated", "reason": "已确认为可上报的不良事件，转医学复核"},
        headers=PV,
    ).json()
    assert decision["signature"]["content_digest"]

    # --- 6. the outcome comes back to the author --------------------------
    inbox = client.get("/api/notifications", params={"unread": 1}, headers=REP).json()
    assert case_id in [item["case_id"] for item in inbox["notifications"]]
    assert inbox["notifications"][0]["next_step"]

    # --- 7. revise without losing the original ----------------------------
    revision = client.post(
        f"/api/cases/{case_id}/revise",
        json={"content": "本品适用于成人原发性高血压的治疗，应遵医嘱规律服用。"},
        headers=REP,
    ).json()
    assert revision["parent_case_id"] == case_id
    original = client.get(f"/api/cases/{case_id}", headers=REP).json()
    assert original["decision"] == submitted["decision"], "the original must not be overwritten"

    # --- 8. hand the chain to an auditor ----------------------------------
    export = client.get(f"/api/cases/{case_id}/export", headers=AUDIT).json()
    assert export["input_hash"]
    assert export["audit_events"]
    assert export["chain_verification"]["ok"] is True

    # --- 9. the ledger still verifies end to end --------------------------
    verify = client.get("/api/audit-trail/verify", headers=AUDIT).json()
    assert verify["ok"] is True
    assert verify["checked"] >= len(export["audit_events"])


def test_journey_leaves_a_complete_audit_narrative(client):
    """An auditor should be able to reconstruct what happened without asking anyone."""
    submitted = client.post(
        "/api/cases/check",
        json=build_sample_request("ae").model_dump(mode="json"),
        headers=REP,
    ).json()
    events = client.get(
        "/api/audit-trail", params={"case_id": submitted["case_id"]}, headers=AUDIT
    ).json()["events"]
    types = [event["event_type"] for event in events]
    for expected in (
        "case_received",
        "security_findings",
        "entity_resolution",
        "field_resolution",
        "scenario_inferred",
        "evidence_retrieved",
        "model_call",
        "rewrite_offered",
    ):
        assert expected in types, f"the trail is missing {expected}"
    # Append-only ordering: the terminal transition is last.
    assert types[-1] == "transition.COMPLETED"


def test_journey_never_writes_an_identifier_into_the_trail(client):
    submitted = client.post(
        "/api/cases/check",
        json=build_sample_request("pii").model_dump(mode="json"),
        headers=REP,
    ).json()
    events = client.get(
        "/api/audit-trail", params={"case_id": submitted["case_id"]}, headers=AUDIT
    ).json()
    assert "13800138000" not in str(events)


def test_blocked_case_offers_a_route_that_is_not_giving_up(client):
    """Blocked plus no way forward is what teaches people to write less."""
    blocked = client.post(
        "/api/cases/check",
        json=build_sample_request("pii").model_dump(mode="json"),
        headers=REP,
    ).json()
    assert blocked["decision"] == "blocked"
    guidance = blocked["guidance"]
    assert guidance["next_step"]
    # Either a verified rewrite or an explanation, never a bare refusal.
    assert guidance["rewrite"]["available"] or guidance["rewrite"]["guidance"]

    appeal = client.post(
        f"/api/cases/{blocked['case_id']}/appeal",
        json={"reason": "客户主动询问，我如实记录了对话内容。"},
        headers=REP,
    )
    assert appeal.status_code == 200
    # An appeal creates work; it does not clear the block.
    still = client.get(f"/api/cases/{blocked['case_id']}", headers=REP).json()
    assert still["decision"] == "blocked"
