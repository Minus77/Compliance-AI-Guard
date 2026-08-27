"""H: the loop closes — submissions are findable, outcomes come back, work continues.

Four gaps this covers, all of which push a representative back toward writing
bland, safe notes:

* **H1 findability.** Submitting used to be the end of the road: no list, no way
  to look at what you sent. Work you cannot see is work you stop trusting.
* **H2 return path.** A review decision stayed with the reviewer. Silence after a
  block reads as "the tool ate my report".
* **H3 revision.** Being blocked meant retyping from nothing. The revision keeps a
  link to its parent so the reviewer sees version 2, and the original is never
  overwritten (21 CFR Part 11 §11.10(e)).
* **H4 appeal.** Without a channel to disagree, the only way past a false positive
  is to write less. The appeal explicitly does *not* lift the block: it creates
  work for a person, because an appeal that self-clears is a bypass.
"""

from __future__ import annotations

from conftest import build_sample_request


def _submit(client, scenario: str = "ae", role: str = "field_rep") -> dict:
    payload = build_sample_request(scenario).model_dump(mode="json")
    response = client.post("/api/cases/check", json=payload, headers={"x-demo-role": role})
    assert response.status_code == 200
    return response.json()


def _rep(headers: dict | None = None) -> dict:
    base = {"x-demo-role": "field_rep"}
    base.update(headers or {})
    return base


# -- H1: my records ---------------------------------------------------------


def test_representative_can_list_their_own_submissions(client):
    case_id = _submit(client)["case_id"]
    body = client.get("/api/cases", params={"scope": "mine"}, headers=_rep()).json()
    assert case_id in [row["case_id"] for row in body["cases"]]


def test_listing_carries_plain_language_status(client):
    _submit(client)
    row = client.get("/api/cases", params={"scope": "mine"}, headers=_rep()).json()["cases"][0]
    assert row["decision_label"]
    assert row["created_at"]


def test_representative_cannot_read_another_persons_records(client):
    _submit(client, role="field_rep")
    body = client.get("/api/cases", params={"scope": "all"}, headers=_rep()).json()
    # scope=all is silently narrowed for a field rep rather than erroring: the
    # answer is "your records", never someone else's.
    assert all(row["submitted_by"] == "demo-field_rep" for row in body["cases"])


def test_reviewer_can_list_every_case(client):
    _submit(client)
    body = client.get(
        "/api/cases", params={"scope": "all"}, headers={"x-demo-role": "compliance_admin"}
    ).json()
    assert body["cases"]


def test_listing_can_filter_by_decision(client):
    _submit(client, "pii")      # blocked
    _submit(client, "normal")   # allow
    body = client.get(
        "/api/cases", params={"scope": "mine", "decision": "blocked"}, headers=_rep()
    ).json()
    assert body["cases"]
    assert {row["decision"] for row in body["cases"]} == {"blocked"}


def test_listing_is_cursor_paginated(client):
    for scenario in ("ae", "normal", "redline"):
        _submit(client, scenario)
    first = client.get("/api/cases", params={"scope": "mine", "limit": 2}, headers=_rep()).json()
    assert len(first["cases"]) == 2
    assert first["next_cursor"]
    second = client.get(
        "/api/cases",
        params={"scope": "mine", "limit": 2, "cursor": first["next_cursor"]},
        headers=_rep(),
    ).json()
    ids = {row["case_id"] for row in first["cases"]} | {row["case_id"] for row in second["cases"]}
    assert len(ids) == 3


# -- H2: outcome returns to the author -------------------------------------


def test_review_decision_notifies_the_author(client):
    case = _submit(client, "ae")
    task_id = client.get(
        "/api/reviews", headers={"x-demo-role": "pv_reviewer"}
    ).json()["tasks"][0]["task_id"]
    client.post(
        f"/api/reviews/{task_id}/decision",
        json={"decision": "rejected", "reason": "需要补充患者信息后再提交"},
        headers={"x-demo-role": "pv_reviewer"},
    )
    inbox = client.get("/api/notifications", params={"unread": 1}, headers=_rep()).json()
    assert any(item["case_id"] == case["case_id"] for item in inbox["notifications"])


def test_notification_explains_the_outcome_in_plain_language(client):
    _submit(client, "ae")
    task_id = client.get(
        "/api/reviews", headers={"x-demo-role": "pv_reviewer"}
    ).json()["tasks"][0]["task_id"]
    client.post(
        f"/api/reviews/{task_id}/decision",
        json={"decision": "rejected", "reason": "需要补充患者信息"},
        headers={"x-demo-role": "pv_reviewer"},
    )
    item = client.get("/api/notifications", headers=_rep()).json()["notifications"][0]
    assert item["title"]
    assert item["next_step"]


def test_notification_carries_no_personal_identifiers(client):
    _submit(client, "pii")
    tasks = client.get("/api/reviews", headers={"x-demo-role": "compliance_admin"}).json()["tasks"]
    if tasks:
        client.post(
            f"/api/reviews/{tasks[0]['task_id']}/decision",
            json={"decision": "rejected", "reason": "含个人信息"},
            headers={"x-demo-role": "compliance_admin"},
        )
    body = client.get("/api/notifications", headers=_rep()).json()
    blob = str(body)
    assert "13800138000" not in blob


def test_notification_can_be_marked_read(client):
    _submit(client, "ae")
    task_id = client.get(
        "/api/reviews", headers={"x-demo-role": "pv_reviewer"}
    ).json()["tasks"][0]["task_id"]
    client.post(
        f"/api/reviews/{task_id}/decision",
        json={"decision": "escalated", "reason": "转医学复核"},
        headers={"x-demo-role": "pv_reviewer"},
    )
    item = client.get("/api/notifications", headers=_rep()).json()["notifications"][0]
    client.post(f"/api/notifications/{item['notification_id']}/read", headers=_rep())
    unread = client.get("/api/notifications", params={"unread": 1}, headers=_rep()).json()
    assert item["notification_id"] not in [n["notification_id"] for n in unread["notifications"]]


# -- H3: revision ----------------------------------------------------------


def test_revision_links_to_its_parent(client):
    original = _submit(client, "pii")
    revised = client.post(
        f"/api/cases/{original['case_id']}/revise",
        json={"content": "今天与客户讨论了产品资料，未涉及个人信息。"},
        headers=_rep(),
    )
    assert revised.status_code == 200
    body = revised.json()
    assert body["parent_case_id"] == original["case_id"]
    assert body["case_id"] != original["case_id"]


def test_revision_does_not_overwrite_the_original(client):
    original = _submit(client, "pii")
    client.post(
        f"/api/cases/{original['case_id']}/revise",
        json={"content": "今天与客户讨论了产品资料，未涉及个人信息。"},
        headers=_rep(),
    )
    kept = client.get(f"/api/cases/{original['case_id']}", headers=_rep()).json()
    assert kept["decision"] == original["decision"]


def test_revision_is_recorded_in_the_audit_trail(client):
    original = _submit(client, "pii")
    revised = client.post(
        f"/api/cases/{original['case_id']}/revise",
        json={"content": "今天与客户讨论了产品资料，未涉及个人信息。"},
        headers=_rep(),
    ).json()
    trail = client.get(
        "/api/audit-trail",
        params={"case_id": revised["case_id"]},
        headers={"x-demo-role": "auditor"},
    ).json()
    assert any(event["event_type"] == "case_revised" for event in trail["events"])


def test_only_the_author_can_revise_their_case(client):
    original = _submit(client, "pii")
    response = client.post(
        f"/api/cases/{original['case_id']}/revise",
        json={"content": "他人修改"},
        headers={"x-demo-role": "msl"},
    )
    assert response.status_code == 403


# -- H4: appeal ------------------------------------------------------------


def test_author_can_appeal_a_block(client):
    blocked = _submit(client, "pii")
    response = client.post(
        f"/api/cases/{blocked['case_id']}/appeal",
        json={"reason": "这是客户主动提出的要求，我只是如实记录。"},
        headers=_rep(),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "pending"


def test_appeal_requires_a_reason(client):
    blocked = _submit(client, "pii")
    response = client.post(
        f"/api/cases/{blocked['case_id']}/appeal",
        json={"reason": "   "},
        headers=_rep(),
    )
    assert response.status_code == 422


def test_appeal_does_not_lift_the_block(client):
    """An appeal that clears itself is a bypass, not an appeal."""
    blocked = _submit(client, "pii")
    client.post(
        f"/api/cases/{blocked['case_id']}/appeal",
        json={"reason": "我认为判断有误"},
        headers=_rep(),
    )
    still = client.get(f"/api/cases/{blocked['case_id']}", headers=_rep()).json()
    assert still["decision"] == blocked["decision"]


def test_appeal_creates_work_for_a_person(client):
    blocked = _submit(client, "pii")
    client.post(
        f"/api/cases/{blocked['case_id']}/appeal",
        json={"reason": "我认为判断有误"},
        headers=_rep(),
    )
    appeals = client.get("/api/appeals", headers={"x-demo-role": "compliance_admin"}).json()
    assert any(item["case_id"] == blocked["case_id"] for item in appeals["appeals"])


def test_appeal_is_recorded_in_the_audit_trail(client):
    blocked = _submit(client, "pii")
    client.post(
        f"/api/cases/{blocked['case_id']}/appeal",
        json={"reason": "我认为判断有误"},
        headers=_rep(),
    )
    trail = client.get(
        "/api/audit-trail",
        params={"case_id": blocked["case_id"]},
        headers={"x-demo-role": "auditor"},
    ).json()
    assert any(event["event_type"] == "case_appealed" for event in trail["events"])


def test_appeal_rate_is_visible_as_a_rule_quality_signal(client):
    blocked = _submit(client, "pii")
    client.post(
        f"/api/cases/{blocked['case_id']}/appeal",
        json={"reason": "我认为判断有误"},
        headers=_rep(),
    )
    summary = client.get("/api/appeals", headers={"x-demo-role": "compliance_admin"}).json()
    assert summary["summary"]["pending"] >= 1
