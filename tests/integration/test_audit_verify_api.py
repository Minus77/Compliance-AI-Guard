"""C2: chain integrity is exposed as an endpoint, restricted like the trail itself.

A tamper-evident ledger is only useful if someone can ask it "are you intact?".
The answer names the first untrustworthy position so a reviewer can act on it,
and the route requires ``audit_export`` for the same reason the trail does: it
reports on records that name who did what.
"""

from __future__ import annotations

import json


def test_verify_reports_an_intact_chain(client, sample_request):
    client.post("/api/cases/check", json=sample_request("ae").model_dump(mode="json"))
    response = client.get("/api/audit-trail/verify", headers={"x-demo-role": "auditor"})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["first_broken_seq"] is None
    assert body["checked"] >= 1


def test_verify_requires_audit_export_permission(client):
    response = client.get("/api/audit-trail/verify", headers={"x-demo-role": "field_rep"})
    assert response.status_code == 403


def test_verify_rejects_an_unknown_role(client):
    response = client.get("/api/audit-trail/verify", headers={"x-demo-role": "nobody"})
    assert response.status_code == 403


def test_verify_detects_an_edited_ledger(client, sample_request):
    client.post("/api/cases/check", json=sample_request("ae").model_dump(mode="json"))
    intact = client.get("/api/audit-trail/verify", headers={"x-demo-role": "auditor"}).json()
    assert intact["ok"] is True

    path = intact["ledger_path"]
    lines = open(path, encoding="utf-8").read().splitlines()
    row = json.loads(lines[0])
    row["payload"]["tampered"] = True
    lines[0] = json.dumps(row, ensure_ascii=False, sort_keys=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    broken = client.get("/api/audit-trail/verify", headers={"x-demo-role": "auditor"}).json()
    assert broken["ok"] is False
    assert broken["first_broken_seq"] == 1
    assert broken["reason"]


def test_verify_states_what_the_check_proves(client):
    body = client.get("/api/audit-trail/verify", headers={"x-demo-role": "auditor"}).json()
    assert body["method"]
    assert "sha256" in body["method"].casefold()


def test_audit_trail_reports_chain_status_alongside_events(client, sample_request):
    client.post("/api/cases/check", json=sample_request("ae").model_dump(mode="json"))
    body = client.get("/api/audit-trail", headers={"x-demo-role": "auditor"}).json()
    assert body["chain"]["ok"] is True
    assert body["chain"]["checked"] >= 1
