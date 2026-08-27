"""F4: measure whether the tool is quietly pushing people to write less.

Every other metric in this system watches for risk getting through. This one
watches for the opposite failure, which is just as damaging and much harder to
see: a representative who hits a warning, deletes the paragraph, and submits
something bland instead. Nothing is blocked, no finding is raised, and the
narrative detail the product exists to encourage is simply gone.

So abandonment is counted. Two constraints:

* **Event only, never content.** Recording what someone abandoned would mean
  storing exactly the text they chose not to submit — the one thing the pre-check
  design is careful never to keep.
* **Read beside the safety numbers.** A falling detection count next to a rising
  abandonment count means the rules got tighter, not that risk went away.
"""

from __future__ import annotations


def test_abandonment_can_be_recorded(client):
    response = client.post(
        "/api/telemetry/usability",
        json={"event": "rep_abandon", "context": {"had_findings": True}},
        headers={"x-demo-role": "field_rep"},
    )
    assert response.status_code == 200
    assert response.json()["recorded"] is True


def test_recorded_event_appears_in_metrics(client):
    client.post(
        "/api/telemetry/usability",
        json={"event": "rep_abandon"},
        headers={"x-demo-role": "field_rep"},
    )
    counters = client.get("/api/metrics").json()["counters"]
    assert counters.get("usability.rep_abandon", 0) >= 1


def test_narrative_text_is_refused(client):
    """The endpoint must not become a place abandoned drafts accumulate."""
    response = client.post(
        "/api/telemetry/usability",
        json={"event": "rep_abandon", "context": {"content": "患者李四出现皮疹"}},
        headers={"x-demo-role": "field_rep"},
    )
    assert response.status_code == 422


def test_unknown_event_names_are_rejected(client):
    response = client.post(
        "/api/telemetry/usability",
        json={"event": "whatever_i_like"},
        headers={"x-demo-role": "field_rep"},
    )
    assert response.status_code == 422


def test_precheck_shown_is_counted_as_the_denominator(client):
    """An abandonment rate without a denominator says nothing."""
    client.post(
        "/api/telemetry/usability",
        json={"event": "precheck_shown"},
        headers={"x-demo-role": "field_rep"},
    )
    counters = client.get("/api/metrics").json()["counters"]
    assert counters.get("usability.precheck_shown", 0) >= 1


def test_usability_summary_reports_a_rate_with_its_denominator(client):
    for _ in range(4):
        client.post(
            "/api/telemetry/usability",
            json={"event": "precheck_shown"},
            headers={"x-demo-role": "field_rep"},
        )
    client.post(
        "/api/telemetry/usability",
        json={"event": "rep_abandon"},
        headers={"x-demo-role": "field_rep"},
    )
    summary = client.get("/api/metrics").json()["usability"]
    assert summary["precheck_shown"] == 4
    assert summary["abandoned"] == 1
    assert summary["abandon_rate"] == 0.25


def test_summary_is_honest_when_there_is_no_data(client):
    summary = client.get("/api/metrics").json()["usability"]
    assert summary["abandon_rate"] is None
    assert summary["status"] == "insufficient_data"


def test_summary_explains_itself_in_plain_language(client):
    summary = client.get("/api/metrics").json()["usability"]
    assert summary["message"]


def test_frontend_reports_abandonment(client):
    js = client.get("/assets/app.js").text
    assert "/api/telemetry/usability" in js
    assert "rep_abandon" in js


def test_frontend_never_sends_the_abandoned_text(client):
    js = client.get("/assets/app.js").text
    start = js.index("function reportAbandon")
    body = js[start : start + 700]
    assert "content" not in body.replace("contentField", "").replace("hadContent", "")
