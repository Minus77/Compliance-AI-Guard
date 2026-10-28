"""E1: a deterministic pre-check fast enough to run while someone is typing.

The tool only reviewed content after submission (defect D-4), which is the wrong
moment: by then the rep has finished writing and a block feels like a rejection
rather than a hint. Pre-check runs the deterministic layer only — masking, rules,
label comparison — and never calls a model, which is what keeps it inside a
typing-latency budget.

What this route must *not* do is as important as what it does:

* no case is created, so a draft in progress does not become a record;
* the raw narrative is not stored;
* it shares the policy version with the submit path, so a hint and the final
  answer cannot contradict each other.
"""

from __future__ import annotations

import time


def _body(content: str, **extra) -> dict:
    payload = {
        "tenant_id": "TENANT-CN",
        "content": content,
        "market": "CN",
        "language": "zh-CN",
        "product_id": "PRODUCT-001",
        "source": "customer_interaction_note",
    }
    payload.update(extra)
    return payload


def test_precheck_flags_an_adverse_event(client):
    response = client.post("/api/cases/precheck", json=_body("患者服药后出现皮疹。"))
    assert response.status_code == 200
    body = response.json()
    assert "potential_adverse_event" in {f["type"] for f in body["findings"]}


def test_precheck_flags_a_redline_immediately(client):
    body = client.post("/api/cases/precheck", json=_body("赠送礼品给医生以表示感谢。")).json()
    assert "bribery_or_inducement" in {f["type"] for f in body["findings"]}
    assert body["decision"] == "blocked"


def test_precheck_masks_identifiers_before_returning(client):
    body = client.post(
        "/api/cases/precheck", json=_body("患者李四出现皮疹，电话13800138000。")
    ).json()
    assert "李四" not in body["masked_text"]
    assert "13800138000" not in body["masked_text"]
    assert "出现皮疹" in body["masked_text"]


def test_precheck_never_calls_a_model(client):
    body = client.post("/api/cases/precheck", json=_body("患者服药后出现皮疹。")).json()
    assert body["model_called"] is False
    assert body["layer"] == "L1"


def test_precheck_does_not_create_a_case(client):
    before = client.get("/api/audit-trail", headers={"x-demo-role": "auditor"}).json()["total"]
    client.post("/api/cases/precheck", json=_body("患者服药后出现皮疹。"))
    after = client.get("/api/audit-trail", headers={"x-demo-role": "auditor"}).json()["total"]
    assert after == before, "a draft in progress must not enter the audit record"


def test_precheck_reports_the_policy_version_it_used(client):
    body = client.post("/api/cases/precheck", json=_body("患者服药后出现皮疹。")).json()
    submitted = client.post(
        "/api/cases/check",
        json={
            "case_id": "req-precheck-parity",
            "tenant_id": "TENANT-CN",
            "content": "患者服药后出现皮疹。",
            "content_parts": [],
            "source": "customer_interaction_note",
            "source_record_id": "SR-precheck",
            "source_version": "v1",
            "market": "CN",
            "language": "zh-CN",
            "product_id": "PRODUCT-001",
            "channel": "customer_interaction_note",
            "received_at": "2026-08-20T00:00:00Z",
            "idempotency_key": "idem-precheck-parity",
            "extensions": {"entities": [], "structured_fields": {}},
        },
    ).json()
    assert body["policy_version"] == submitted["policy_version"]


def test_precheck_and_submit_agree_on_finding_types(client):
    """A hint that disappears on submit destroys trust in the hint."""
    content = "赠送礼品给医生以表示感谢。"
    pre = client.post("/api/cases/precheck", json=_body(content)).json()
    post = client.post(
        "/api/cases/check",
        json={
            "case_id": "req-precheck-agree",
            "tenant_id": "TENANT-CN",
            "content": content,
            "content_parts": [],
            "source": "customer_interaction_note",
            "source_record_id": "SR-precheck-2",
            "source_version": "v1",
            "market": "CN",
            "language": "zh-CN",
            "product_id": "PRODUCT-001",
            "channel": "customer_interaction_note",
            "received_at": "2026-08-20T00:00:00Z",
            "idempotency_key": "idem-precheck-agree",
            "extensions": {"entities": [], "structured_fields": {}},
        },
    ).json()
    pre_types = {f["type"] for f in pre["findings"]}
    post_types = {f["type"] for f in post["findings"]}
    assert pre_types <= post_types


def test_precheck_stays_within_the_latency_budget(client):
    """p95 < 300ms is the budget; the deterministic layer should be far under."""
    content = "患者李四服药后出现皮疹，章医生建议停药观察。"
    samples = []
    for _ in range(20):
        started = time.perf_counter()
        client.post("/api/cases/precheck", json=_body(content))
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()
    p95 = samples[max(0, int(len(samples) * 0.95) - 1)]
    assert p95 < 300, f"p95 {p95:.1f}ms exceeds the 300ms pre-check budget"


def test_precheck_reports_elapsed_time_for_slo_tracking(client):
    body = client.post("/api/cases/precheck", json=_body("患者服药后出现皮疹。")).json()
    assert body["elapsed_ms"] >= 0


def test_clean_content_returns_no_findings(client):
    body = client.post(
        "/api/cases/precheck", json=_body("本品适用于成人原发性高血压的治疗，应遵医嘱规律服用。")
    ).json()
    assert body["findings"] == []
    assert body["decision"] == "allow"


def test_empty_content_is_accepted_quietly(client):
    """An empty editor is not an error; it just has nothing to say yet."""
    body = client.post("/api/cases/precheck", json=_body("")).json()
    assert body["findings"] == []


def test_precheck_flags_off_label_from_the_narrative(client):
    body = client.post(
        "/api/cases/precheck", json=_body("本品对糖尿病也很有效，推荐给糖尿病患者。")
    ).json()
    assert "off_label" in {f["type"] for f in body["findings"]}


def test_precheck_findings_carry_plain_language_guidance(client):
    body = client.post("/api/cases/precheck", json=_body("患者服药后出现皮疹。")).json()
    finding = body["findings"][0]
    assert finding["title"]
    assert finding["what_to_do"]


def test_precheck_returns_every_repeated_phrase_span(client):
    body = client.post(
        "/api/cases/precheck",
        json=_body("皮疹和皮疹，随后停药。"),
    ).json()
    finding = next(item for item in body["findings"] if item["rule_id"] == "CN-001")

    assert [(span["start"], span["end"]) for span in finding["spans"]] == [
        (0, 2),
        (3, 5),
        (8, 10),
    ]


def test_precheck_returns_spans_for_multiple_fragments(client):
    body = client.post(
        "/api/cases/precheck",
        json=_body("皮疹并出现昏迷。"),
    ).json()
    spans_by_rule = {
        item["rule_id"]: [(span["start"], span["end"]) for span in item["spans"]]
        for item in body["findings"]
    }

    assert spans_by_rule["CN-001"] == [(0, 2)]
    assert spans_by_rule["CN-002"] == [(5, 7)]


def test_precheck_marks_spans_stale_when_client_version_differs(client):
    current = client.post(
        "/api/cases/precheck",
        json=_body("患者服药后出现皮疹。"),
    ).json()
    stale = client.post(
        "/api/cases/precheck",
        json=_body(
            "患者服药后出现皮疹。",
            client_content_version="an-outdated-editor-version",
        ),
    ).json()

    assert current["spans_stale"] is False
    assert stale["spans_stale"] is True
    assert stale["content_version"] == current["content_version"]
