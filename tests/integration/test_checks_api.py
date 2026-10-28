"""Public content-check API contracts."""

from tests.conftest import build_sample_request


def _body(**extra):
    body = {
        "tenant_id": "TENANT-A",
        "content_type": "promotional_content",
        "market": "CN",
        "language": "zh-CN",
        "product_id": "PRODUCT-A",
        "content": "皮疹并出现昏迷。",
    }
    body.update(extra)
    return body


def test_public_check_routes_share_rule_version_and_original_spans(client):
    precheck = client.post("/api/checks/precheck", json=_body())
    submitted = client.post(
        "/api/checks",
        json=_body(),
        headers={"x-demo-role": "field_rep"},
    )

    assert precheck.status_code == 200
    assert submitted.status_code == 201
    assert precheck.json()["policy_version"] == submitted.json()["policy_version"]
    assert any(finding["spans"] for finding in submitted.json()["findings"])


def test_submitted_check_is_scoped_to_its_tenant(client):
    submitted = client.post(
        "/api/checks",
        json=_body(),
        headers={"x-demo-role": "field_rep"},
    ).json()
    check_id = submitted["check_id"]

    own = client.get(
        f"/api/checks/{check_id}",
        params={"tenant_id": "TENANT-A"},
        headers={"x-demo-role": "field_rep"},
    )
    other = client.get(
        f"/api/checks/{check_id}",
        params={"tenant_id": "TENANT-B"},
        headers={"x-demo-role": "field_rep"},
    )

    assert own.status_code == 200
    assert other.status_code == 404
    assert "皮疹并出现昏迷" not in other.text


def test_check_preview_and_legacy_case_agree_on_decision(client):
    body = _body(content="赠送礼品给医生以表示感谢。")
    modern = client.post("/api/checks/precheck", json=body).json()
    legacy = client.post(
        "/api/cases/precheck",
        json={
            "tenant_id": body["tenant_id"],
            "content_type": body["content_type"],
            "content": body["content"],
            "market": body["market"],
            "language": body["language"],
            "product_id": body["product_id"],
        },
    ).json()

    assert modern["decision"] == legacy["decision"]
    assert modern["policy_version"] == legacy["policy_version"]


def test_check_marks_result_stale_but_returns_the_compared_version(client):
    current = client.post("/api/checks/precheck", json=_body()).json()
    stale = client.post(
        "/api/checks/precheck",
        json=_body(client_content_version="older-editor-content"),
    ).json()

    assert stale["spans_stale"] is True
    assert stale["content_version"] == current["content_version"]
    assert stale["findings"]


def test_legacy_submission_uses_the_shared_check_service(client):
    response = client.post(
        "/api/cases/check",
        json=build_sample_request("ae").model_dump(mode="json"),
    )

    assert response.status_code == 200
    assert any(finding["spans"] for finding in response.json()["findings"])
