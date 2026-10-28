"""A release without a durable audit record must fail closed."""

import json

import pytest
from fastapi.testclient import TestClient

from apps.api.main import create_app
from compliance_guard.llm.types import RawModelResult


RAW_CONTENT = "患者李四电话13800138000，请概述用药信息。"
SAFE_PROMPT = "请概述成人高血压用药时需要注意的安全信息。"


class AllowedGateway:
    def complete(self, task_type, request, constraints):
        return RawModelResult(
            provider="fake",
            model_id=constraints.model_id,
            profile_id=constraints.profile_id,
            route_version=constraints.route_version,
            raw_json={
                "text": "请按说明书使用并遵医嘱；如出现不适，请及时咨询医疗专业人员。"
            },
        )


@pytest.fixture(autouse=True)
def _demo_mode(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")


def _client(app_services) -> TestClient:
    gateway = AllowedGateway()
    app_services.gateway = gateway
    app_services.conversations._gateway = gateway
    return TestClient(create_app(services=app_services))


def _check_body(content: str = RAW_CONTENT) -> dict[str, str]:
    return {
        "tenant_id": "TENANT-A",
        "content_type": "medical_information_request",
        "market": "CN",
        "language": "zh-CN",
        "product_id": "PRODUCT-A",
        "content": content,
    }


def _fail_audit(monkeypatch, ledger):
    def unavailable(_event):
        raise OSError("disk unavailable at /private/provider/path")

    monkeypatch.setattr(ledger, "append", unavailable)


def test_content_submission_returns_no_success_when_audit_write_fails(
    app_services, monkeypatch
):
    client = _client(app_services)
    _fail_audit(monkeypatch, app_services.ledger)

    response = client.post(
        "/api/checks",
        json=_check_body(),
        headers={"x-demo-role": "field_rep"},
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "audit_unavailable"
    assert "check_id" not in response.text
    assert RAW_CONTENT not in response.text
    assert "disk unavailable" not in response.text


def test_conversation_generation_publishes_only_after_audit_succeeds(
    app_services, monkeypatch
):
    client = _client(app_services)
    guarded = client.post(
        "/api/conversations/guard-input",
        json={
            "tenant_id": "TENANT-A",
            "content": SAFE_PROMPT,
            "market": "CN",
            "language": "zh-CN",
            "product_id": "PRODUCT-A",
        },
        headers={"x-demo-role": "field_rep"},
    )
    assert guarded.status_code == 200
    assert guarded.json()["conversation_id"]

    _fail_audit(monkeypatch, app_services.ledger)
    response = client.post(
        f"/api/conversations/{guarded.json()['conversation_id']}/generate",
        json={"tenant_id": "TENANT-A", "content": SAFE_PROMPT},
        headers={"x-demo-role": "field_rep"},
    )

    assert response.status_code == 503
    assert response.json()["state"] == "failed_safe"
    assert response.json()["published_text"] == ""
    assert RAW_CONTENT not in response.text
    assert "disk unavailable" not in response.text


def test_successful_release_keeps_raw_narrative_out_of_audit(
    app_services, monkeypatch
):
    client = _client(app_services)
    response = client.post(
        "/api/checks",
        json=_check_body(),
        headers={"x-demo-role": "field_rep"},
    )
    assert response.status_code == 201

    serialized = json.dumps(
        [event.model_dump(mode="json") for event in app_services.ledger.all()],
        ensure_ascii=False,
    )
    assert RAW_CONTENT not in serialized
    assert "13800138000" not in serialized
    assert "患者李四" not in serialized
    assert app_services.ledger.verify().ok is True
