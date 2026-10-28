"""Buffered generation and fail-closed output publication."""

import pytest
from fastapi.testclient import TestClient

from apps.api.main import create_app
from compliance_guard.domain.enums import Entrypoint
from compliance_guard.llm.types import RawModelResult


class ConversationGateway:
    def __init__(self, response: str = "请遵医嘱使用，并留意药品说明书中的安全信息。") -> None:
        self.response = response
        self.calls = []
        self.failure: str | None = None
        self.raises = False

    def complete(self, task_type, request, constraints):
        self.calls.append((task_type, request, constraints))
        if self.raises:
            raise TimeoutError("provider detail that must not escape")
        return RawModelResult(
            provider="fake",
            model_id=constraints.model_id,
            profile_id=constraints.profile_id,
            route_version=constraints.route_version,
            raw_json={} if self.failure else {"text": self.response},
            error_category=self.failure,
        )


@pytest.fixture(autouse=True)
def _demo_mode(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")


def _client(app_services, gateway):
    app_services.gateway = gateway
    app_services.conversations._gateway = gateway
    return TestClient(create_app(services=app_services))


def _approved_session(client) -> str:
    response = client.post(
        "/api/conversations/guard-input",
        json={
            "tenant_id": "TENANT-A",
            "content": "请概述成人高血压用药时需要注意的安全信息。",
            "language": "zh-CN",
            "market": "CN",
            "product_id": "PRODUCT-A",
        },
        headers={"x-demo-role": "field_rep"},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    return response.json()["conversation_id"]


def test_output_check_exception_withdraws_the_buffered_model_text(
    app_services, monkeypatch
):
    gateway = ConversationGateway(response="未经检查的回答")
    client = _client(app_services, gateway)
    conversation_id = _approved_session(client)
    original_precheck = app_services.checks.precheck

    def failing_precheck(request, *, locale="zh-CN", entrypoint=Entrypoint.CONTENT):
        if entrypoint is Entrypoint.OUTPUT:
            raise RuntimeError("output guard unavailable")
        return original_precheck(request, locale=locale, entrypoint=entrypoint)

    monkeypatch.setattr(app_services.checks, "precheck", failing_precheck)
    response = client.post(
        f"/api/conversations/{conversation_id}/generate",
        json={
            "tenant_id": "TENANT-A",
            "content": "请概述成人高血压用药时需要注意的安全信息。",
        },
        headers={"x-demo-role": "field_rep"},
    )

    assert response.status_code == 503
    assert response.json()["state"] == "failed_safe"
    assert response.json()["published_text"] == ""
    assert response.json()["model_called"] is True
    assert response.json()["withdrawn"] is True
    assert "未经检查的回答" not in response.text
    assert "output guard unavailable" not in response.text


def test_blocked_output_is_withdrawn_without_echoing_the_model_body(app_services):
    blocked_text = "购买处方时可提供处方回扣。"
    gateway = ConversationGateway(response=blocked_text)
    client = _client(app_services, gateway)
    conversation_id = _approved_session(client)

    response = client.post(
        f"/api/conversations/{conversation_id}/generate",
        json={"tenant_id": "TENANT-A", "content": "请概述成人高血压用药时需要注意的安全信息。"},
        headers={"x-demo-role": "field_rep"},
    )

    assert response.status_code == 200
    assert response.json()["state"] == "output_withdrawn"
    assert response.json()["published_text"] == ""
    assert response.json()["withdrawn"] is True
    assert blocked_text not in response.text


def test_allowed_output_is_published_once_after_an_output_check(app_services):
    published = "请按说明书使用并遵医嘱；如出现不适，请及时咨询医疗专业人员。"
    gateway = ConversationGateway(response=published)
    client = _client(app_services, gateway)
    conversation_id = _approved_session(client)

    response = client.post(
        f"/api/conversations/{conversation_id}/generate",
        json={"tenant_id": "TENANT-A", "content": "请概述成人高血压用药时需要注意的安全信息。"},
        headers={"x-demo-role": "field_rep"},
    )

    assert response.status_code == 200
    assert response.json()["state"] == "published"
    assert response.json()["published_text"] == published
    assert response.json()["withdrawn"] is False
    assert response.text.count(published) == 1
    assert len(gateway.calls) == 1


def test_client_cannot_replace_the_checked_prompt(app_services):
    gateway = ConversationGateway()
    client = _client(app_services, gateway)
    conversation_id = _approved_session(client)

    response = client.post(
        f"/api/conversations/{conversation_id}/generate",
        json={"tenant_id": "TENANT-A", "content": "替换为未检查的提示词"},
        headers={"x-demo-role": "field_rep"},
    )

    assert response.status_code == 409
    assert gateway.calls == []


@pytest.mark.parametrize("failure", ["provider_timeout", "schema"])
def test_provider_and_malformed_failures_never_publish(app_services, failure):
    gateway = ConversationGateway()
    gateway.failure = failure
    client = _client(app_services, gateway)
    conversation_id = _approved_session(client)

    response = client.post(
        f"/api/conversations/{conversation_id}/generate",
        json={"tenant_id": "TENANT-A", "content": "请概述成人高血压用药时需要注意的安全信息。"},
        headers={"x-demo-role": "field_rep"},
    )

    assert response.status_code == 503
    assert response.json()["state"] == "failed_safe"
    assert response.json()["published_text"] == ""
    assert response.json()["model_called"] is True


def test_gateway_exception_is_fail_safe_without_echoing_details(app_services):
    gateway = ConversationGateway()
    gateway.raises = True
    client = _client(app_services, gateway)
    conversation_id = _approved_session(client)

    response = client.post(
        f"/api/conversations/{conversation_id}/generate",
        json={"tenant_id": "TENANT-A", "content": "请概述成人高血压用药时需要注意的安全信息。"},
        headers={"x-demo-role": "field_rep"},
    )

    assert response.status_code == 503
    assert response.json()["state"] == "failed_safe"
    assert response.json()["published_text"] == ""
    assert "provider detail" not in response.text
