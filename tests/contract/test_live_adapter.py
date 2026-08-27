"""Contract tests for the live HTTP model adapter.

These tests are hermetic: the transport is injected, so no network socket is
opened and no API key is required. They pin the behaviour that matters for
compliance rather than the provider's wire format:

* a live result is a *candidate* and never carries a decision,
* every provider failure mode becomes a fail-safe ``error_category``,
* a truncated or fenced response is handled explicitly,
* credentials never leak into results, and
* the adapter refuses to invent an endpoint it was not configured for.

The single live end-to-end call is opt-in via ``RUN_LIVE_LLM_TESTS=1`` so the
default suite stays offline and deterministic.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from compliance_guard.llm.credentials import (
    CredentialError,
    resolve_endpoint,
    secrets_path,
)
from compliance_guard.llm.live_adapter import LiveHttpAdapter, resolve_proxy
from compliance_guard.llm.types import ModelConstraints, ModelRequest

CONSTRAINTS = ModelConstraints(
    mode="live",
    profile_id="deepseek-routine",
    model_id="DeepSeek V4 Flash",
    route_version="routes-v1",
)


def _envelope(content: str, finish_reason: str = "stop") -> dict:
    return {
        "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7},
    }


def _responder(payload: dict, status: int = 200):
    captured: dict = {}

    def post(url, headers=None, json=None, timeout=None):  # noqa: A002 - mirrors httpx
        captured["url"] = url
        captured["headers"] = headers or {}
        captured["json"] = json or {}
        captured["timeout"] = timeout
        return httpx.Response(status_code=status, json=payload)

    return post, captured


def _adapter(post) -> LiveHttpAdapter:
    return LiveHttpAdapter(post=post)


def _request() -> ModelRequest:
    return ModelRequest(
        scenario="ae",
        task_type="routine_compliance",
        content="患者服药后出现皮疹。",
        evidence_ids=["EV-CN-2026-001"],
        structured_payload={"dose": "80mg"},
    )


# -- happy path --------------------------------------------------------------


def test_live_result_parses_candidate_json():
    body = {"summary": "疑似不良事件", "findings": [{"type": "potential_adverse_event", "confidence": 0.9}]}
    post, _ = _responder(_envelope(json.dumps(body, ensure_ascii=False)))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category is None
    assert result.provider == "live"
    assert result.raw_json["findings"][0]["type"] == "potential_adverse_event"
    # Provenance must survive so the audit trail can name what answered.
    assert result.profile_id == "deepseek-routine"
    assert result.model_id == "DeepSeek V4 Flash"
    assert result.route_version == "routes-v1"
    assert result.input_tokens == 11
    assert result.output_tokens == 7


def test_markdown_fenced_json_is_accepted():
    """Providers wrap JSON in a fence even when told not to; that is not a failure."""
    post, _ = _responder(_envelope('```json\n{"summary": "ok", "findings": []}\n```'))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category is None
    assert result.raw_json == {"summary": "ok", "findings": []}


# -- output framing tolerance ------------------------------------------------
#
# Real models are inconsistent about framing even at temperature 0. Observed on
# this provider: claude-haiku returns a bare fenced object, while claude-sonnet
# sometimes prepends a sentence of prose. Rejecting either would send a good
# check to human review for a cosmetic reason, so framing is tolerated while
# genuinely malformed output still fails safe.


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("bare object", '{"summary": "ok", "findings": []}'),
        ("fenced", '```json\n{"summary": "ok", "findings": []}\n```'),
        ("fence without language", '```\n{"summary": "ok", "findings": []}\n```'),
        ("prose then object", '好的，分析如下：\n\n{"summary": "ok", "findings": []}'),
        ("prose then fence", 'Result:\n```json\n{"summary": "ok", "findings": []}\n```\nDone.'),
    ],
)
def test_tolerated_output_framing_is_parsed(label, text):
    post, _ = _responder(_envelope(text))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category is None, label
    assert result.raw_json["summary"] == "ok", label


def test_braces_inside_a_string_value_do_not_truncate_the_object():
    """A representative's own words may contain braces; that must not corrupt parsing."""
    post, _ = _responder(_envelope('{"summary": "含{花括号}的原话", "findings": []}'))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category is None
    assert result.raw_json["summary"] == "含{花括号}的原话"
    assert result.raw_json["findings"] == []


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("prose only", "I cannot help with that."),
        ("truncated object", '{"summary": "partial", "findings": ['),
        ("top-level array", '[{"type": "potential_adverse_event"}]'),
        ("prose then array", 'Result:\n[{"type": "potential_adverse_event"}]'),
        ("scalar", '"approved"'),
    ],
)
def test_malformed_output_still_fails_safe(label, text):
    """Framing tolerance must not become "guess what the model meant"."""
    post, _ = _responder(_envelope(text))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == "schema", label
    assert result.raw_json == {}, label


def test_array_element_is_never_promoted_to_the_result():
    """A JSON array must not be mined for its first object.

    Promoting an element would fabricate a finding set the model never asserted
    as its answer, which is worse than refusing: it would look like a real result.
    """
    post, _ = _responder(_envelope('[{"summary": "wrong", "findings": []}]'))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == "schema"
    assert "summary" not in result.raw_json


# -- the model never decides -------------------------------------------------


def test_live_adapter_never_returns_a_decision_field_it_invented():
    """Reserved keys may come back, but the adapter must not honour them.

    The adapter passes raw JSON through; the downstream extractor and policy
    engine drop reserved keys. This test pins that the adapter itself adds no
    decision of its own, so a provider outage can never look like an approval.
    """
    post, _ = _responder(_envelope('{"summary": "x", "findings": []}'))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert "decision" not in result.raw_json
    assert "severity" not in result.raw_json
    assert result.error_category is None


def test_system_prompt_forbids_server_controlled_keys():
    post, captured = _responder(_envelope('{"summary": "x", "findings": []}'))
    _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    system = captured["json"]["messages"][0]["content"]
    for reserved in ("decision", "severity", "approval_status", "routing", "tool_permissions"):
        assert reserved in system
    assert captured["json"]["temperature"] == 0


def test_untrusted_content_is_sent_as_labelled_data():
    """Case text must travel as a data field, not as an instruction."""
    post, captured = _responder(_envelope('{"summary": "x", "findings": []}'))
    _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    user = json.loads(captured["json"]["messages"][1]["content"])
    assert user["CONTENT"] == "患者服药后出现皮疹。"
    assert "untrusted" in user["instruction"].casefold()
    assert user["EVIDENCE_IDS"] == ["EV-CN-2026-001"]


# -- refusal and evidence grounding ------------------------------------------


def test_explicit_refusal_fails_safe():
    """A refusal is a failure, not an empty finding list.

    Regression for a live-model defect: the model answered
    ``{"refused": true, "reason": "..."}`` and the adapter passed it through with
    no error category. Downstream that was indistinguishable from "assessed, found
    nothing", so a case the model declined to judge could read as low risk.
    """
    post, _ = _responder(_envelope('{"refused": true, "reason": "insufficient reference data"}'))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == "refused"
    assert result.raw_json == {}


def test_evidence_excerpts_are_sent_to_the_model():
    """The model must receive evidence text, not just identifiers.

    Regression for a live-model defect: sending only ``EVIDENCE_IDS`` asked the
    model to reason from facts it could not see, and it correctly refused the whole
    task -- which silently produced cases with no off-label detection at all.
    """
    post, captured = _responder(_envelope('{"summary": "ok", "findings": []}'))
    request = ModelRequest(
        scenario="off_label",
        task_type="routine_compliance",
        content="本品可用于糖尿病的治疗。",
        evidence_ids=["EV-CN-2026-001"],
        evidence_excerpts=[
            {
                "evidence_id": "EV-CN-2026-001",
                "version": "CN-PI-2026-01",
                "source_type": "label",
                "stance": "supports",
                "excerpt": "本品适用于成人原发性高血压的治疗。",
            }
        ],
    )

    _adapter(post).complete("routine_compliance", request, CONSTRAINTS)

    user = json.loads(captured["json"]["messages"][1]["content"])
    assert user["EVIDENCE"][0]["evidence_id"] == "EV-CN-2026-001"
    assert "成人原发性高血压" in user["EVIDENCE"][0]["excerpt"]
    # Stance must survive: supporting and contradicting evidence must not look alike.
    assert user["EVIDENCE"][0]["stance"] == "supports"


def test_prompt_tells_the_model_not_to_refuse_when_evidence_is_empty():
    """An empty pack is a normal case, not a reason to abandon the assessment."""
    post, captured = _responder(_envelope('{"summary": "ok", "findings": []}'))
    _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    system = captured["json"]["messages"][0]["content"]
    assert "do not refuse" in system.casefold()


# -- fail safe, never fail open ---------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, "credential_rejected"),
        (403, "credential_rejected"),
        (429, "provider_rate_limited"),
        (400, "provider_rejected"),
        (500, "provider_unavailable"),
        (503, "provider_unavailable"),
    ],
)
def test_http_error_status_fails_safe(status, expected):
    post, _ = _responder({"error": "nope"}, status=status)

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == expected
    assert result.raw_json == {}


def test_timeout_fails_safe():
    def post(url, headers=None, json=None, timeout=None):  # noqa: A002
        raise httpx.ReadTimeout("too slow")

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == "provider_timeout"
    assert result.raw_json == {}


def test_transport_failure_fails_safe_without_echoing_the_request():
    def post(url, headers=None, json=None, timeout=None):  # noqa: A002
        raise httpx.ConnectError("患者服药后出现皮疹。")

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == "provider_unreachable"
    # Clinical narrative must never ride out on an error object.
    assert "皮疹" not in json.dumps(result.model_dump(mode="json"), ensure_ascii=False)


def test_truncated_response_fails_safe():
    """Half a findings list looks like a clean bill of health; refuse it."""
    post, _ = _responder(_envelope('{"summary": "partial", "findings": [', finish_reason="length"))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == "truncated"


def test_non_json_model_output_fails_safe():
    post, _ = _responder(_envelope("I cannot help with that."))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == "schema"


def test_empty_message_fails_safe():
    post, _ = _responder(_envelope("   "))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == "empty"


def test_json_array_output_fails_safe():
    post, _ = _responder(_envelope('[{"type": "ae"}]'))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == "schema"


def test_envelope_without_choices_fails_safe():
    post, _ = _responder({"usage": {}})

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert result.error_category == "schema"


def test_missing_profile_id_fails_safe():
    post, _ = _responder(_envelope('{"summary": "x"}'))
    constraints = ModelConstraints(mode="live", profile_id=None)

    result = _adapter(post).complete("routine_compliance", _request(), constraints)

    assert result.error_category == "credential_missing"


# -- secrets never leak ------------------------------------------------------


def test_api_key_is_sent_only_as_a_header_and_never_returned():
    post, captured = _responder(_envelope('{"summary": "x", "findings": []}'))

    result = _adapter(post).complete("routine_compliance", _request(), CONSTRAINTS)

    assert captured["headers"]["Authorization"].startswith("Bearer ")
    serialized = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
    assert "Bearer" not in serialized
    assert "sk-" not in serialized


def test_endpoint_reference_cannot_escape_the_endpoints_directory():
    with pytest.raises(CredentialError):
        resolve_endpoint(endpoint_ref="../../etc/passwd", timeout_ms=1000, token_budget=256)


def test_unknown_endpoint_reference_raises_rather_than_guessing():
    with pytest.raises(CredentialError):
        resolve_endpoint(endpoint_ref="no-such-profile", timeout_ms=1000, token_budget=256)


def test_endpoint_mapping_files_contain_no_plaintext_secrets():
    from compliance_guard.runtime_paths import config_dir

    for path in (config_dir() / "endpoints").glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        keys = {str(key).casefold() for key in payload}
        assert not keys & {"api_key", "apikey", "secret", "secret_key", "password", "access_token"}


def test_local_secrets_file_is_git_ignored():
    """The key must never be committable."""
    from compliance_guard.runtime_paths import resource_root

    ignore = (resource_root() / ".gitignore").read_text(encoding="utf-8")
    assert "config/secrets/" in ignore
    assert secrets_path().name == "llm.local.json"


# -- proxy resolution --------------------------------------------------------


def test_socks_proxy_is_ignored_when_socksio_is_absent(monkeypatch):
    """An inherited SOCKS proxy must not break compliance checks."""
    monkeypatch.delenv("COMPLIANCE_GUARD_LLM_PROXY", raising=False)
    for name in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:7897")
    monkeypatch.setattr("compliance_guard.llm.live_adapter._socks_supported", lambda: False)

    assert resolve_proxy() is None


def test_http_proxy_is_preferred_over_socks(monkeypatch):
    monkeypatch.delenv("COMPLIANCE_GUARD_LLM_PROXY", raising=False)
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:7897")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:7897")

    assert resolve_proxy() == "http://127.0.0.1:7897"


# -- opt-in live smoke test --------------------------------------------------


@pytest.mark.skipif(
    os.getenv("RUN_LIVE_LLM_TESTS") != "1",
    reason="set RUN_LIVE_LLM_TESTS=1 to exercise the real provider",
)
def test_live_provider_returns_parseable_candidate():
    result = LiveHttpAdapter(prompts_dir=None).complete(
        "routine_compliance", _request(), CONSTRAINTS
    )

    assert result.error_category is None, result.error_category
    assert isinstance(result.raw_json, dict) and result.raw_json
    assert result.latency_ms > 0
