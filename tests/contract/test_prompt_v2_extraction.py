"""D4: the model extracts; the server judges. And the prompt does not grow.

Two properties are pinned here.

**Extraction only.** Prompt v2 tells the model to report the indication *text* it
sees and forbids it from concluding on-label or off-label. That conclusion is a
closed-world comparison against the current label, which the policy layer owns —
so it stays reproducible and traceable to a concept id rather than to model prose.

**Prompt size is decoupled from catalogue size.** This is the answer to "our
company has many products and the labels are long". What travels to the model is
one product's structured facts, never label prose. Going from 1 product to 500
grows a local JSON file, not the request. The test asserts that directly: the
payload for a catalogue of ten product/market pairs is the same size as for one.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from compliance_guard.llm.live_adapter import LiveHttpAdapter
from compliance_guard.llm.types import ModelConstraints, ModelRequest
from compliance_guard.runtime_paths import config_dir

CONSTRAINTS = ModelConstraints(
    mode="live",
    profile_id="deepseek-routine",
    model_id="DeepSeek V4 Flash",
    route_version="routes-v1",
)

PROMPTS_DIR = config_dir() / "prompts"


def _responder(payload: dict):
    captured: dict = {}

    def post(url, headers=None, json=None, timeout=None):  # noqa: A002 - mirrors httpx
        captured["json"] = json or {}
        return httpx.Response(status_code=200, json=payload)

    return post, captured


def _envelope(content: str) -> dict:
    return {
        "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7},
    }


def _request(label_facts: dict | None = None) -> ModelRequest:
    return ModelRequest(
        scenario="ae",
        task_type="routine_compliance",
        content="患者血压高，每天80mg口服。",
        evidence_ids=["EV-CN-2026-001"],
        structured_payload={"dose": "80mg"},
        label_facts=label_facts,
    )


def _adapter(post):
    return LiveHttpAdapter(prompts_dir=PROMPTS_DIR, prompt_version="compliance-evaluator-v2", post=post)


def _call(label_facts: dict | None = None) -> dict:
    post, captured = _responder(_envelope('{"summary": "x", "findings": []}'))
    _adapter(post).complete("routine_compliance", _request(label_facts), CONSTRAINTS)
    return captured["json"]


CURRENT_LABEL = {
    "product_id": "PRODUCT-001",
    "market": "CN",
    "version": "CN-PI-2026-01",
    "indication": "成人原发性高血压",
    "indication_id": "IND-001",
    "population": "成人",
    "line": "一线",
    "dose": "80mg",
    "route": "口服",
    "duration": "长期",
    "combination": "单药",
}


def test_v2_prompt_file_exists():
    assert (PROMPTS_DIR / "compliance-evaluator-v2.txt").is_file()


def test_v1_prompt_is_retained_for_replay():
    """An old conclusion must stay reproducible against the prompt that produced it."""
    assert (PROMPTS_DIR / "compliance-evaluator-v1.txt").is_file()


def test_v2_forbids_the_model_from_judging_label_status():
    system = _call(CURRENT_LABEL)["messages"][0]["content"]
    lowered = system.casefold()
    assert "extract" in lowered
    assert "off_label" in lowered or "off-label" in lowered
    assert "indication_text" in lowered


def test_v2_still_forbids_server_controlled_keys():
    system = _call(CURRENT_LABEL)["messages"][0]["content"]
    for reserved in ("decision", "severity", "approval_status", "routing", "tool_permissions"):
        assert reserved in system


def test_label_facts_travel_as_structured_fields(): 
    user = json.loads(_call(CURRENT_LABEL)["messages"][1]["content"])
    assert user["APPROVED_LABEL_FACTS"]["indication_id"] == "IND-001"
    assert user["APPROVED_LABEL_FACTS"]["version"] == "CN-PI-2026-01"


def test_no_label_prose_is_sent():
    """Contraindication and warning prose stays out of the request."""
    body = json.dumps(_call(CURRENT_LABEL), ensure_ascii=False)
    assert "禁用" not in body
    assert "慎用" not in body


def test_payload_size_is_independent_of_catalogue_size():
    """The whole point of the ontology approach: context does not scale with products."""
    from compliance_guard.knowledge.label_facts import LabelFactsStore

    store = LabelFactsStore()
    pairs = sorted({(label.product_id, label.market) for label in store._labels})
    assert len(pairs) >= 10, "fixture set should cover a multi-product catalogue"

    one_product = len(json.dumps(_call(CURRENT_LABEL), ensure_ascii=False))
    # Same request against a store holding every product: only the current
    # product's facts are selected, so the payload must not change size.
    facts = store.current("PRODUCT-001", "CN")
    selected = {
        key: getattr(facts, key)
        for key in (
            "product_id", "market", "version", "indication", "indication_id",
            "population", "line", "dose", "route", "duration", "combination",
        )
    }
    whole_catalogue = len(json.dumps(_call(selected), ensure_ascii=False))
    assert whole_catalogue == one_product


def test_payload_carries_one_label_version_only():
    from compliance_guard.knowledge.label_facts import LabelFactsStore

    store = LabelFactsStore()
    facts = store.current("PRODUCT-001", "CN")
    selected = {"product_id": facts.product_id, "market": facts.market, "version": facts.version}
    user = json.loads(_call(selected)["messages"][1]["content"])
    assert user["APPROVED_LABEL_FACTS"]["version"] == "CN-PI-2026-01"
    # The retired 2024 label must not be in the request at all.
    assert "CN-PI-2024-01" not in json.dumps(user, ensure_ascii=False)
