from compliance_guard.policy.spans import find_spans
from compliance_guard.security.pii_gateway import PiiGateway, SanitizeContext


def test_repeated_unicode_phrase_returns_every_exact_span():
    text = "风险😀风险"
    spans = find_spans(text, ["风险"])

    assert [(span.start, span.end) for span in spans] == [(0, 2), (3, 5)]


def test_sanitized_rule_hit_maps_back_to_the_original_text():
    gateway = PiiGateway()
    result = gateway.sanitize(
        "患者李四出现皮疹，电话13800138000。",
        SanitizeContext(tenant_id="T1"),
    )
    safe_start = result.model_text.index("皮疹")
    original = result.offset_map.to_original(safe_start, safe_start + 2)

    assert original is not None
    assert result.offset_map.original[original.start : original.end] == "皮疹"


def test_token_range_cannot_be_mapped_to_raw_text():
    result = PiiGateway().sanitize(
        "患者李四出现皮疹",
        SanitizeContext(tenant_id="T1"),
    )
    token_start = result.model_text.index("[")
    token_end = result.model_text.index("]") + 1

    assert result.offset_map.to_original(token_start, token_end) is None


def test_offset_map_round_trips_unicode_text():
    original = "风险😀风险，患者李四出现皮疹"
    result = PiiGateway().sanitize(original, SanitizeContext(tenant_id="T1"))

    assert result.offset_map.original == original
    assert result.offset_map.masked == result.model_text
