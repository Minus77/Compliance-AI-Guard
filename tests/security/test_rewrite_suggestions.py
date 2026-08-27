"""F3: a block must offer a way forward, and the way forward must itself be clean.

Telling someone "you cannot send this" without showing what would work leaves one
option: write less. So a blocked result carries a rewrite suggestion.

The load-bearing rule is that the suggestion is re-checked before it is shown. A
suggestion is generated text, and generated text is exactly as capable of tripping
a redline as the original. Showing an unchecked suggestion would mean the tool
proposing the violation it just blocked -- so anything that fails the second pass
is withheld rather than displayed.
"""

from __future__ import annotations

from compliance_guard.agents.rewrite import RewriteService, suggest_rewrite


def _service() -> RewriteService:
    return RewriteService()


def test_bribery_block_gets_guidance_not_a_redraft():
    """Rewriting this would mean changing what happened, which is worse.

    Narrowed after a live check: any mechanical rewrite of an inducement sentence
    has to restate the events, and a compliance tool must not draft a more
    compliant-looking version of something that did not occur.
    """
    result = _service().suggest("赠送礼品给医生以表示感谢。", finding_types=["bribery_or_inducement"])
    assert result.available is False
    assert result.guidance
    assert result.withheld_reason


def test_suggestion_is_itself_clean():
    """The whole point: the proposed text must pass the same rules."""
    result = _service().suggest("本品比竞品更安全。", finding_types=["comparative_claim"])
    assert result.verified is True
    recheck = _service().suggest(result.suggestion, finding_types=["comparative_claim"])
    assert recheck.residual_findings == []


def test_suggestion_that_would_still_trip_a_rule_is_withheld():
    """A rewrite is only useful if it clears the rule; otherwise say nothing."""
    result = _service().suggest(
        "本品比竞品更安全。",
        finding_types=["comparative_claim"],
        candidate="本品仍然比竞品更安全一些。",
    )
    assert result.available is False
    assert result.suggestion == ""
    assert result.residual_findings
    assert result.withheld_reason


def test_comparative_claim_suggestion_drops_the_comparison():
    result = _service().suggest("本品比竞品更安全。", finding_types=["comparative_claim"])
    assert result.available is True
    for banned in ("比竞品", "更安全"):
        assert banned not in result.suggestion


def test_off_label_gets_guidance_rather_than_an_invented_claim():
    """Rewriting this needs the approved indication, which is a label lookup.

    A mechanical substitution here would produce a confident-sounding clinical
    claim the service has no basis for, so it offers guidance and routes the case
    to medical review instead.
    """
    result = _service().suggest("本品对糖尿病也很有效。", finding_types=["off_label"])
    assert result.available is False
    assert result.guidance
    assert "说明书" in result.guidance


def test_no_suggestion_for_a_clean_narrative():
    result = _service().suggest("本品适用于成人原发性高血压的治疗。", finding_types=[])
    assert result.available is False


def test_adverse_event_is_never_rewritten_away():
    """Safety content must be reported, not edited to look acceptable."""
    result = _service().suggest("患者服药后出现皮疹。", finding_types=["potential_adverse_event"])
    assert result.available is False
    assert "上报" in result.guidance or "报告" in result.guidance


def test_pii_needs_no_rewrite_because_masking_handles_it():
    result = _service().suggest("患者李四电话13800138000。", finding_types=["pii"])
    assert result.available is False


def test_suggestion_never_contains_an_identifier():
    result = _service().suggest(
        "章医生认为本品比竞品更安全。", finding_types=["comparative_claim"]
    )
    if result.available:
        assert "章" not in result.suggestion


def test_module_level_helper_matches_the_service():
    direct = suggest_rewrite("本品比竞品更安全。", finding_types=["comparative_claim"])
    assert direct.available is True


def test_result_states_which_rules_it_addressed():
    result = _service().suggest("本品比竞品更安全。", finding_types=["comparative_claim"])
    assert "comparative_claim" in result.addressed


def test_verification_is_recorded_even_when_it_passes():
    result = _service().suggest("本品比竞品更安全。", finding_types=["comparative_claim"])
    assert result.verified is True
    assert result.checked_against
