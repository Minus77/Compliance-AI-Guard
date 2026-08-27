"""A finding that must not be rewritten wins over one that may be.

Found on the last probe. Passing both `comparative_claim` (rewritable) and
`bribery_or_inducement` (guidance-only) rewrote the inducement sentence anyway:

    赠送礼品给医生以表示感谢。  ->  医生以表示感谢。

The cause is precedence. `bribery_or_inducement` sits in neither the rewritable set
nor the "never rewrite" map, so when a rewritable type appeared alongside it the
service proceeded as though only the rewritable one existed — and substituted
against text it had already been decided must not be redrafted.

Real cases arrive with several findings at once, so this is the normal shape of the
input, not a corner. The rule has to be precedence, not presence: if *any* finding
must not be rewritten, the whole suggestion is withheld. A sentence is rewritten as
a whole, so a suggestion "addressing" one finding necessarily rewrites the text the
other one flagged.
"""

from __future__ import annotations

from compliance_guard.agents.rewrite import RewriteService


def _service() -> RewriteService:
    return RewriteService()


def test_inducement_beside_a_comparison_is_not_rewritten():
    result = _service().suggest(
        "赠送礼品给医生以表示感谢。",
        finding_types=["comparative_claim", "bribery_or_inducement"],
    )
    assert result.available is False
    assert result.suggestion == ""


def test_the_probe_fragment_is_never_produced():
    result = _service().suggest(
        "赠送礼品给医生以表示感谢。",
        finding_types=["comparative_claim", "bribery_or_inducement"],
    )
    assert result.suggestion != "医生以表示感谢。"


def test_order_of_finding_types_does_not_matter():
    forward = _service().suggest(
        "赠送礼品给医生。", finding_types=["bribery_or_inducement", "comparative_claim"]
    )
    reverse = _service().suggest(
        "赠送礼品给医生。", finding_types=["comparative_claim", "bribery_or_inducement"]
    )
    assert forward.available is reverse.available is False


def test_withheld_mixed_case_still_explains_both_concerns():
    result = _service().suggest(
        "赠送礼品给医生以表示感谢，本品比竞品更安全。",
        finding_types=["comparative_claim", "bribery_or_inducement"],
    )
    assert result.available is False
    assert result.guidance
    # The author needs to know about both problems, not just the blocking one.
    assert "改变事实" in result.guidance
    assert "说明书" in result.guidance


def test_off_label_beside_a_comparison_is_also_withheld():
    result = _service().suggest(
        "本品对糖尿病也很有效，而且比竞品更安全。",
        finding_types=["comparative_claim", "off_label"],
    )
    assert result.available is False
    assert result.guidance


def test_safety_content_beside_a_comparison_is_never_rewritten():
    """Softening an adverse event is the one thing this must never help with."""
    result = _service().suggest(
        "患者服药后出现皮疹，但本品比竞品更安全。",
        finding_types=["comparative_claim", "potential_adverse_event"],
    )
    assert result.available is False


def test_a_comparison_on_its_own_is_still_rewritten():
    """Precedence must not disable the one case that works."""
    result = _service().suggest("本品比竞品更安全。", finding_types=["comparative_claim"])
    assert result.available is True
    assert result.suggestion == "本品的安全性信息见说明书。"


def test_advisory_findings_do_not_block_a_rewrite():
    """`missing_evidence` and `missing_context` accompany almost every case."""
    result = _service().suggest(
        "本品比竞品更安全。",
        finding_types=["comparative_claim", "missing_evidence", "missing_context"],
    )
    assert result.available is True
    assert result.suggestion


def test_blocking_reason_is_recorded_for_the_audit_trail():
    result = _service().suggest(
        "赠送礼品给医生。", finding_types=["comparative_claim", "bribery_or_inducement"]
    )
    assert result.withheld_reason
    assert "bribery_or_inducement" in result.audit_payload()["addressed"]
