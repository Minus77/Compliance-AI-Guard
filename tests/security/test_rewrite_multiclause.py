"""A multi-clause sentence must not be left with a dangling particle mid-string.

Found on the final live pass. "本品比竞品更安全，疗效更好。" produced:

    本品的安全性信息见说明书，的疗效数据见说明书。

Each substitution is fine on its own: the replacement phrases begin with 的 so they
attach to a subject ("本品的疗效数据见说明书"). But the second clause has no subject
of its own, so after the comma the 的 dangles.

The readability guard missed it because it only inspected the *first* character of
the suggestion. Same defect class as the earlier fragment, one level deeper: the
check has to hold at every clause boundary, not just at the start.

Conservative on purpose. Reconstructing the missing subject would mean guessing at
what the author meant, and withholding a usable suggestion costs one guidance
message while showing a broken one costs the reader's trust in every suggestion
after it.
"""

from __future__ import annotations

import re

from compliance_guard.agents.rewrite import RewriteService

# Any clause opening with a particle is malformed, wherever the clause starts.
_DANGLING_AFTER_PUNCTUATION = re.compile(r"[，,、；;。.!?！？]\s*[的了和与及以]")


def _service() -> RewriteService:
    return RewriteService()


def test_the_live_defect_string_is_never_produced():
    result = _service().suggest("本品比竞品更安全，疗效更好。", finding_types=["comparative_claim"])
    assert result.suggestion != "本品的安全性信息见说明书，的疗效数据见说明书。"


def test_no_clause_begins_with_a_dangling_particle():
    for text in (
        "本品比竞品更安全，疗效更好。",
        "本品起效更快，效果最好。",
        "本品比竞品更有效，且更安全。",
        "同类药中本品效果最好，起效更快。",
    ):
        result = _service().suggest(text, finding_types=["comparative_claim"])
        if result.available:
            assert not _DANGLING_AFTER_PUNCTUATION.search(result.suggestion), (
                f"dangling particle after punctuation in {result.suggestion!r}"
            )


def test_a_withheld_multiclause_suggestion_still_carries_guidance():
    result = _service().suggest("本品比竞品更安全，疗效更好。", finding_types=["comparative_claim"])
    if not result.available:
        assert result.guidance
        assert result.withheld_reason


def test_single_clause_suggestions_still_work():
    """The stricter guard must not withhold the cases that were already fine."""
    result = _service().suggest("本品比竞品更安全。", finding_types=["comparative_claim"])
    assert result.available is True
    assert result.suggestion == "本品的安全性信息见说明书。"


def test_shown_suggestion_is_still_rule_clean():
    result = _service().suggest("本品疗效更好。", finding_types=["comparative_claim"])
    assert result.available is True
    assert result.verified is True
    assert result.residual_findings == []


def test_no_suggestion_contains_a_doubled_particle():
    for text in ("本品比竞品更安全，疗效更好。", "本品比竞品更有效。"):
        result = _service().suggest(text, finding_types=["comparative_claim"])
        if result.available:
            assert "的的" not in result.suggestion
            assert "，的" not in result.suggestion
