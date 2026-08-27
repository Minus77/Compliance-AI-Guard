"""A suggestion must be readable, not merely rule-clean.

Found by running the real server. For "赠送礼品给医生以表示感谢。" the service
proposed:

    医生以表示感谢。

It passed the second deterministic check — no rule matched — and was shown. But it
is not a sentence. Phrase substitution turned "赠送礼品给" into "向", and then the
name-stripping pass removed the 向 because 向 is a genuine Chinese surname, leaving
a fragment.

"Clean" was the wrong bar. A representative who is shown one nonsense suggestion
stops reading all of them, and then the block has no way forward again — which is
the exact failure the rewrite feature exists to prevent. So a suggestion must also
be well-formed, and anything that is not is withheld with guidance instead.
"""

from __future__ import annotations

from compliance_guard.agents.rewrite import RewriteService

# Sentence-ending punctuation a complete Chinese sentence may end with.
_TERMINALS = "。！？.!?"


def _service() -> RewriteService:
    return RewriteService()


def test_inducement_is_never_redrafted_into_a_cleaner_story():
    """The deeper fix: this must not be rewritten at all.

    Repairing the fragment would have required turning "赠送礼品给医生" into
    something like "向医生提供了产品资料" — changing what *happened*. Falsifying a
    call report is a graver offence than the wording it would be fixing, so the
    service refuses and explains instead.
    """
    result = _service().suggest(
        "赠送礼品给医生以表示感谢。", finding_types=["bribery_or_inducement"]
    )
    assert result.available is False
    assert result.suggestion == ""
    assert result.guidance
    assert "改变事实" in result.guidance


def test_the_live_defect_fragment_is_never_produced():
    result = _service().suggest(
        "赠送礼品给医生以表示感谢。", finding_types=["bribery_or_inducement"]
    )
    assert result.suggestion != "医生以表示感谢。"
    assert result.suggestion == ""


def test_suggestion_does_not_begin_with_a_dangling_particle():
    for text in (
        "本品比竞品更安全。",
        "本品疗效更好，起效更快。",
        "同类药中本品效果最好。",
    ):
        result = _service().suggest(text, finding_types=["comparative_claim"])
        if result.available:
            assert result.suggestion[0] not in "的了和与以及，。"


def test_suggestion_is_not_degenerate_in_length():
    """A two-character stub is not a usable replacement for a sentence."""
    result = _service().suggest("本品比竞品更安全。", finding_types=["comparative_claim"])
    assert result.available is True
    assert len(result.suggestion) >= 8


def test_suggestion_never_echoes_a_person_name():
    result = _service().suggest(
        "章医生认为本品比竞品更安全。", finding_types=["comparative_claim"]
    )
    if result.available:
        assert "章" not in result.suggestion


def test_a_shown_suggestion_is_always_readable_and_verified():
    """The two conditions for display, together: readable *and* rule-clean."""
    result = _service().suggest("本品比竞品更安全。", finding_types=["comparative_claim"])
    assert result.available is True
    assert result.verified is True
    assert result.suggestion.endswith(tuple(_TERMINALS))
    assert result.suggestion[0] not in "的了和与及以，。、"


def test_comparative_suggestion_is_still_readable():
    result = _service().suggest("本品比竞品更安全。", finding_types=["comparative_claim"])
    assert result.available is True
    assert result.suggestion.endswith(tuple(_TERMINALS))
    assert len(result.suggestion) >= 8


def test_unreadable_candidate_is_withheld_with_guidance():
    """Supplied text that cannot be shown must still leave the author a next step."""
    result = _service().suggest(
        "本品比竞品更安全。",
        finding_types=["comparative_claim"],
        candidate="以。",
    )
    assert result.available is False
    assert result.guidance
    assert result.withheld_reason


def test_withheld_suggestion_still_explains_what_to_do():
    result = _service().suggest(
        "本品比竞品更安全。", finding_types=["comparative_claim"], candidate="本品比竞品更安全一些。"
    )
    assert result.available is False
    assert result.guidance


def test_verified_flag_only_true_when_shown():
    result = _service().suggest(
        "本品比竞品更安全。", finding_types=["comparative_claim"], candidate="以。"
    )
    assert result.verified is False
