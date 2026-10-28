"""Compliant rewrite suggestions, gated by a second deterministic check.

Telling someone "this cannot go out" without showing what would work leaves them
one option: write less. That is the outcome this product exists to prevent, so a
blocked result carries a suggestion.

The load-bearing rule is the second pass. A suggestion is generated text, and
generated text is exactly as capable of tripping a redline as the original was. A
tool that displayed an unchecked suggestion would end up proposing the violation
it had just blocked. So every candidate is re-run through the same deterministic
rules, and anything that fails is withheld rather than shown.

Two categories are deliberately *not* rewritten:

**Safety content.** An adverse event must be reported, not reworded until it looks
acceptable. Offering to soften it would be coaching someone through a
pharmacovigilance failure.

**Personal data.** Masking already handles it, upstream and automatically. Asking
the author to edit names out would be duplicated work that also invites them to
leave the clinical detail out with it.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import Field

from compliance_guard.domain.models import DomainModel
from compliance_guard.policy.bundles import PolicyBundleStore, parse_bundle_rules
from compliance_guard.security.name_lexicon import find_mentions

# Rules a rewrite can legitimately clear.
#
# Only one qualifies, and the reason matters more than the list. A safe rewrite
# must remove an unsupported *assertion* without changing what happened. Dropping
# "safer than the competitor" does exactly that: the claim goes, the events stay.
#
# Everything else was removed after a live check produced "医生以表示感谢。" for an
# inducement sentence. Fixing that fragment would have exposed the deeper problem:
# any mechanical rewrite of "赠送礼品给医生" has to change the *facts* -- turning a
# gift into "provided product materials" is falsifying source content, which is a
# graver offence than the wording it was trying to fix. A compliance tool must
# never draft a more compliant-looking version of events that did not happen.
#
# `off_label` and `unapproved_promotion` are excluded for a related reason:
# correcting them needs the approved indication, so a substitution would invent a
# confident clinical claim the service has no basis for.
#
# Those findings still get guidance and a human route. They do not get prose.
_REWRITABLE = frozenset({"comparative_claim"})

# A suggestion has to be readable, not merely rule-clean. The live defect passed
# the deterministic re-check and was still unusable, and a representative shown one
# nonsense suggestion stops reading all of them -- which returns the block to
# having no way forward, the exact failure the feature exists to prevent.
_MIN_SUGGESTION_CHARS = 8
_SENTENCE_TERMINALS = "。！？.!?"
_DANGLING_LEADS = "的了和与及以，。、"

# A clause opening with a particle is malformed wherever that clause starts, not
# only at character zero. Two substitutions in one sentence produced
# "本品的安全性信息见说明书，的疗效数据见说明书。": each replacement is fine alone,
# but the second clause has no subject of its own, so its 的 dangles after the
# comma. Checking only the first character missed it entirely.
_CLAUSE_BREAK = "，,、；;。.!?！？"
_DANGLING_AFTER_BREAK = re.compile(
    rf"[{re.escape(_CLAUSE_BREAK)}]\s*[{re.escape('的了和与及以')}]"
)

# Rules where a rewrite would be the wrong advice, with the reason a user sees.
_NOT_REWRITABLE = {
    "potential_adverse_event": (
        "这属于需要上报的安全信息，不能改写掉。请如实保留描述，系统已转药物警戒同事处理。"
    ),
    "serious_adverse_event": (
        "这属于严重不良事件，必须如实上报，不能改写。系统已按最高优先级转药物警戒。"
    ),
    "pii": "个人信息已由系统自动替换为代号，你不需要手动改写或删除。",
    "phi": "健康相关个人信息已由系统自动脱敏，无需手动改写。",
    "severe_pii_leak": "涉及大量身份信息，请确认是否确实需要记录，而不是改写措辞。",
    "prompt_injection": "如果这是客户原话，请照实记录并说明背景，不要改写。",
}

# Phrase-level substitutions. Deliberately conservative: each one removes a
# specific banned construction rather than paraphrasing the sentence, because a
# paraphrase of a clinical statement can change its meaning.
_SUBSTITUTIONS: tuple[tuple[str, str], ...] = (
    # inducement -> factual record of a compliant interaction
    ("赠送礼品给", "向"),
    ("赠送礼品", "提供了产品资料"),
    ("送礼品", "提供产品资料"),
    ("礼品", "产品资料"),
    ("宴请", "会面"),
    ("请客", "会面"),
    ("回扣", "合规费用说明"),
    ("红包", "合规费用说明"),
    ("好处费", "合规费用说明"),
    ("返点", "合规价格政策"),
    ("贿赂", "合规沟通"),
    ("违规激励", "合规激励政策"),
    # comparison -> label-anchored statement
    ("比竞品更安全", "的安全性信息见说明书"),
    ("比竞品更有效", "的疗效数据见说明书"),
    ("比竞品", "按说明书"),
    ("更安全", "的安全性信息见说明书"),
    ("更有效", "的疗效数据见说明书"),
    ("疗效更好", "的疗效数据见说明书"),
    ("起效更快", "的起效时间见说明书"),
    ("效果最好", "的疗效数据见说明书"),
    ("同类最佳", "的数据见说明书"),
    ("明显优于", "与其他方案的比较需依据说明书"),
    ("优于", "的数据见说明书，未做直接比较"),
    ("最好", "的相关数据见说明书"),
)

_GUIDANCE = {
    "bribery_or_inducement": (
        "这段内容不能对外发出。系统不会替你改写：把「赠送礼品」改成「提供资料」"
        "会改变事实，属于记录失真，比原来的措辞问题更严重。"
        "如果这是客户主动提出的要求，请如实记录并转合规同事处理；"
        "如果实际发生的是合规行为，请按真实情况重新描述。"
    ),
    "comparative_claim": (
        "去掉与其他产品的比较，改为引用说明书里的数据。需要做比较时，"
        "请提供可引用的研究依据并走医学复核。"
    ),
    "off_label": (
        "请改用说明书批准的适应症表述。确实需要讨论说明书以外的用法时，"
        "应走医学与合规复核，而不是直接写进业务内容。"
    ),
    "unapproved_promotion": (
        "请只描述已获批的产品与用法。未获批内容不能出现在对外记录里。"
    ),
}


class RewriteResult(DomainModel):
    """A rewrite suggestion, or a stated reason there is none."""

    available: bool = False
    suggestion: str = ""
    guidance: str = ""
    addressed: list[str] = Field(default_factory=list)
    # Whether the suggestion passed the second deterministic check. A suggestion
    # is only ever shown when this is true.
    verified: bool = False
    checked_against: list[str] = Field(default_factory=list)
    residual_findings: list[str] = Field(default_factory=list)
    withheld_reason: str = ""

    def audit_payload(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "addressed": list(self.addressed),
            "verified": self.verified,
            "residual_findings": list(self.residual_findings),
            "withheld_reason": self.withheld_reason,
        }


class RewriteService:
    """Proposes compliant wording and refuses to show anything that still trips a rule."""

    def __init__(self, policy_store: PolicyBundleStore | None = None) -> None:
        store = policy_store or PolicyBundleStore()
        self._rules = [
            rule for rule in parse_bundle_rules(store.load()) if rule.patterns
        ]

    def _match_rules(self, text: str) -> list[str]:
        """Deterministic rule types matching ``text``. The second-pass check."""
        hits: list[str] = []
        for rule in self._rules:
            for pattern in rule.patterns:
                if re.search(re.escape(pattern), text, re.IGNORECASE):
                    if rule.type not in hits:
                        hits.append(rule.type)
                    break
        return hits

    @staticmethod
    def _apply_substitutions(text: str) -> str:
        rewritten = text
        for banned, replacement in _SUBSTITUTIONS:
            rewritten = rewritten.replace(banned, replacement)
        return rewritten

    @staticmethod
    def _is_readable(text: str) -> bool:
        """Whether a suggestion is a usable sentence.

        Checks the ways the substitution pass can leave debris: a fragment, a
        dangling particle opening any clause, a doubled particle, and a missing
        sentence ending.

        Deliberately conservative. Reconstructing a missing clause subject would
        mean guessing at what the author meant, and the trade is asymmetric:
        withholding a usable suggestion costs one guidance message, while showing a
        malformed one costs the reader's trust in every suggestion after it.
        """
        stripped = (text or "").strip()
        if len(stripped) < _MIN_SUGGESTION_CHARS:
            return False
        if stripped[0] in _DANGLING_LEADS:
            return False
        if _DANGLING_AFTER_BREAK.search(stripped):
            return False
        if "的的" in stripped:
            return False
        return stripped.endswith(tuple(_SENTENCE_TERMINALS))

    @staticmethod
    def _strip_names(text: str) -> str:
        """Remove person names from a suggestion.

        A suggestion is display text shown back to the author, so it is not routed
        through the masking gateway. Rather than echo a raw name in the interface,
        the name is dropped and the role word left in place -- which is also the
        wording a compliant record should use.
        """
        mentions = find_mentions(text)
        for mention in sorted(mentions, key=lambda m: m.start, reverse=True):
            text = text[: mention.start] + text[mention.end :]
        return text

    def suggest(
        self,
        text: str,
        *,
        finding_types: list[str] | None = None,
        candidate: str | None = None,
    ) -> RewriteResult:
        """Propose a compliant rewrite for ``text``, or explain why there is none.

        ``candidate`` lets a caller supply text produced elsewhere (a model, in a
        live deployment). It goes through exactly the same verification: the point
        of the second pass is that the source of the wording does not matter.
        """
        types = [str(item) for item in (finding_types or [])]

        # Safety and personal data are not wording problems.
        for finding_type in types:
            if finding_type in _NOT_REWRITABLE:
                return RewriteResult(
                    available=False,
                    guidance=_NOT_REWRITABLE[finding_type],
                    addressed=[finding_type],
                    withheld_reason="not_a_wording_problem",
                )

        rewritable = [item for item in types if item in _REWRITABLE]

        # Precedence, not presence. A finding that must not be rewritten vetoes the
        # suggestion even when a rewritable finding sits beside it.
        #
        # Without this, passing `comparative_claim` alongside `bribery_or_inducement`
        # rewrote the inducement sentence anyway and produced "医生以表示感谢。" --
        # the service substituted against text it had already decided must not be
        # redrafted. Real cases arrive with several findings at once, so this is the
        # normal shape of the input rather than a corner.
        #
        # The reason it has to be a veto: a sentence is rewritten as a whole. A
        # suggestion that "addresses" the comparison necessarily also rewrites the
        # clause the other finding flagged.
        veto = [item for item in types if item in _GUIDANCE and item not in _REWRITABLE]
        if veto:
            # Both concerns are explained. The author needs to know about the
            # blocking one *and* the one a rewrite would have handled.
            explained = veto + [item for item in rewritable if item in _GUIDANCE]
            return RewriteResult(
                available=False,
                guidance="\n".join(_GUIDANCE[item] for item in explained),
                addressed=explained,
                withheld_reason=(
                    "这段内容里有不能靠改写解决的问题，系统不提供替换文本，"
                    "请按上面的说明处理。"
                ),
            )

        if not rewritable:
            return RewriteResult(available=False)

        proposed = candidate if candidate is not None else self._apply_substitutions(text)
        proposed = self._strip_names(proposed).strip()
        guidance = "\n".join(_GUIDANCE[item] for item in rewritable if item in _GUIDANCE)

        if not proposed or proposed == text.strip():
            return RewriteResult(
                available=False,
                guidance=guidance,
                addressed=rewritable,
                withheld_reason="no_safe_alternative_found",
            )

        if not self._is_readable(proposed):
            # Rule-clean but not a sentence. Withheld, with the guidance kept, so
            # the author still has a next step.
            return RewriteResult(
                available=False,
                guidance=guidance,
                addressed=rewritable,
                verified=False,
                withheld_reason=(
                    "自动改写结果不成句，已不予展示，请按上面的说明手动修改。"
                ),
            )

        # The second pass. Anything still matching a rule is withheld: the tool
        # must not propose the violation it just blocked.
        residual = self._match_rules(proposed)
        if residual:
            return RewriteResult(
                available=False,
                guidance=guidance,
                addressed=rewritable,
                verified=False,
                checked_against=[rule.rule_id for rule in self._rules],
                residual_findings=residual,
                withheld_reason=(
                    "改写建议本身仍会触发合规规则，已不予展示，请按上面的说明手动修改。"
                ),
            )

        return RewriteResult(
            available=True,
            suggestion=proposed,
            guidance=guidance,
            addressed=rewritable,
            verified=True,
            checked_against=[rule.rule_id for rule in self._rules],
        )


_DEFAULT: RewriteService | None = None


def suggest_rewrite(
    text: str,
    *,
    finding_types: list[str] | None = None,
    candidate: str | None = None,
) -> RewriteResult:
    """Module-level convenience wrapper around a shared service instance."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = RewriteService()
    return _DEFAULT.suggest(text, finding_types=finding_types, candidate=candidate)


__all__ = ["RewriteResult", "RewriteService", "suggest_rewrite"]
