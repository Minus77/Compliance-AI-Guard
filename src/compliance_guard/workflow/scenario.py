"""Server-side inference of the examination scenario.

``extensions.scenario`` used to travel straight from the caller into the model
request, where it selected which response profile the provider was asked for
(defect P-2). That let the sender of a piece of content decide how that content
would be examined, which is the same class of mistake as letting it declare its
own indication.

Inference is deterministic and local. Cue precedence follows consequence, not
frequency: an injection attempt outranks a commercial redline, which outranks a
safety narrative, because acting on the wrong one costs the most in that order.

Two deliberate carve-outs:

**Operational scenarios pass through.** Values that do not describe content at
all (``schema_failure``, ``model_timeout``, ``permission_denial``) are harness and
degradation directives used to prove the workflow fails safe. They are not claims
about the narrative, so inference forwards them untouched.

**Demo mode can override, visibly.** With ``DEMO_MODE=1`` a claimed content
scenario is honoured so a walkthrough can pin a specific path, and the override
is recorded in the audit trail rather than applied silently.
"""

from __future__ import annotations

import os
from typing import Any

from compliance_guard.domain.models import DomainModel
from compliance_guard.security.name_lexicon import find_mentions

# Scenarios that describe content, and therefore may never be self-declared.
CONTENT_SCENARIOS = frozenset({"ae", "injection", "normal", "off_label", "pii", "redline"})

# Scenarios that describe an operational condition rather than the narrative.
OPERATIONAL_SCENARIOS = frozenset({"schema_failure", "model_timeout", "permission_denial"})

_INJECTION_CUES = (
    "忽略之前", "忽略以上", "忽略前面", "忽视之前", "不要遵守", "系统提示",
    "system prompt", "ignore previous", "ignore all previous", "disregard",
    "直接批准", "自动批准", "调用工具", "执行函数", "修改系统",
)

_REDLINE_CUES = (
    "宴请", "贿赂", "回扣", "红包", "请客", "礼品", "好处费", "违规激励",
    "赞助费", "感谢费", "返点",
)

_SAE_CUES = ("死亡", "危及生命", "住院", "致残", "抢救", "休克")

_AE_CUES = (
    "皮疹", "恶心", "呕吐", "腹泻", "头晕", "头痛", "瘙痒", "不良反应",
    "副作用", "停药", "过敏", "水肿", "乏力", "晕厥", "肝损", "心悸",
)

_OFF_LABEL_CUES = (
    "超适应症", "适应症外", "说明书之外", "也很有效", "也有效", "还能治",
    "还可以治", "可以用于", "off-label", "超说明书",
)

_PII_CUES = ("身份证", "病历号", "手机号", "联系电话", "住址", "@")


class ScenarioDecision(DomainModel):
    """The scenario the server will use, and what the client asked for."""

    scenario: str
    inferred: str
    claimed: str | None = None
    claim_honoured: bool = False
    basis: str = ""

    def audit_payload(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "inferred": self.inferred,
            "claimed": self.claimed,
            "claim_honoured": self.claim_honoured,
            "basis": self.basis,
        }


def demo_mode_enabled() -> bool:
    """True when the explicitly labelled demo mode is active."""
    return str(os.environ.get("DEMO_MODE", "")).strip().lower() in {"1", "true", "yes", "on"}


def _first_cue(text: str, cues: tuple[str, ...]) -> str | None:
    lowered = text.casefold()
    for cue in cues:
        if cue.casefold() in lowered:
            return cue
    return None


def _infer_from_content(content: str) -> tuple[str, str]:
    text = content or ""

    cue = _first_cue(text, _INJECTION_CUES)
    if cue is not None:
        return "injection", f"injection cue {cue!r}"

    cue = _first_cue(text, _REDLINE_CUES)
    if cue is not None:
        return "redline", f"redline cue {cue!r}"

    cue = _first_cue(text, _SAE_CUES) or _first_cue(text, _AE_CUES)
    if cue is not None:
        return "ae", f"safety cue {cue!r}"

    cue = _first_cue(text, _OFF_LABEL_CUES)
    if cue is not None:
        return "off_label", f"off-label cue {cue!r}"

    cue = _first_cue(text, _PII_CUES)
    if cue is not None:
        return "pii", f"identifier cue {cue!r}"
    if find_mentions(text):
        return "pii", "person name detected in content"

    return "normal", "no risk cue detected"


def infer_scenario(content: str, claimed: str | None = None) -> ScenarioDecision:
    """Decide the examination scenario for ``content``."""
    inferred, basis = _infer_from_content(content)
    claim = str(claimed).strip() if claimed else None

    if claim and claim not in CONTENT_SCENARIOS:
        # Not a statement about the narrative; forward it unchanged.
        return ScenarioDecision(
            scenario=claim,
            inferred=inferred,
            claimed=claim,
            claim_honoured=True,
            basis=f"operational scenario {claim!r} passed through; content suggests {inferred}",
        )

    if claim and demo_mode_enabled():
        return ScenarioDecision(
            scenario=claim,
            inferred=inferred,
            claimed=claim,
            claim_honoured=True,
            basis=f"demo mode honoured claimed scenario {claim!r}; content suggests {inferred}",
        )

    return ScenarioDecision(
        scenario=inferred,
        inferred=inferred,
        claimed=claim,
        claim_honoured=False,
        basis=basis,
    )


__all__ = [
    "CONTENT_SCENARIOS",
    "OPERATIONAL_SCENARIOS",
    "ScenarioDecision",
    "demo_mode_enabled",
    "infer_scenario",
]
