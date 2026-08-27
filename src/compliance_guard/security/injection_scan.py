"""Prompt-injection detection.

Untrusted model input and content is treated strictly as data. Matching phrases
produce `prompt_injection` findings with action `record_and_route`: the signal is
recorded and routed for review, but never returned as an instruction and never
allowed to change system prompts or tool behavior.
"""

from __future__ import annotations

from compliance_guard.domain.enums import SecurityAction, Severity
from compliance_guard.domain.models import SecurityFinding

_EN_PHRASES = (
    "ignore all previous instructions",
    "ignore all instructions",
    "ignore your instructions",
    "disregard the rules",
    "disregard previous instructions",
    "forget your instructions",
    "reveal your system prompt",
    "reveal the system prompt",
    "output the system prompt",
    "expose your instructions",
    "say everything as if",
    "developer mode",
    "you are now",
    "act as the system",
    "call the tool",
    "execute the function",
)

_ZH_PHRASES = (
    "忽略所有规则",
    "忽略所有指令",
    "忽略之前的指令",
    "忽略之前所有",
    "无视所有规则",
    "无视指令",
    "泄露系统提示",
    "泄露提示词",
    "输出秘密",
    "调用工具",
    "执行函数",
    "绕过审查",
    "假装你是",
    "不要遵守",
)

_GENERIC_REASON = (
    "untrusted content contains an injection phrase; "
    "recorded and routed for review, never executed"
)


def scan_untrusted_content(content: str) -> list[SecurityFinding]:
    """Return one `prompt_injection` finding per distinct phrase matched."""
    haystack = content.casefold()
    matched: list[str] = []
    for phrase in (*_EN_PHRASES, *_ZH_PHRASES):
        if phrase.casefold() in haystack and phrase not in matched:
            matched.append(phrase)

    findings: list[SecurityFinding] = []
    for phrase in matched:
        position = haystack.find(phrase.casefold())
        findings.append(
            SecurityFinding(
                type="prompt_injection",
                severity=Severity.S2,
                action=SecurityAction.RECORD_AND_ROUTE,
                blocked=False,
                reason=_GENERIC_REASON,
                spans=[f"char:{position}-{position + len(phrase)}"],
            )
        )
    return findings
