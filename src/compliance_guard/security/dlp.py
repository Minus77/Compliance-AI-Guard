"""DLP scanner: reject raw phone / email / name patterns in model output and config payloads.

Raw personal identifiers must never leave the boundary in model output or be
accepted inside configuration payloads. Detection returns blocking findings.
"""

from __future__ import annotations

import json
from typing import Any

from compliance_guard.domain.enums import SecurityAction, Severity
from compliance_guard.domain.models import SecurityFinding

from .name_lexicon import find_mentions
from .pii_gateway import EMAIL_RE, PATIENT_ID_RE, PHONE_RE

_CHECKS = (
    (PHONE_RE, "raw phone number"),
    (EMAIL_RE, "raw email address"),
    (PATIENT_ID_RE, "raw patient or HCP identifier"),
)

_NAME_LABELS = {
    "patient": "raw patient name",
    "hcp": "raw HCP name",
}


class DlpScanner:
    """Rejects raw personal-identifier patterns in untrusted payloads."""

    def _text(self, content: str | dict | list) -> str:
        if isinstance(content, str):
            return content
        return json.dumps(content, ensure_ascii=False)

    def scan(self, content: str | dict | list) -> list[SecurityFinding]:
        text = self._text(content)
        findings: list[SecurityFinding] = []
        for pattern, label in _CHECKS:
            for match in pattern.finditer(text):
                findings.append(
                    SecurityFinding(
                        type="dlp",
                        severity=Severity.S1,
                        action=SecurityAction.BLOCK,
                        blocked=True,
                        reason=f"{label} must not leave the gateway",
                        spans=[f"char:{match.start()}-{match.end()}"],
                    )
                )
        # Person names use the same surname-anchored detector as the gateway, so a
        # name the gateway would mask is exactly a name DLP refuses to let out.
        for mention in find_mentions(text):
            findings.append(
                SecurityFinding(
                    type="dlp",
                    severity=Severity.S1,
                    action=SecurityAction.BLOCK,
                    blocked=True,
                    reason=f"{_NAME_LABELS.get(mention.entity_type, 'raw name')} must not leave the gateway",
                    spans=[f"char:{mention.start}-{mention.end}"],
                )
            )
        return findings

    def is_clean(self, content: str | dict | list) -> bool:
        return not self.scan(content)


def reject_raw_pii(content: str | dict | list) -> list[SecurityFinding]:
    """Convenience scan returning blocking findings for raw PII patterns."""
    return DlpScanner().scan(content)
