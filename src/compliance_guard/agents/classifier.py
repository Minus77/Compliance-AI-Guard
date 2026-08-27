"""Task classification: deterministic choice of the routing task type.

Classification is server-side and does not depend on model output. Image or audio
content parts select multimodal extraction; evidence conflicts, off-label field
mismatches, and comparative-claim contexts select complex evidence reasoning;
everything else is routine compliance.
"""

from __future__ import annotations

from typing import Any

from compliance_guard.domain.enums import ContentPartType, TaskType
from compliance_guard.domain.models import DomainModel

_COMPLEX_FINDING_TYPES = frozenset({"evidence_conflict", "off_label", "comparative_claim"})


class TaskClassification(DomainModel):
    task_type: TaskType
    rationale: str = ""
    modality: str | None = None
    data_class: str | None = None
    region: str | None = None
    degraded: bool = False


def classify_task(
    request: Any,
    security_findings: list[Any] | None = None,
    policy_result: Any | None = None,
) -> TaskClassification:
    """Choose the routing task type from content parts and server-side findings."""
    del security_findings
    for part in request.content_parts or []:
        if part.type is ContentPartType.IMAGE_REF:
            return TaskClassification(
                task_type=TaskType.MULTIMODAL_EXTRACTION,
                rationale="content includes an image part; multimodal extraction required",
                modality="image",
            )
        if part.type is ContentPartType.AUDIO_REF:
            return TaskClassification(
                task_type=TaskType.MULTIMODAL_EXTRACTION,
                rationale="content includes an audio part; multimodal extraction required",
                modality="audio",
            )

    findings = list(getattr(policy_result, "findings", []) or [])
    for finding in findings:
        finding_type = str(getattr(finding, "type", "")).casefold()
        if finding_type in _COMPLEX_FINDING_TYPES:
            return TaskClassification(
                task_type=TaskType.COMPLEX_EVIDENCE_REASONING,
                rationale=f"finding {finding_type} requires complex evidence reasoning",
            )

    return TaskClassification(
        task_type=TaskType.ROUTINE_COMPLIANCE,
        rationale="routine extraction and safety-signal evaluation",
        modality="text",
    )


__all__ = ["TaskClassification", "classify_task"]
