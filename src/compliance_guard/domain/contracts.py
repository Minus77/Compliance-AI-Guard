"""Public contract exports and protocol boundaries for later services."""

from __future__ import annotations

from typing import Protocol

from compliance_guard.llm.types import RawModelResult

from .models import (
    Actor,
    AuditEvent,
    CandidateFinding,
    CaseContext,
    CheckCaseRequest,
    CheckCaseResponse,
    Evidence,
    ExtractedData,
    Finding,
    KnowledgeFilter,
    ModelProfile,
    PolicyBundle,
    ReviewTask,
    SecurityFinding,
    TaskRoute,
    TraceSpan,
)


class ModelCandidateValidator(Protocol):
    """Boundary for validating an untrusted RawModelResult candidate."""

    def validate(self, result: RawModelResult) -> ExtractedData:
        """Return candidate data without assigning final policy decisions."""


class ResponsePolicy(Protocol):
    """Boundary for the code-controlled final response policy."""

    def build_response(self, request: CheckCaseRequest) -> CheckCaseResponse:
        """Build a response from server-controlled policy and evidence."""


__all__ = [
    "Actor",
    "AuditEvent",
    "CandidateFinding",
    "CaseContext",
    "CheckCaseRequest",
    "CheckCaseResponse",
    "Evidence",
    "ExtractedData",
    "Finding",
    "KnowledgeFilter",
    "ModelCandidateValidator",
    "ModelProfile",
    "PolicyBundle",
    "RawModelResult",
    "ResponsePolicy",
    "ReviewTask",
    "SecurityFinding",
    "TaskRoute",
    "TraceSpan",
]
