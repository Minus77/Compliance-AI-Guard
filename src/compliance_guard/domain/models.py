"""Compatibility facade for compliance domain contracts.

The concrete models live in focused modules; existing callers can continue to
import every public name from this module.
"""

from .base import DomainModel
from .case import (
    Actor,
    AuditEvent,
    CaseContext,
    ExtractedData,
    KnowledgeFilter,
    ReviewTask,
    TraceSpan,
)
from .content import (
    CandidateFinding,
    CharacterSpan,
    CheckCaseRequest,
    CheckCaseResponse,
    ContentPart,
    Entity,
    Evidence,
    Finding,
    KnowledgeChunk,
    KnowledgeDocument,
    ProductContext,
    SecurityFinding,
)
from .routing import ModelProfile, PolicyBundle, TaskRoute


__all__ = [
    "Actor",
    "AuditEvent",
    "CandidateFinding",
    "CaseContext",
    "CharacterSpan",
    "CheckCaseRequest",
    "CheckCaseResponse",
    "ContentPart",
    "Entity",
    "Evidence",
    "ExtractedData",
    "Finding",
    "KnowledgeChunk",
    "KnowledgeDocument",
    "KnowledgeFilter",
    "ModelProfile",
    "PolicyBundle",
    "ProductContext",
    "ReviewTask",
    "SecurityFinding",
    "TaskRoute",
    "TraceSpan",
]
