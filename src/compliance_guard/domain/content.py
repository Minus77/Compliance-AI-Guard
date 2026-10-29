"""Compatibility facade for content, evidence, and completed-check contracts.

The concrete models live in focused modules; existing callers can continue to
import every public name from this module.
"""

from .case_contracts import CheckCaseRequest, CheckCaseResponse
from .content_primitives import CharacterSpan, ContentPart, Entity, ProductContext
from .evidence import Evidence, KnowledgeChunk, KnowledgeDocument
from .findings import CandidateFinding, Finding, SecurityFinding

__all__ = [
    "CandidateFinding",
    "CharacterSpan",
    "CheckCaseRequest",
    "CheckCaseResponse",
    "ContentPart",
    "Entity",
    "Evidence",
    "Finding",
    "KnowledgeChunk",
    "KnowledgeDocument",
    "ProductContext",
    "SecurityFinding",
]
