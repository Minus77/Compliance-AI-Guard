"""Explicit values shared by the compliance domain and workflow."""

from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    NEEDS_INFO = "needs_info"
    HUMAN_REVIEW = "human_review"
    BLOCKED = "blocked"
    REFUSED = "refused"


class Severity(str, Enum):
    S0 = "S0"
    S1 = "S1"
    S2 = "S2"
    S3 = "S3"


class CaseState(str, Enum):
    RECEIVED = "RECEIVED"
    AUTHORIZED = "AUTHORIZED"
    PREPROCESSED = "PREPROCESSED"
    CONTEXT_READY = "CONTEXT_READY"
    CLASSIFIED = "CLASSIFIED"
    EVIDENCE_READY = "EVIDENCE_READY"
    EVALUATED = "EVALUATED"
    VALIDATED = "VALIDATED"
    DECISIONED = "DECISIONED"
    ALLOWED = "ALLOWED"
    NEEDS_INFO = "NEEDS_INFO"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    BLOCKED = "BLOCKED"
    REFUSED = "REFUSED"
    AUDITED = "AUDITED"
    COMPLETED = "COMPLETED"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_SAFE = "FAILED_SAFE"
    MANUAL_DEGRADED = "MANUAL_DEGRADED"


class WorkflowEvent(str, Enum):
    AUTHORIZE = "AUTHORIZED"
    AUTHORIZED = "AUTHORIZED"
    PREPROCESS = "PREPROCESSED"
    PREPROCESSED = "PREPROCESSED"
    PREPARE_CONTEXT = "CONTEXT_READY"
    CONTEXT_READY = "CONTEXT_READY"
    CLASSIFY = "CLASSIFIED"
    CLASSIFIED = "CLASSIFIED"
    RETRIEVE_EVIDENCE = "EVIDENCE_READY"
    EVIDENCE_READY = "EVIDENCE_READY"
    EVALUATE = "EVALUATED"
    EVALUATED = "EVALUATED"
    VALIDATE = "VALIDATED"
    VALIDATED = "VALIDATED"
    DECIDE = "DECISIONED"
    DECISIONED = "DECISIONED"
    ALLOW = "ALLOWED"
    ALLOWED = "ALLOWED"
    NEEDS_INFO = "NEEDS_INFO"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    BLOCK = "BLOCKED"
    BLOCKED = "BLOCKED"
    REFUSE = "REFUSED"
    REFUSED = "REFUSED"
    AUDIT = "AUDITED"
    AUDITED = "AUDITED"
    COMPLETE = "COMPLETED"
    COMPLETED = "COMPLETED"
    FAIL_RETRYABLE = "FAIL_RETRYABLE"
    FAILED_RETRYABLE = "FAIL_RETRYABLE"
    RETRYABLE_FAILURE = "FAIL_RETRYABLE"
    FAIL_SAFE = "FAIL_SAFE"
    FAILED_SAFE = "FAIL_SAFE"
    SAFE_FAILURE = "FAIL_SAFE"
    MANUAL_DEGRADE = "MANUAL_DEGRADED"
    MANUAL_DEGRADED = "MANUAL_DEGRADED"
    MODEL_FAILURE = "MODEL_FAILURE"
    RETRY_COMPLETE = "RETRY_COMPLETE"


class TaskType(str, Enum):
    MULTIMODAL_EXTRACTION = "multimodal_extraction"
    ROUTINE_COMPLIANCE = "routine_compliance"
    COMPLEX_EVIDENCE_REASONING = "complex_evidence_reasoning"


class Role(str, Enum):
    AUTHOR = "author"
    SUBMITTER = "submitter"
    REVIEWER = "reviewer"
    MEDICAL_REVIEWER = "medical_reviewer"
    SAFETY_REVIEWER = "safety_reviewer"
    LEGAL_REVIEWER = "legal_reviewer"
    COMPLIANCE_ADMIN = "compliance_admin"
    AUDITOR = "auditor"
    ADMIN = "admin"

    # Read-only compatibility values for persisted records and existing clients.
    REPRESENTATIVE = "representative"
    COMPLIANCE = "compliance"
    MEDICAL_REVIEW = "medical_review"
    PHARMACOVIGILANCE = "pharmacovigilance"
    LEGAL = "legal"
    SECURITY = "security"
    ARCHITECT = "architect"
    SYSTEM = "system"
    FIELD_REP = "field_rep"
    PV_REVIEWER = "pv_reviewer"
    # Functions a real pharma affiliate separates. MSL is medical-affairs
    # field-facing (not commercial); QPPV is the EU-style qualified person for
    # pharmacovigilance; QA owns CSV/GxP posture; regulatory owns submissions.
    MSL = "msl"
    QPPV = "qppv"
    QA = "qa"
    REGULATORY_AFFAIRS = "regulatory_affairs"
    MLR_REVIEWER = "mlr_reviewer"


class DataClass(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII_TOKENIZED = "pii_tokenized"
    PHI_TOKENIZED = "phi_tokenized"


class ContentType(str, Enum):
    CUSTOMER_INTERACTION_NOTE = "customer_interaction_note"
    MEDICAL_INFORMATION_REQUEST = "medical_information_request"
    MEDICAL_FIELD_NOTE = "medical_field_note"
    PROMOTIONAL_CONTENT = "promotional_content"
    AI_CONVERSATION = "ai_conversation"
    OTHER = "other"


class Entrypoint(str, Enum):
    CONTENT = "content"
    INPUT = "input"
    OUTPUT = "output"


class RuleStatus(str, Enum):
    DRAFT = "draft"
    PASSED = "passed"
    PUBLISHED = "published"
    ROLLED_BACK = "rolled_back"


_ROLE_ALIASES = {
    "field_rep": Role.AUTHOR,
    "representative": Role.AUTHOR,
    "author": Role.AUTHOR,
    "submitter": Role.SUBMITTER,
    "reviewer": Role.REVIEWER,
    "compliance": Role.REVIEWER,
    "medical_review": Role.MEDICAL_REVIEWER,
    "medical_reviewer": Role.MEDICAL_REVIEWER,
    "pharmacovigilance": Role.SAFETY_REVIEWER,
    "pv_reviewer": Role.SAFETY_REVIEWER,
    "safety_reviewer": Role.SAFETY_REVIEWER,
    "legal": Role.LEGAL_REVIEWER,
    "legal_reviewer": Role.LEGAL_REVIEWER,
    "compliance_admin": Role.COMPLIANCE_ADMIN,
    "architect": Role.COMPLIANCE_ADMIN,
    "auditor": Role.AUDITOR,
    "admin": Role.ADMIN,
    "system": Role.SYSTEM,
    "security": Role.SECURITY,
    "msl": Role.MSL,
    "qppv": Role.QPPV,
    "qa": Role.QA,
    "regulatory_affairs": Role.REGULATORY_AFFAIRS,
    "mlr_reviewer": Role.MLR_REVIEWER,
}

_LEGACY_INTERACTION_NOTE_ALIAS = "".join(("call", "_", "report"))

_CONTENT_TYPE_ALIASES = {
    _LEGACY_INTERACTION_NOTE_ALIAS: ContentType.CUSTOMER_INTERACTION_NOTE,
    "customer_interaction_note": ContentType.CUSTOMER_INTERACTION_NOTE,
    "medical_information_request": ContentType.MEDICAL_INFORMATION_REQUEST,
    "medical_field_note": ContentType.MEDICAL_FIELD_NOTE,
    "promotional": ContentType.PROMOTIONAL_CONTENT,
    "promotional_content": ContentType.PROMOTIONAL_CONTENT,
    "medcomms": ContentType.PROMOTIONAL_CONTENT,
    "ai_conversation": ContentType.AI_CONVERSATION,
    "other": ContentType.OTHER,
}


def normalize_role(value: str) -> Role:
    """Resolve a current role or a persisted legacy alias."""
    normalized = value.strip().casefold()
    if normalized in _ROLE_ALIASES:
        return _ROLE_ALIASES[normalized]
    try:
        return Role(normalized)
    except ValueError as exc:
        raise ValueError(f"unknown role {value!r}") from exc


def normalize_content_type(value: str) -> ContentType:
    """Resolve a documented content type or a compatibility alias."""
    return _CONTENT_TYPE_ALIASES.get(value.strip().casefold(), ContentType.OTHER)


class Modality(str, Enum):
    TEXT = "text"
    VISION = "vision"
    AUDIO = "audio"


class ContentPartType(str, Enum):
    TEXT = "text"
    IMAGE_REF = "image_ref"
    AUDIO_REF = "audio_ref"


class EvidenceStatus(str, Enum):
    ACTIVE = "active"
    DRAFT = "draft"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"


class ReviewTaskStatus(str, Enum):
    PENDING = "pending"
    IN_REVIEW = "in_review"
    COMPLETED = "completed"
    ESCALATED = "escalated"
    CANCELLED = "cancelled"


class SpanStatus(str, Enum):
    UNSET = "unset"
    OK = "ok"
    ERROR = "error"


class AdapterType(str, Enum):
    MOCK = "mock"
    HTTP_JSON = "http_json"
    PROVIDER_SPECIFIC = "provider_specific"


class CostTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SecurityAction(str, Enum):
    BLOCK = "block"
    FLAG = "flag"
    REDACT = "redact"
    HUMAN_REVIEW = "human_review"
    RECORD_AND_ROUTE = "record_and_route"


class ErrorCategory(str, Enum):
    PROVIDER = "provider"
    TIMEOUT = "timeout"
    CONNECTION = "connection"
    QUEUE = "queue"
    SCHEMA = "schema"
    PERMISSION = "permission"
    POLICY = "policy"
    AUDIT = "audit"
    MODEL_UNAVAILABLE = "model_unavailable"
    MOCK_RESPONSE_MISSING = "mock_response_missing"
    MOCK_RESPONSE_INVALID = "mock_response_invalid"
    MODEL_MODE_UNSUPPORTED = "model_mode_unsupported"
    UNKNOWN = "unknown"
