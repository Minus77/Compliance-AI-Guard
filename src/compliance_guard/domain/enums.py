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
    REPRESENTATIVE = "representative"
    COMPLIANCE = "compliance"
    MEDICAL_REVIEW = "medical_review"
    PHARMACOVIGILANCE = "pharmacovigilance"
    LEGAL = "legal"
    SECURITY = "security"
    AUDITOR = "auditor"
    ADMIN = "admin"
    ARCHITECT = "architect"
    SYSTEM = "system"
    FIELD_REP = "field_rep"
    REVIEWER = "reviewer"
    PV_REVIEWER = "pv_reviewer"
    MEDICAL_REVIEWER = "medical_reviewer"
    COMPLIANCE_ADMIN = "compliance_admin"
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
