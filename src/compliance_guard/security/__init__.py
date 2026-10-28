"""Security boundary: tokenization, sanitization, injection scanning, DLP, authorization."""

from .authorization import AuthorizationService
from .dlp import DlpScanner, reject_raw_pii
from .injection_scan import scan_untrusted_content
from .pii_gateway import (
    KnownIdentifier,
    PiiGateway,
    SanitizeContext,
    SanitizedContent,
    sanitize,
)
from .token_service import TokenRef, TokenService
from compliance_guard.policy.spans import (
    OffsetSegment,
    SanitizationIntegrityError,
    TextOffsetMap,
    find_spans,
)

__all__ = [
    "AuthorizationService",
    "DlpScanner",
    "KnownIdentifier",
    "OffsetSegment",
    "PiiGateway",
    "SanitizeContext",
    "SanitizedContent",
    "SanitizationIntegrityError",
    "TextOffsetMap",
    "TokenRef",
    "TokenService",
    "find_spans",
    "reject_raw_pii",
    "sanitize",
    "scan_untrusted_content",
]
