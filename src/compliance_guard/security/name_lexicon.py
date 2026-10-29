"""Compatibility facade for Chinese person-name detection."""

from __future__ import annotations

from compliance_guard.security.name_detection import find_mentions
from compliance_guard.security.name_models import (
    MentionKind,
    NameLexicon,
    NameMention,
    load_lexicon,
)

__all__ = ["MentionKind", "NameLexicon", "NameMention", "find_mentions", "load_lexicon"]
