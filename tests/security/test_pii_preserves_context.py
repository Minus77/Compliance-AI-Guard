"""D-1 regression: masking replaces only the identifier, never surrounding context.

The gateway used to substitute the whole regex match (including the leading
"患者" context word and one greedily captured extra character), which corrupted
the narrative that downstream AE keyword matching reads.
"""

import re

from compliance_guard.security.pii_gateway import KnownIdentifier, SanitizeContext, sanitize

TOKEN_RE = re.compile(r"\[(?:PATIENT|HCP|ENTITY)_TKN_[0-9a-f]{16}\]")


def plain_context(tenant_id: str = "TENANT-CN", known: list[KnownIdentifier] | None = None):
    return SanitizeContext(tenant_id=tenant_id, known_identifiers=known or [])


def residue(text: str) -> str:
    """Sanitized text with every token removed, for fidelity comparison."""
    return TOKEN_RE.sub("", text)


def test_patient_context_word_survives_masking():
    result = sanitize("患者李四出现皮疹", plain_context())
    assert "李四" not in result.model_text
    assert result.model_text.startswith("患者")
    assert result.model_text.endswith("出现皮疹")


def test_no_character_is_swallowed_after_patient_name():
    result = sanitize("患者王五恶心呕吐", plain_context())
    assert "恶心呕吐" in result.model_text
    assert "王五" not in result.model_text


def test_source_fidelity_rate_is_one_for_patient_narrative():
    """Everything that is not an identifier must survive byte for byte."""
    original = "患者李四出现皮疹，持续两天，建议复查。"
    result = sanitize(original, plain_context())
    assert residue(result.model_text) == original.replace("李四", "")


def test_source_fidelity_rate_is_one_for_hcp_narrative():
    original = "今天拜访了章医生，对本品很认可。"
    result = sanitize(original, plain_context())
    assert residue(result.model_text) == original.replace("章", "")


def test_title_word_is_preserved_as_role_context():
    result = sanitize("章医生正在查看影像", plain_context())
    assert "医生" in result.model_text
    assert "正在查看影像" in result.model_text
    assert "章医生" not in result.model_text


def test_spans_still_point_at_tokens_after_group_only_replacement():
    result = sanitize("患者李四出现皮疹，患者王五恶心呕吐", plain_context())
    assert result.spans
    for token, spans in result.spans.items():
        for span in spans:
            start, end = (int(part) for part in span[5:].split("-", 1))
            assert result.model_text[start:end] == token


def test_known_identifier_masking_keeps_context_word():
    known = [
        KnownIdentifier(entity_type="patient", canonical_id="PATIENT-0001", values=["李四"]),
    ]
    result = sanitize("患者李四出现皮疹", plain_context(known=known))
    assert result.model_text.startswith("患者")
    assert result.model_text.endswith("出现皮疹")
