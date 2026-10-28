from compliance_guard.domain.enums import (
    ContentType,
    Role,
    normalize_content_type,
    normalize_role,
)


def test_neutral_roles_are_public_and_legacy_values_are_read_only_aliases():
    assert normalize_role("field_rep") is Role.AUTHOR
    assert normalize_role("medical_review") is Role.MEDICAL_REVIEWER
    assert normalize_role("reviewer") is Role.REVIEWER
    assert normalize_role("pharmacovigilance") is Role.SAFETY_REVIEWER
    assert normalize_content_type("call_report") is ContentType.CUSTOMER_INTERACTION_NOTE
    assert normalize_content_type("promotional") is ContentType.PROMOTIONAL_CONTENT
    assert normalize_content_type("other") is ContentType.OTHER
