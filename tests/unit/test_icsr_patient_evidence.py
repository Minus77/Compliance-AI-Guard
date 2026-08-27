"""D-6: "identifiable patient" is about existence, not about what survived masking.

Reproduced before the fix: the narrative "李四服药后出现皮疹，联系电话1380013xxxx"
produced ``identifiable_patient.met = False`` with ``basis_code = absent`` — even
though masking had just minted a patient token for that very name. The criterion
was reading the text *after* masking, so removing the identifier also removed the
evidence that an identifiable patient existed.

That understates ICSR completeness in exactly the cases that matter most: a
narrative naming a real patient looks *less* reportable than one saying "患者".
The presence of a patient token is affirmative evidence and is what the criterion
now reads. The token itself is never interpreted — only its existence.
"""

from datetime import UTC, datetime

from compliance_guard.agents.icsr_assessment import assess_icsr

RECEIVED = datetime(2026, 8, 24, 2, 0, tzinfo=UTC)


def _assess(text, **kwargs):
    kwargs.setdefault("product_id", "PRODUCT-001")
    return assess_icsr(text, received_at=RECEIVED, **kwargs)


def _criterion(result, name):
    return next(item for item in result.criteria if item.criterion == name)


def test_patient_token_satisfies_the_criterion():
    result = _assess(
        "[PATIENT_TKN_82e8dbc2d4fcd5c3]服药后出现皮疹。",
        patient_entity_present=True,
    )
    assert _criterion(result, "identifiable_patient").met is True


def test_basis_records_token_presence_not_a_value():
    result = _assess(
        "[PATIENT_TKN_82e8dbc2d4fcd5c3]服药后出现皮疹。",
        patient_entity_present=True,
    )
    criterion = _criterion(result, "identifiable_patient")
    assert criterion.basis_code == "patient_token_present"
    assert "82e8dbc2d4fcd5c3" not in criterion.basis_value
    assert "82e8dbc2d4fcd5c3" not in criterion.basis


def test_masked_narrative_is_a_valid_icsr():
    """The whole point: masking must not cost the case its reportability."""
    result = _assess(
        "[PATIENT_TKN_82e8dbc2d4fcd5c3]服药后出现皮疹。",
        patient_entity_present=True,
    )
    assert result.valid_icsr is True
    assert "identifiable_patient" not in result.missing_criteria


def test_token_in_text_alone_is_enough_without_the_entity_flag():
    """Detection must not depend on a caller remembering to pass a flag."""
    result = _assess("[PATIENT_TKN_82e8dbc2d4fcd5c3]服药后出现皮疹。")
    assert _criterion(result, "identifiable_patient").met is True


def test_context_word_still_satisfies_the_criterion():
    result = _assess("患者服药后出现皮疹。")
    criterion = _criterion(result, "identifiable_patient")
    assert criterion.met is True
    assert criterion.basis_code == "term_present"


def test_hcp_token_alone_does_not_imply_a_patient():
    """A doctor being identifiable says nothing about the patient."""
    result = _assess("[HCP_TKN_33e6d2a1b4c5d6e7]反馈本品出现皮疹。")
    assert _criterion(result, "identifiable_patient").met is False


def test_no_party_at_all_leaves_the_criterion_unmet():
    result = _assess("服药后出现皮疹。")
    criterion = _criterion(result, "identifiable_patient")
    assert criterion.met is False
    assert criterion.basis_code == "absent"
    assert "identifiable_patient" in result.missing_criteria


def test_unmet_patient_criterion_still_requires_follow_up():
    """An incomplete report is a collection task, never a dropped signal."""
    result = _assess("服药后出现皮疹。")
    assert result.is_safety_relevant is True
    assert result.followup_required is True
