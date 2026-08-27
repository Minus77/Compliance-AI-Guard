"""ICSR minimum criteria and regulatory reporting-clock assessment."""

from datetime import UTC, datetime

from compliance_guard.agents.icsr_assessment import assess_icsr

RECEIVED = datetime(2026, 8, 24, 2, 0, tzinfo=UTC)


def _assess(text, **kwargs):
    kwargs.setdefault("product_id", "PRODUCT-001")
    return assess_icsr(text, received_at=RECEIVED, **kwargs)


def test_non_safety_narrative_is_not_assessed():
    result = _assess("本品适用于成人原发性高血压的治疗，应遵医嘱规律服用。")
    assert result.is_safety_relevant is False
    assert result.valid_icsr is False
    assert result.criteria == []
    assert result.reporting_clock_days is None


def test_life_threatening_case_gets_seven_day_clock():
    result = _assess("患者出现昏迷，危及生命，需立即处理。")
    assert result.is_safety_relevant is True
    assert result.seriousness == "life_threatening"
    assert result.expedited is True
    assert result.reporting_clock_days == 7
    # Day 0 is first company awareness, not triage time.
    assert result.day_zero == RECEIVED
    assert result.submission_due == datetime(2026, 8, 31, 2, 0, tzinfo=UTC)


def test_fatal_case_gets_seven_day_clock():
    result = _assess("患者死亡，家属已告知。")
    assert result.seriousness == "fatal"
    assert result.reporting_clock_days == 7


def test_other_serious_case_gets_fifteen_day_clock():
    result = _assess("患者因不良反应住院治疗。")
    assert result.seriousness == "serious"
    assert result.expedited is True
    assert result.reporting_clock_days == 15
    assert result.submission_due == datetime(2026, 9, 8, 2, 0, tzinfo=UTC)


def test_non_serious_case_is_aggregate_not_expedited():
    result = _assess("患者服药后出现皮疹。")
    assert result.seriousness == "non_serious"
    assert result.expedited is False
    assert result.reporting_clock_days is None
    assert result.submission_due is None
    assert "aggregate" in result.rationale


def test_four_minimum_criteria_are_all_assessed():
    result = _assess("患者服药后出现皮疹，医生建议停药。")
    assert [item.criterion for item in result.criteria] == [
        "identifiable_patient",
        "identifiable_reporter",
        "suspect_product",
        "suspect_reaction",
    ]
    assert result.criteria_met_count == 4
    assert result.valid_icsr is True
    assert result.missing_criteria == []


def test_missing_product_makes_icsr_incomplete_but_keeps_the_signal():
    """An incomplete ICSR must never suppress a safety signal."""
    result = _assess("患者服药后出现皮疹。", product_id="")
    assert result.is_safety_relevant is True   # signal preserved
    assert result.valid_icsr is False
    assert "suspect_product" in result.missing_criteria
    assert result.followup_required is True
    assert "pharmacovigilance" in result.rationale


def test_tokenized_patient_entity_satisfies_patient_criterion():
    """Criteria ask whether a party is identifiable, not that we hold identifiers.

    The basis is reported as ``patient_token_present``: masking removes the name
    but the fact that one was there is exactly the evidence this criterion needs
    (defect D-6).
    """
    result = _assess("服药后出现皮疹。", patient_entity_present=True)
    patient = [c for c in result.criteria if c.criterion == "identifiable_patient"][0]
    assert patient.met is True
    assert patient.basis_code == "patient_token_present"


def test_basis_is_structured_for_localization():
    result = _assess("患者服药后出现皮疹。")
    reaction = [c for c in result.criteria if c.criterion == "suspect_reaction"][0]
    assert reaction.basis_code == "term_present"
    assert reaction.basis_value == "皮疹"
    # The prose fallback remains for logs and vocabulary-less clients.
    assert reaction.basis
