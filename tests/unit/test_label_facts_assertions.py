"""Label-field comparison: only real claims are compared against the label.

Every case here is a regression for a defect that a live model produced and the
offline fixtures could never produce, because fixtures returned `{}` for
`extracted_fields` while a real model returns a populated, sometimes hedged,
sometimes null-filled object.

The invariant under test: an *asserted* value is compared closed-world (an
asserted value absent from the label is a mismatch), while silence, a
"not stated" marker, or a value the model admits it inferred is **not** a
mismatch. Getting this wrong fabricates off-label findings on compliant copy,
which is the fastest way to lose a representative's trust in the tool.
"""

from __future__ import annotations

import pytest

from compliance_guard.knowledge.label_facts import LabelFacts, compare_label_fields

APPROVED = LabelFacts(
    product_id="PRODUCT-001",
    market="CN",
    version="CN-PI-2026-01",
    indication_id="IND-001",
    indication="成人原发性高血压",
    population="成人",
    line="一线",
    dose="80mg",
    route="口服",
    duration="长期",
    combination="单药",
)


# -- real claims are still caught --------------------------------------------


def test_asserted_off_label_indication_and_dose_are_mismatches():
    """The headline business case must keep working."""
    result = compare_label_fields(
        {"indication": "糖尿病", "dose": "100mg"}, APPROVED
    )

    assert result.matches is False
    assert set(result.mismatches) == {"indication", "dose"}


def test_fully_matching_claims_are_a_clean_match():
    result = compare_label_fields(
        {
            "indication_id": "IND-001",
            "population": "成人",
            "line": "一线",
            "dose": "80mg",
            "route": "口服",
            "duration": "长期",
            "combination": "单药",
        },
        APPROVED,
    )

    assert result.matches is True
    assert result.mismatches == []


# -- silence is not a contradiction ------------------------------------------


def test_absent_fields_are_not_mismatches():
    """A short note that mentions nothing must not read as off-label."""
    result = compare_label_fields({}, APPROVED)

    assert result.matches is True
    assert result.mismatches == []


def test_null_filled_template_is_not_a_contradiction():
    """Live-model defect: the model returns every key with a null value.

    Treating those as claims reported all seven fields as mismatched and turned
    a clean on-label sentence into an S1 off-label finding.
    """
    result = compare_label_fields(
        {
            "indication": None,
            "population": None,
            "line": None,
            "dose": None,
            "route": None,
            "duration": None,
            "combination": None,
        },
        APPROVED,
    )

    assert result.matches is True
    assert result.mismatches == []


@pytest.mark.parametrize(
    "marker",
    ["未指定", "未提及", "未明确说明", "不详", "无", "not specified", "N/A", "  "],
)
def test_not_stated_markers_are_not_claims(marker):
    result = compare_label_fields({"dose": marker}, APPROVED)

    assert "dose" not in result.mismatches


# -- hedged values -----------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["口服（推断）", "口服（未明确说明）", "口服(推测)", "口服（inferred）"],
)
def test_inferred_values_do_not_create_mismatches(value):
    """Live-model defect: the model appends its own hedge to a value.

    Observed route values on content that never stated a route. Comparing the
    decorated string against the label's "口服" produced a false mismatch, even
    though the bare value agrees with the label and the model admitted it was an
    inference rather than something the representative wrote.
    """
    result = compare_label_fields({"route": value}, APPROVED)

    assert "route" not in result.mismatches
    assert result.details["route"]["asserted"] is False


def test_hedged_value_that_contradicts_the_label_is_still_not_invented():
    """An inference must not create a finding even when it disagrees.

    The representative never wrote it, so there is nothing to hold them to. The
    real off-label signal has to come from an asserted value.
    """
    result = compare_label_fields({"route": "静脉注射（推断）"}, APPROVED)

    assert "route" not in result.mismatches


def test_a_parenthetical_that_is_part_of_the_value_is_not_stripped_as_a_hedge():
    """Only "not stated"/inference hedges are discounted, not real qualifiers."""
    result = compare_label_fields({"population": "成人（18岁以上）"}, APPROVED)

    # This is a genuine claim that differs from the plain "成人" on the label.
    assert result.details["population"]["asserted"] is True
    assert "population" in result.mismatches


def test_hedged_value_is_reported_as_unasserted_rather_than_compared():
    """A hedged value is not compared at all, so it can never be a mismatch.

    ``matched`` is not meaningful for a field nobody claimed; ``asserted`` is the
    field the reviewer UI should read, and the mismatch list is what drives a
    finding.
    """
    result = compare_label_fields({"route": "口服（推断）"}, APPROVED)

    assert result.details["route"]["asserted"] is False
    assert "route" not in result.mismatches
    assert result.matches is True


# -- field shape -------------------------------------------------------------


@pytest.mark.parametrize("value", ["一次", "每日一次", "口服", "长期"])
def test_dose_without_a_quantity_is_not_a_dose_claim(value):
    """Live-model defect: a frequency word landed in the dose field.

    On "成人原发性高血压的治疗推荐口服给药，一次。" the model extracted
    ``dose: "一次"``. Compared against the approved "80mg" that read as an
    off-label dose claim and turned a compliant sentence into an S1 finding. A
    dose is inherently quantitative, so a value with no digit is not a dose.
    """
    result = compare_label_fields({"dose": value}, APPROVED)

    assert "dose" not in result.mismatches
    assert result.details["dose"]["asserted"] is False


@pytest.mark.parametrize("value", ["100mg", "100 mg", "每日100mg"])
def test_quantitative_dose_claims_are_still_compared(value):
    result = compare_label_fields({"dose": value}, APPROVED)

    assert "dose" in result.mismatches


def test_matching_quantitative_dose_is_a_match():
    result = compare_label_fields({"dose": "80mg"}, APPROVED)

    assert "dose" not in result.mismatches
    assert result.details["dose"]["asserted"] is True


def test_non_quantitative_fields_are_unaffected_by_the_digit_rule():
    """Only dose is quantity-gated; a route or population needs no digit."""
    result = compare_label_fields({"route": "静脉注射"}, APPROVED)

    assert result.details["route"]["asserted"] is True
    assert "route" in result.mismatches


# -- details stay explainable ------------------------------------------------


def test_details_record_assertion_state_for_every_compared_field():
    """The reviewer UI needs to distinguish "not said" from "said and wrong"."""
    result = compare_label_fields({"dose": "100mg"}, APPROVED)

    assert result.details["dose"]["asserted"] is True
    assert result.details["dose"]["matched"] is False
    assert result.details["route"]["asserted"] is False
    assert result.details["route"]["expected"] == "口服"
