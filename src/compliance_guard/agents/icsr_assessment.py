"""ICSR minimum-criteria assessment and regulatory reporting clocks.

A safety narrative only becomes a *reportable* Individual Case Safety Report
(ICSR) when the four minimum criteria are all present:

  1. an identifiable patient
  2. an identifiable reporter
  3. a suspect medicinal product
  4. a suspect adverse reaction / event

This module assesses those four criteria deterministically and, when the case
qualifies, derives the regulatory submission clock. Day 0 is the date of first
receipt by any company personnel -- awareness, not triage -- which is why the
clock is anchored on the request's ``received_at``.

Clock durations follow the widely used ICH E2B / NMPA / EMA convention:

  - **7 calendar days** for fatal or life-threatening serious cases
  - **15 calendar days** for other serious cases
  - non-serious cases are aggregated (PSUR/PBRER) rather than expedited

**Scope.** This is a demo aid for triage transparency, not a validated safety
database and not regulatory advice. It never suppresses a signal: an incomplete
ICSR still routes to pharmacovigilance for human follow-up, because missing
criteria are a data-collection task, not a reason to drop a safety signal.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from pydantic import Field

from compliance_guard.domain.models import DomainModel

# Seriousness criteria per ICH E2A. Fatal / life-threatening drive the 7-day clock.
_FATAL_TERMS = ("死亡", "致死")
_LIFE_THREATENING_TERMS = ("危及生命", "生命危险", "昏迷", "休克")
_OTHER_SERIOUS_TERMS = (
    "严重住院",
    "住院",
    "致残",
    "残疾",
    "先天畸形",
    "出生缺陷",
)

# An adverse reaction must be present for criterion 4.
_REACTION_TERMS = (
    "皮疹", "恶心", "呕吐", "腹泻", "头晕", "头痛", "瘙痒", "嗜睡",
    "心悸", "失眠", "不良反应", "副作用", "停药", "过敏",
    "死亡", "昏迷", "休克", "危及生命", "致残", "先天畸形", "住院",
)

# Criterion 1: an identifiable patient. Tokenized patient entities count -- the
# patient is identifiable to the reporter even though we hold only a token.
_PATIENT_TERMS = ("患者", "病人", "受试者", "该患者", "患方")

# A patient token is affirmative evidence that an identifiable patient exists.
# Reading only the post-masking text got this backwards (defect D-6): a narrative
# naming a real patient scored *lower* on completeness than one saying "患者",
# because masking had removed the very evidence the criterion looked for. Only the
# existence of a token is used; its digest is never interpreted or recorded.
_PATIENT_TOKEN_RE = re.compile(r"\[PATIENT_TKN_[0-9a-f]{16}\]")

# Criterion 2: an identifiable reporter. In a call report the submitting
# representative is the reporter, so this is satisfied by provenance.
_REPORTER_TERMS = ("医生", "医师", "护士", "药师", "患者本人", "家属", "代表")


class IcsrCriterion(DomainModel):
    """One of the four ICSR minimum criteria."""

    criterion: str
    met: bool = False
    basis: str = ""
    # Structured basis so the UI can render it in the active locale instead of
    # displaying English machine prose. ``basis`` stays as a machine-readable
    # fallback for logs and for any client that has no vocabulary table.
    basis_code: str = ""
    basis_value: str = ""


class IcsrAssessment(DomainModel):
    """Deterministic ICSR minimum-criteria and reporting-clock assessment."""

    is_safety_relevant: bool = False
    criteria: list[IcsrCriterion] = Field(default_factory=list)
    criteria_met_count: int = 0
    valid_icsr: bool = False
    seriousness: str = "non_serious"     # fatal | life_threatening | serious | non_serious
    expedited: bool = False
    reporting_clock_days: int | None = None
    day_zero: datetime | None = None
    submission_due: datetime | None = None
    missing_criteria: list[str] = Field(default_factory=list)
    followup_required: bool = False
    rationale: str = ""


def _contains(haystack: str, terms: tuple[str, ...]) -> str | None:
    for value in terms:
        if value in haystack:
            return value
    return None


def assess_icsr(
    narrative: str,
    *,
    received_at: datetime,
    product_id: str = "",
    reporter_known: bool = True,
    patient_entity_present: bool = False,
) -> IcsrAssessment:
    """Assess ICSR minimum criteria and derive the regulatory reporting clock.

    ``narrative`` should be the tokenized (PII-safe) text: criteria are about the
    *presence* of an identifiable party, never about holding their identifiers.
    """
    text = narrative or ""

    reaction = _contains(text, _REACTION_TERMS)
    if reaction is None:
        # Not a safety narrative: no ICSR assessment applies.
        return IcsrAssessment(
            is_safety_relevant=False,
            rationale="no adverse reaction term present; not a safety narrative",
        )

    patient_hit = _contains(text, _PATIENT_TERMS)
    # Presence of a masked patient identifier, detected from the text itself so
    # the result does not depend on a caller remembering to pass a flag.
    patient_token_present = bool(_PATIENT_TOKEN_RE.search(text)) or patient_entity_present
    patient_met = bool(patient_hit) or patient_token_present
    reporter_hit = _contains(text, _REPORTER_TERMS)
    reporter_met = bool(reporter_hit) or reporter_known
    product_met = bool(product_id)

    criteria = [
        IcsrCriterion(
            criterion="identifiable_patient",
            met=patient_met,
            basis=(
                f"patient term '{patient_hit}' present" if patient_hit
                else (
                    "masked patient identifier present before tokenization"
                    if patient_token_present
                    else ""
                )
            ),
            basis_code=(
                "term_present" if patient_hit
                else ("patient_token_present" if patient_token_present else "absent")
            ),
            # Never the token digest: the basis explains why the criterion is met,
            # it is not a place to re-introduce an identifier reference.
            basis_value=patient_hit or "",
        ),
        IcsrCriterion(
            criterion="identifiable_reporter",
            met=reporter_met,
            basis=(
                f"reporter term '{reporter_hit}' present" if reporter_hit
                else ("submitting representative is the reporter" if reporter_known else "")
            ),
            basis_code=(
                "term_present" if reporter_hit
                else ("submitter_is_reporter" if reporter_known else "absent")
            ),
            basis_value=reporter_hit or "",
        ),
        IcsrCriterion(
            criterion="suspect_product",
            met=product_met,
            basis=f"product {product_id}" if product_met else "",
            basis_code="product_in_context" if product_met else "absent",
            basis_value=product_id if product_met else "",
        ),
        IcsrCriterion(
            criterion="suspect_reaction",
            met=True,
            basis=f"reaction term '{reaction}' present",
            basis_code="term_present",
            basis_value=reaction,
        ),
    ]

    met_count = sum(1 for item in criteria if item.met)
    missing = [item.criterion for item in criteria if not item.met]
    valid = not missing

    if _contains(text, _FATAL_TERMS):
        seriousness = "fatal"
    elif _contains(text, _LIFE_THREATENING_TERMS):
        seriousness = "life_threatening"
    elif _contains(text, _OTHER_SERIOUS_TERMS):
        seriousness = "serious"
    else:
        seriousness = "non_serious"

    expedited = seriousness in {"fatal", "life_threatening", "serious"}
    clock_days = None
    due = None
    if expedited:
        clock_days = 7 if seriousness in {"fatal", "life_threatening"} else 15
        # Day 0 = first receipt by any company personnel (awareness date).
        due = received_at + timedelta(days=clock_days)

    if valid and expedited:
        rationale = (
            f"valid ICSR, {seriousness} -> expedited {clock_days}-calendar-day submission"
        )
    elif valid:
        rationale = "valid ICSR, non-serious -> aggregate reporting (PSUR/PBRER)"
    else:
        rationale = (
            "incomplete ICSR ("
            + ", ".join(missing)
            + "); follow-up required, signal still routed to pharmacovigilance"
        )

    return IcsrAssessment(
        is_safety_relevant=True,
        criteria=criteria,
        criteria_met_count=met_count,
        valid_icsr=valid,
        seriousness=seriousness,
        expedited=expedited,
        reporting_clock_days=clock_days,
        day_zero=received_at,
        submission_due=due,
        missing_criteria=missing,
        followup_required=not valid,
        rationale=rationale,
    )


__all__ = ["IcsrAssessment", "IcsrCriterion", "assess_icsr"]
