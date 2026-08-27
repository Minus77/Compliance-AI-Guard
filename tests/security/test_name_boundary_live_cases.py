"""Regression for name spans found by running the real server, not the fixtures.

The unit fixtures used "患者李四出现皮疹", where 出现 is a boundary word, so the
name ended in the right place. A live check with "患者李四服药后出现皮疹" showed
李四服 — the 服 of 服药 was absorbed into the name, and the masked text became
"患者[TKN]药后出现皮疹".

That is defect D-1 again, in a case the fixtures did not cover: masking recall was
fine (the name went), but a character of narrative was destroyed, and it is exactly
the character that carries clinical meaning. These cases pin the clinical verbs
that follow a patient name in practice.
"""

from __future__ import annotations

import re

from compliance_guard.security.name_lexicon import find_mentions
from compliance_guard.security.pii_gateway import SanitizeContext, sanitize

TOKEN_RE = re.compile(r"\[(?:PATIENT|HCP|ENTITY)_TKN_[0-9a-f]{16}\]")


def _masked(text: str) -> str:
    return sanitize(text, SanitizeContext(tenant_id="TENANT-CN")).model_text


def _residue(text: str) -> str:
    return TOKEN_RE.sub("", _masked(text))


def test_dosing_verb_is_not_absorbed_into_the_name():
    assert [m.text for m in find_mentions("患者李四服药后出现皮疹")] == ["李四"]


def test_masked_dosing_narrative_keeps_every_clinical_word():
    original = "患者李四服药后出现皮疹"
    assert _residue(original) == original.replace("李四", "")


def test_injection_route_is_not_absorbed():
    assert [m.text for m in find_mentions("患者李四注射后不适")] == ["李四"]


def test_oral_route_is_not_absorbed():
    assert [m.text for m in find_mentions("患者王五口服本品")] == ["王五"]


def test_infusion_route_is_not_absorbed():
    assert [m.text for m in find_mentions("患者张三输液时头晕")] == ["张三"]


def test_previously_covered_case_still_works():
    assert [m.text for m in find_mentions("患者李四用药后好转")] == ["李四"]


def test_full_live_narrative_preserves_all_context():
    original = "今天拜访了章三，章医生对本品很认可。患者李四服药后出现皮疹，联系电话13800138000。"
    masked = _masked(original)
    # Identifiers gone.
    for identifier in ("李四", "13800138000"):
        assert identifier not in masked
    # Every clinical and context word survives.
    for kept in ("患者", "医生", "服药后出现皮疹", "对本品很认可", "今天拜访了", "联系电话"):
        assert kept in masked, f"{kept} was destroyed by masking"


def test_one_doctor_still_gets_one_token():
    masked = _masked("今天拜访了章三，章医生对本品很认可，章主任还问了剂量。")
    tokens = set(TOKEN_RE.findall(masked))
    assert len(tokens) == 1, f"expected one HCP token, got {tokens}"


def test_two_character_given_names_are_still_fully_masked():
    """Recall is the floor: a longer name must not be left half-visible."""
    masked = _masked("患者李明月出现皮疹")
    assert "李明月" not in masked
    assert "明月" not in masked
    assert "月" not in masked
