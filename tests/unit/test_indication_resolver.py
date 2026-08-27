"""D2: deterministic indication normalisation, no model involved.

The resolver answers "which approved concept is this text talking about?" using a
local ontology. It never decides on-label or off-label — that stays with the
closed-world comparison in the policy layer, so an off-label conclusion is always
reproducible and traceable to a specific concept id.
"""

from datetime import UTC, datetime

import pytest

from compliance_guard.knowledge.indication_resolver import IndicationResolver

AS_OF = datetime(2026, 8, 20, tzinfo=UTC)


@pytest.fixture(scope="module")
def resolver() -> IndicationResolver:
    return IndicationResolver()


def test_canonical_name_resolves_to_its_concept(resolver):
    match = resolver.resolve("成人原发性高血压", market="CN", as_of=AS_OF)
    assert match.indication_id == "IND-001"
    assert match.basis == "canonical_name"


def test_colloquial_synonym_resolves_to_the_same_concept(resolver):
    """The D-5 case: a rep writing 血压高 must reach IND-001."""
    match = resolver.resolve("患者血压高，建议规律服药", market="CN", as_of=AS_OF)
    assert match.indication_id == "IND-001"
    assert match.basis == "synonym"


def test_english_synonym_resolves(resolver):
    match = resolver.resolve("patient has essential hypertension", market="CN", as_of=AS_OF)
    assert match.indication_id == "IND-001"


def test_unknown_indication_returns_no_match_instead_of_guessing(resolver):
    match = resolver.resolve("某罕见代谢病", market="CN", as_of=AS_OF)
    assert match.indication_id is None
    assert match.basis == "unresolved"
    assert match.confidence == 0.0


def test_different_disease_resolves_to_its_own_concept(resolver):
    match = resolver.resolve("本品对糖尿病也有效", market="CN", as_of=AS_OF)
    assert match.indication_id == "IND-002"


def test_longest_synonym_wins_over_shorter_overlap(resolver):
    """儿童高血压 is its own concept and must not collapse into plain 高血压."""
    match = resolver.resolve("用于儿童高血压的治疗", market="CN", as_of=AS_OF)
    assert match.indication_id == "IND-006"


def test_broader_concept_is_flagged_rather_than_accepted(resolver):
    match = resolver.resolve("适用于心血管疾病", market="CN", as_of=AS_OF)
    assert match.indication_id == "IND-100"
    assert match.is_broader_category is True


def test_market_filter_keeps_other_markets_out(resolver):
    match = resolver.resolve("高血压", market="US", as_of=AS_OF)
    assert match.indication_id == "IND-008"


def test_as_of_excludes_retired_ontology_versions(resolver):
    match = resolver.resolve("高血压", market="CN", as_of=AS_OF)
    assert match.indication_id == "IND-001"
    assert match.ontology_version == "CN-IND-2026-01"


def test_historical_as_of_replays_the_version_in_force_then(resolver):
    """A conclusion must be replayable against the ontology of its own time."""
    match = resolver.resolve("高血压", market="CN", as_of=datetime(2025, 6, 1, tzinfo=UTC))
    assert match.indication_id == "IND-009"
    assert match.ontology_version == "CN-IND-2024-01"


def test_resolution_is_deterministic(resolver):
    first = resolver.resolve("患者血压高", market="CN", as_of=AS_OF)
    second = resolver.resolve("患者血压高", market="CN", as_of=AS_OF)
    assert first.model_dump() == second.model_dump()


def test_match_reports_the_matched_text_for_auditability(resolver):
    match = resolver.resolve("患者血压高，建议复查", market="CN", as_of=AS_OF)
    assert match.matched_text == "血压高"


def test_is_covered_by_accepts_exact_concept(resolver):
    match = resolver.resolve("血压高", market="CN", as_of=AS_OF)
    assert match.covers("IND-001") is True


def test_is_covered_by_rejects_a_different_concept(resolver):
    match = resolver.resolve("糖尿病", market="CN", as_of=AS_OF)
    assert match.covers("IND-001") is False


def test_child_concept_does_not_cover_its_parent_label(resolver):
    """Paediatric hypertension is not covered by an adult-only label."""
    match = resolver.resolve("儿童高血压", market="CN", as_of=AS_OF)
    assert match.covers("IND-001") is False
