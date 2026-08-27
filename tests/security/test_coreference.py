"""D-2 regression: 章三 / 章医生 / 章主任 must resolve to one person, one token.

Resolution runs on *unmasked* text and must stay local and deterministic — it is
the one place that sees real names, so a model call here would defeat the whole
pseudonymisation boundary.
"""

from compliance_guard.security.coreference import resolve_mentions
from compliance_guard.security.pii_gateway import KnownIdentifier


def roster_zhang() -> list[KnownIdentifier]:
    return [
        KnownIdentifier(
            entity_type="hcp",
            canonical_id="HCP-001",
            values=["章三", "章医生", "章主任"],
        )
    ]


def clusters_by_member(text: str, **kwargs):
    result = resolve_mentions(text, **kwargs)
    return {member.text for cluster in result.clusters for member in cluster.members}


def test_roster_match_puts_all_aliases_in_one_cluster():
    text = "今天拜访了章三，章医生对本品很认可，章主任还问了剂量。"
    result = resolve_mentions(text, known_identifiers=roster_zhang(), case_id="CASE-1")
    hcp = [c for c in result.clusters if c.entity_type == "hcp"]
    assert len(hcp) == 1
    assert hcp[0].canonical_id == "HCP-001"
    assert hcp[0].resolution_basis == "roster"


def test_same_surname_aliases_merge_without_roster():
    text = "今天拜访了章三，章医生对本品很认可，章主任还问了剂量。"
    result = resolve_mentions(text, case_id="CASE-2")
    hcp = [c for c in result.clusters if c.entity_type == "hcp"]
    assert len(hcp) == 1
    assert hcp[0].canonical_id.startswith("case_local:CASE-2:")
    assert hcp[0].resolution_basis == "surname_heuristic"
    assert hcp[0].ambiguous is False


def test_two_people_with_same_surname_are_not_merged():
    text = "今天拜访了章三和章丽，章三很认可本品。"
    result = resolve_mentions(text, case_id="CASE-3")
    hcp = [c for c in result.clusters if c.entity_type == "hcp"]
    assert len(hcp) == 2
    assert all(cluster.ambiguous for cluster in hcp)


def test_ambiguous_flag_is_surfaced_on_result():
    text = "今天拜访了章三和章丽。"
    result = resolve_mentions(text, case_id="CASE-4")
    assert result.ambiguous is True


def test_unambiguous_result_is_not_flagged():
    text = "今天拜访了章三，章医生很认可本品。"
    result = resolve_mentions(text, case_id="CASE-5")
    assert result.ambiguous is False


def test_case_local_ids_do_not_leak_across_cases():
    text = "今天拜访了章三，章医生很认可本品。"
    first = resolve_mentions(text, case_id="CASE-A")
    second = resolve_mentions(text, case_id="CASE-B")
    first_ids = {c.canonical_id for c in first.clusters}
    second_ids = {c.canonical_id for c in second.clusters}
    assert first_ids.isdisjoint(second_ids)


def test_patient_and_hcp_mentions_stay_in_separate_clusters():
    text = "今天拜访了章医生，患者李四出现皮疹。"
    result = resolve_mentions(text, case_id="CASE-6")
    kinds = {cluster.entity_type for cluster in result.clusters}
    assert kinds == {"hcp", "patient"}


def test_resolution_never_drops_a_mention():
    """Masking recall is the compliance floor: every mention must reach a cluster."""
    text = "今天拜访了章三，章医生对本品很认可，患者李四出现皮疹。"
    result = resolve_mentions(text, case_id="CASE-7")
    clustered = sum(len(cluster.members) for cluster in result.clusters)
    assert clustered == len(result.mentions)
    assert clustered >= 3


def test_bare_name_is_still_clustered_when_roster_misses():
    text = "今天拜访了章三。"
    assert "章三" in clusters_by_member(text, case_id="CASE-8")


def test_confidence_is_higher_for_roster_than_heuristic():
    text = "今天拜访了章三，章医生很认可本品。"
    roster = resolve_mentions(text, known_identifiers=roster_zhang(), case_id="CASE-9")
    heuristic = resolve_mentions(text, case_id="CASE-10")
    assert roster.clusters[0].confidence > heuristic.clusters[0].confidence
