import pytest

from compliance_guard.domain.models import KnowledgeFilter
from compliance_guard.knowledge.label_facts import LabelFactsStore
from compliance_guard.knowledge.retrieval import EvidenceRetriever


def cn_filters(**overrides):
    payload = dict(
        tenant_id="TENANT-CN",
        market="CN",
        product_id="PRODUCT-001",
        language="zh-CN",
        as_of="2026-08-20",
        purpose="release_check",
        access_scope=["internal", "cn_release"],
    )
    payload.update(overrides)
    return KnowledgeFilter(**payload)


@pytest.fixture
def retriever() -> EvidenceRetriever:
    return EvidenceRetriever()


@pytest.fixture
def label_store() -> LabelFactsStore:
    return LabelFactsStore()


def test_old_label_is_not_current_release_evidence(retriever):
    pack = retriever.search_evidence(
        query="适应症和剂量",
        filters=KnowledgeFilter(
            tenant_id="TENANT-CN",
            market="CN",
            product_id="PRODUCT-001",
            language="zh-CN",
            as_of="2026-08-20",
            purpose="release_check",
        ),
    )
    assert all(item.version != "CN-PI-2024-01" for item in pack.items)
    assert all(item.market == "CN" for item in pack.items)


def test_cross_market_evidence_is_filtered(retriever):
    pack = retriever.search_evidence("适应症", cn_filters())
    assert all(item.market == "CN" for item in pack.items)
    assert "EV-HK-2026-001" not in {item.evidence_id for item in pack.items}


def test_empty_retrieval_produces_explicit_evidence_gap(retriever):
    pack = retriever.search_evidence("完全不存在的化合物XQZ99", cn_filters())
    assert pack.items == []
    assert pack.evidence_gap is True
    assert len(pack.gaps) >= 1
    assert pack.gaps[0].topic == "完全不存在的化合物XQZ99"


def test_expired_evidence_is_excluded(retriever):
    expired_id = "EV-CN-2026-EXP"
    pack = retriever.search_evidence("辅助研究", cn_filters())
    assert expired_id not in {item.evidence_id for item in pack.items}

    pack_early = retriever.search_evidence("辅助研究", cn_filters(as_of="2026-05-01"))
    assert expired_id in {item.evidence_id for item in pack_early.items}


def test_conflicting_evidence_retained_as_contradiction(retriever):
    pack = retriever.search_evidence("100mg外部研究", cn_filters())
    assert "EV-CN-2026-003" in {item.evidence_id for item in pack.contradictions}
    assert pack.supporting == []
    assert pack.evidence_gap is True


def test_evidence_id_and_quote_hash_presence(retriever):
    pack = retriever.search_evidence("适应症", cn_filters())
    assert pack.items
    for item in pack.items:
        assert item.evidence_id
        assert item.quote
        assert item.hash


def test_access_scope_filtering_restricts_evidence(retriever):
    restricted_id = "EV-CN-2026-LEGAL"
    pack = retriever.search_evidence("法律审查", cn_filters())
    assert restricted_id not in {item.evidence_id for item in pack.items}

    pack_legal = retriever.search_evidence("法律审查", cn_filters(access_scope=["legal_only"]))
    assert restricted_id in {item.evidence_id for item in pack_legal.items}


def test_tenant_mismatch_excludes_evidence(retriever):
    pack = retriever.search_evidence("适应症", cn_filters(tenant_id="TENANT-OTHER"))
    assert pack.items == []
    assert pack.evidence_gap is True


def test_non_release_external_item_excluded_from_supporting(retriever):
    non_release_id = "EV-CN-2026-EXT-NR"
    pack = retriever.search_evidence("糖尿病", cn_filters())
    ids = {item.evidence_id for item in pack.items}
    assert non_release_id not in ids
    assert non_release_id not in {item.evidence_id for item in pack.supporting}


def test_release_evidence_requires_approved_source_type(retriever):
    contradiction_id = "EV-CN-2026-003"
    pack = retriever.search_evidence("100mg外部研究", cn_filters())
    assert contradiction_id in {item.evidence_id for item in pack.contradictions}
    assert contradiction_id not in {item.evidence_id for item in pack.supporting}


def test_dose_mismatch_is_deterministic(label_store):
    result = label_store.compare_label_fields(
        extracted={"dose": "100mg", "indication_id": "IND-001"},
        label_facts=label_store.current("PRODUCT-001", "CN"),
    )
    assert result.matches is False
    assert "dose" in result.mismatches


def test_matching_label_fields_is_closed_world_match(label_store):
    result = label_store.compare_label_fields(
        extracted={
            "indication_id": "IND-001",
            "population": "成人",
            "line": "一线",
            "dose": "80mg",
            "route": "口服",
            "duration": "长期",
            "combination": "单药",
        },
        label_facts=label_store.current("PRODUCT-001", "CN"),
    )
    assert result.matches is True
    assert result.mismatches == []


def test_label_store_rejects_unknown_product(label_store):
    with pytest.raises(ValueError):
        label_store.current("PRODUCT-999", "CN")


def test_label_store_rejects_unknown_market(label_store):
    # JP rather than US: the fixture set now covers CN and US for every product,
    # so US no longer demonstrates an unconfigured market.
    with pytest.raises(ValueError):
        label_store.current("PRODUCT-001", "JP")


def test_label_store_rejects_unknown_version(label_store):
    with pytest.raises(ValueError):
        label_store.current("PRODUCT-001", "CN", version="CN-PI-2099-01")