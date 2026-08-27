import hashlib

import pytest

from compliance_guard.domain.models import KnowledgeDocument
from compliance_guard.knowledge.ingestion import ingest_document


def _loc_bounds(location: str) -> tuple[int, int]:
    start_text, end_text = location[5:].split("-", 1)
    return int(start_text), int(end_text)


def test_ingest_creates_document_with_versioned_chunks():
    source = (
        "【适应症】本品适用于成人原发性高血压的治疗，适用于血压中度升高的患者，"
        "应在医生指导下长期规律服用，不可自行增减剂量或突然停药，治疗期间应定期"
        "监测血压水平，评估疗效与安全性，并根据个体情况制定合适的治疗方案。\n\n"
        "【用法用量】推荐起始剂量80mg，每日一次口服，可长期使用，应根据血压控制情况"
        "在医生指导下调整剂量，最大剂量不得超过每日160mg，服药时间应尽量固定，"
        "如漏服应尽快补服，但不可一次服用双倍剂量以避免不良反应。\n\n"
        "【不良反应】常见不良反应包括头痛、头晕、乏力、心悸等，多数患者可以耐受，"
        "若出现严重不良反应应立即就医并报告，少数患者可能出现皮疹、水肿等反应，"
        "应停止用药并及时咨询医生进行对症处理。\n\n"
        "【禁忌】对本品活性成分过敏者禁用，孕妇及哺乳期妇女禁用，严重肝功能不全者"
        "禁用，正在使用其他降压药物者应在医生指导下联合使用并密切监测。"
    )
    doc = ingest_document(
        source,
        {
            "source_id": "CN-PI-2026-01",
            "version": "CN-PI-2026-01",
            "market": "CN",
            "product_id": "PRODUCT-001",
            "language": "zh-CN",
            "tenant_id": "TENANT-CN",
            "status": "active",
            "access_scope": ["internal", "cn_release"],
        },
    )
    assert isinstance(doc, KnowledgeDocument)
    assert doc.source_id == "CN-PI-2026-01"
    assert doc.version == "CN-PI-2026-01"
    assert doc.checksum == hashlib.sha256(source.encode("utf-8")).hexdigest()
    assert len(doc.chunks) >= 2
    for chunk in doc.chunks:
        assert chunk.source_id == "CN-PI-2026-01"
        assert chunk.version == "CN-PI-2026-01"
        assert chunk.market == "CN"
        assert chunk.product_id == "PRODUCT-001"
        assert chunk.access_scope == ["internal", "cn_release"]
        assert chunk.tenant_id == "TENANT-CN"
        assert chunk.location.startswith("char:")
        start, end = _loc_bounds(chunk.location)
        assert chunk.text == source[start:end]
        assert chunk.checksum == hashlib.sha256(chunk.text.encode("utf-8")).hexdigest()


def test_chunking_uses_paragraph_windows_with_exact_spans():
    from compliance_guard.knowledge.chunking import chunk_text

    source = (
        "第一段内容详细描述本品用于治疗成人原发性高血压这一适应症范围。\n\n"
        "第二段内容详细说明推荐剂量为每日八十毫克并强调在医生指导下使用。\n\n"
        "第三段内容详细描述用药期间可能出现的不良反应以及应当采取的处理措施。"
    )
    chunks = chunk_text(source, max_chars=45)
    assert len(chunks) >= 2
    seen = set()
    for location, chunk in chunks:
        start, end = _loc_bounds(location)
        assert chunk == source[start:end]
        assert start not in seen
        seen.add(start)
    assert any("适应症" in chunk for _, chunk in chunks)
    assert any("剂量" in chunk for _, chunk in chunks)


def test_ingest_rejects_missing_metadata():
    with pytest.raises(ValueError):
        ingest_document("some text", {"source_id": "X"})


def test_ingest_rejects_invalid_status():
    with pytest.raises(ValueError):
        ingest_document(
            "text",
            {
                "source_id": "X",
                "version": "v",
                "market": "CN",
                "product_id": "P",
                "language": "zh-CN",
                "status": "not-a-status",
            },
        )


def test_external_or_unsigned_is_non_release():
    doc = ingest_document(
        "外部草稿内容",
        {
            "source_id": "EXT-1",
            "version": "v",
            "market": "CN",
            "product_id": "P",
            "language": "zh-CN",
            "tenant_id": "TENANT-CN",
            "status": "draft",
            "access_scope": ["internal"],
            "release_evidence": False,
        },
    )
    assert all(chunk.release_evidence is False for chunk in doc.chunks)
    assert doc.release_evidence is False


def test_ingest_empty_source_is_rejected():
    with pytest.raises(ValueError):
        ingest_document(
            "   ",
            {
                "source_id": "X",
                "version": "v",
                "market": "CN",
                "product_id": "P",
                "language": "zh-CN",
                "status": "active",
            },
        )