"""Single-product China knowledge layer: label facts, retrieval, evidence packs."""

from .evidence_pack import EvidenceGap, EvidencePack
from .ingestion import ingest_document
from .label_facts import LabelComparison, LabelFacts, LabelFactsStore, compare_label_fields
from .retrieval import EvidenceRetriever, search_evidence

__all__ = [
    "EvidenceGap",
    "EvidencePack",
    "EvidenceRetriever",
    "LabelComparison",
    "LabelFacts",
    "LabelFactsStore",
    "compare_label_fields",
    "ingest_document",
    "search_evidence",
]