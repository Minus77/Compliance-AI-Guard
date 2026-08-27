"""Pluggable call-report source connectors (contract mocks).

A connector describes *where* a narrative comes from and how it is fetched:

- ``veeva_crm``   -- Veeva CRM call report, read through :class:`CrmAdapter`
- ``veeva_vault`` -- Veeva Vault MedComms record, read through :class:`VeevaAdapter`
- ``manual``      -- typed by the representative (no upstream record)

Contract-only: no live Veeva/Vault system, license, credential, or network call
is used. The adapters re-read the authoritative record from an in-memory store
and reject stale event versions, so the demo shows the *shape* of a real
integration (event payloads are never authoritative) without a real tenant.

Adding a connector means appending one :class:`SourceConnector` entry; the API
and UI enumerate this registry instead of hard-coding source names.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.domain.models import DomainModel

from .crm_adapter import CrmAdapter
from .veeva_adapter import SourceRecord, VeevaAdapter


class SourceConnector(DomainModel):
    """Describes one pluggable source connector for the UI and API."""

    connector_id: str
    system: str
    kind: str
    label_zh: str
    label_en: str
    description_zh: str
    description_en: str
    reads_upstream: bool = True
    mode: str = "mock"
    # --- governance attributes a pharma IT/QA reviewer expects to see -------
    # Vendor and interface let QA trace which validated system is in scope.
    vendor: str = ""
    interface: str = ""
    # Auth mode and credential reference: never a secret value, only a pointer.
    auth_mode: str = "none"
    credential_ref: str = ""
    # Data residency matters for PIPL / GDPR cross-border assessment.
    data_residency: str = "CN"
    # Highest data classification this connector is permitted to carry.
    data_classification: str = "confidential"
    # CSV/GxP posture. "not_validated" is the honest answer for a demo mock.
    validation_status: str = "not_validated"
    gxp_relevant: bool = False
    # Which SOP governs use of this interface, and record retention.
    sop_ref: str = ""
    retention_period: str = ""
    # Read-only vs. write-capable, and whether writes need an approval token.
    write_capable: bool = False
    approval_required_for_write: bool = True


_CONNECTORS: tuple[SourceConnector, ...] = (
    SourceConnector(
        connector_id="veeva_crm",
        system="Veeva CRM",
        kind="call_report",
        label_zh="Veeva CRM 拜访记录",
        label_en="Veeva CRM call report",
        description_zh=(
            "从 Veeva CRM 读取拜访记录正文。按 record_id 回读权威记录，"
            "并拒绝比当前版本更旧的事件版本（事件负载永不可信）。"
        ),
        description_en=(
            "Reads the call-report narrative from Veeva CRM. The record is re-read "
            "by record_id and stale event versions are rejected; the event payload "
            "is never authoritative."
        ),
        vendor="Veeva Systems",
        interface="REST v24 (mock)",
        auth_mode="oauth2_client_credentials",
        credential_ref="vault://veeva/crm/client_secret",
        data_residency="CN",
        data_classification="pii_tokenized",
        validation_status="not_validated",
        gxp_relevant=True,
        sop_ref="SOP-CRM-014",
        retention_period="10y",
        write_capable=False,
        approval_required_for_write=True,
    ),
    SourceConnector(
        connector_id="veeva_vault",
        system="Veeva Vault",
        kind="med_comms",
        label_zh="Veeva Vault 医学沟通稿",
        label_en="Veeva Vault MedComms record",
        description_zh=(
            "从 Veeva Vault 读取医学沟通材料。写回需要短时效审批令牌，本演示只做读取。"
        ),
        description_en=(
            "Reads MedComms material from Veeva Vault. Write-back requires a "
            "short-lived approval token; this demo only reads."
        ),
        vendor="Veeva Systems",
        interface="Vault REST v24 (mock)",
        auth_mode="oauth2_client_credentials",
        credential_ref="vault://veeva/vault/client_secret",
        data_residency="CN",
        data_classification="confidential",
        validation_status="not_validated",
        gxp_relevant=True,
        sop_ref="SOP-MLR-021",
        retention_period="10y",
        write_capable=True,
        approval_required_for_write=True,
    ),
    SourceConnector(
        connector_id="manual",
        system="Manual entry",
        kind="call_report",
        label_zh="手工录入",
        label_en="Manual entry",
        description_zh="由代表直接输入，无上游记录，因此没有可回读的版本。",
        description_en=(
            "Typed directly by the representative. No upstream record, so there is "
            "no version to re-read."
        ),
        reads_upstream=False,
        vendor="—",
        interface="in-app form",
        auth_mode="demo_role_header",
        data_residency="CN",
        data_classification="pii_tokenized",
        validation_status="not_validated",
        gxp_relevant=False,
        sop_ref="SOP-CR-002",
        retention_period="10y",
        write_capable=False,
        approval_required_for_write=True,
    ),
)


# Deterministic demo records. Content stays Chinese because server-side risk
# detection and the evidence corpus are Chinese-only; see docs/operations.md.
_SEED: tuple[dict[str, Any], ...] = (
    {
        "connector_id": "veeva_crm",
        "record_id": "CR-2026-0001",
        "version": "v3",
        "event_type": "call_report.submitted",
        "summary": "常规拜访：高血压适应症用法说明",
        "content": "本品适用于成人原发性高血压的治疗，应遵医嘱规律服用。",
    },
    {
        "connector_id": "veeva_crm",
        "record_id": "CR-2026-0002",
        "version": "v2",
        "event_type": "call_report.submitted",
        "summary": "拜访记录提到疑似不良事件",
        "content": "服药后出现皮疹，建议停药。",
    },
    {
        "connector_id": "veeva_crm",
        "record_id": "CR-2026-0003",
        "version": "v5",
        "event_type": "call_report.submitted",
        "summary": "拜访记录含患者身份证号",
        "content": "身份证号13800138000。",
    },
    {
        "connector_id": "veeva_vault",
        "record_id": "VV-2026-0007",
        "version": "v4",
        "event_type": "medcomms.draft",
        "summary": "医学沟通稿：超说明书剂量表述",
        "content": "本品可用于糖尿病的治疗，推荐剂量100mg每日一次。",
    },
    {
        "connector_id": "veeva_vault",
        "record_id": "VV-2026-0008",
        "version": "v1",
        "event_type": "medcomms.draft",
        "summary": "医学沟通稿：严重不良事件描述",
        "content": "出现昏迷，危及生命，需立即处理。",
    },
)


class SourceRegistry:
    """Enumerates connectors and fetches records through the real adapters."""

    def __init__(
        self,
        *,
        ledger: AuditLedger | None = None,
        now: Callable[[], datetime] | None = None,
        tenant_id: str = "TENANT-CN",
        market: str = "CN",
        product_id: str = "PRODUCT-001",
    ) -> None:
        self._crm = CrmAdapter(ledger=ledger, now=now)
        self._vault = VeevaAdapter(ledger=ledger, now=now)
        self._index: dict[str, dict[str, str]] = {}
        updated = now() if now is not None else datetime.now(UTC)
        for row in _SEED:
            adapter = self._adapter(row["connector_id"])
            adapter.seed(
                SourceRecord(
                    record_id=row["record_id"],
                    version=row["version"],
                    source=row["connector_id"],
                    event_type=row["event_type"],
                    tenant_id=tenant_id,
                    market=market,
                    product_id=product_id,
                    content=row["content"],
                    summary=row["summary"],
                    updated_at=updated,
                )
            )
            self._index[row["record_id"]] = {
                "connector_id": row["connector_id"],
                "summary": row["summary"],
                "version": row["version"],
            }

    def _adapter(self, connector_id: str) -> Any:
        if connector_id == "veeva_vault":
            return self._vault
        if connector_id == "veeva_crm":
            return self._crm
        raise ValueError(f"connector {connector_id!r} has no upstream store")

    @staticmethod
    def connectors() -> list[SourceConnector]:
        return [connector.model_copy(deep=True) for connector in _CONNECTORS]

    def records(self, connector_id: str | None = None) -> list[dict[str, Any]]:
        """List available upstream records, optionally filtered by connector."""
        out: list[dict[str, Any]] = []
        for record_id, meta in self._index.items():
            if connector_id and meta["connector_id"] != connector_id:
                continue
            out.append(
                {
                    "record_id": record_id,
                    "connector_id": meta["connector_id"],
                    "summary": meta["summary"],
                    "version": meta["version"],
                }
            )
        return sorted(out, key=lambda item: item["record_id"])

    def fetch(
        self, connector_id: str, record_id: str, version: str | None = None
    ) -> dict[str, Any]:
        """Re-read one authoritative record through its adapter."""
        adapter = self._adapter(connector_id)
        record = adapter.get_current_record(record_id, version=version)
        return {
            "connector_id": connector_id,
            "record_id": record.record_id,
            "version": record.version,
            "event_type": record.event_type,
            "summary": record.summary,
            "content": record.content,
            "market": record.market,
            "product_id": record.product_id,
            "updated_at": record.updated_at.isoformat() if record.updated_at else None,
            "reread": True,
        }


__all__ = ["SourceConnector", "SourceRegistry"]
