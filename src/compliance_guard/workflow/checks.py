"""Shared deterministic precheck and persisted content check service."""

from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import UTC, datetime
from compliance_guard.audit.ledger import AuditLedger, AuditWriteError
from compliance_guard.audit.privacy import privacy_safe_audit_payload
from compliance_guard.domain.enums import (
    Decision,
    Entrypoint,
    Severity,
    SEVERITY_RANK,
)
from compliance_guard.domain.models import (
    Actor,
    AuditEvent,
    CheckCaseRequest,
    CheckCaseResponse,
)
from compliance_guard.policy.bundles import PolicyBundleStore
from compliance_guard.workflow.check_contracts import (
    CheckFinding,
    CheckRequest,
    CheckResult,
)
from compliance_guard.workflow.precheck import PrecheckResult, PrecheckService


class CheckService:
    """One policy path for prechecks and persisted checks."""

    def __init__(
        self,
        *,
        precheck: PrecheckService,
        orchestrator,
        policy_store: PolicyBundleStore,
        ledger: AuditLedger | None = None,
    ) -> None:
        self._precheck = precheck
        self._orchestrator = orchestrator
        self._policy_store = policy_store
        self._ledger = ledger
        self._lock = threading.RLock()
        self._records: dict[str, tuple[CheckRequest, CheckResult, CheckCaseResponse | None]] = {}

    @staticmethod
    def content_version(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _require_rule_version(self, requested: str) -> None:
        current = self._policy_store.current().policy_version
        if requested and requested != current:
            raise ValueError(f"unknown policy bundle version {requested!r}")

    def precheck_preview(
        self,
        request: CheckRequest,
        *,
        locale: str = "zh-CN",
        entrypoint: Entrypoint = Entrypoint.CONTENT,
    ) -> PrecheckResult:
        self._require_rule_version(request.rule_version)
        return self._precheck.run(
            request.content,
            tenant_id=request.tenant_id,
            market=request.market,
            language=request.language,
            product_id=request.product_id,
            claimed_fields=dict(request.business_fields),
            locale=locale,
            content_type=request.content_type.value,
            content_subtype=request.content_subtype,
            therapeutic_area=request.therapeutic_area,
            client_content_version=request.client_content_version,
            entrypoint=entrypoint,
        )

    def precheck(
        self,
        request: CheckRequest,
        *,
        locale: str = "zh-CN",
        entrypoint: Entrypoint = Entrypoint.CONTENT,
    ) -> CheckResult:
        preview = self.precheck_preview(
            request,
            locale=locale,
            entrypoint=entrypoint,
        )
        findings = [
            CheckFinding(
                type=finding.type,
                severity=Severity(finding.severity),
                decision=Decision(finding.decision),
                rule_id=finding.rule_id,
                rule_version=finding.rule_version,
                category=finding.category,
                matched_terms=list(finding.matched_terms),
                spans=list(finding.spans),
                allow_save=finding.allow_save,
                allow_generate=finding.allow_generate,
                allow_publish=finding.allow_publish,
                notification_message=finding.notification_message,
                remediation_guidance=finding.remediation_guidance,
            )
            for finding in preview.findings
        ]
        return CheckResult(
            decision=Decision(preview.decision),
            severity=self._severity(findings),
            findings=findings,
            policy_version=preview.policy_version,
            content_version=preview.content_version,
            spans_stale=preview.spans_stale,
            safe_text=preview.masked_text,
            masked_count=preview.masked_count,
            model_called=False,
            status="prechecked",
        )

    def submit(self, request: CheckRequest, actor: Actor) -> CheckResult:
        response = self.submit_case(self._case_request(request), actor)
        findings = [
            CheckFinding(
                finding_id=finding.finding_id,
                type=finding.type,
                severity=finding.severity,
                decision=finding.decision,
                rule_id=finding.rule_id,
                rule_version=finding.rule_version,
                category=finding.category,
                matched_terms=list(finding.matched_terms),
                spans=list(finding.spans),
                allow_save=finding.allow_save,
                allow_generate=finding.allow_generate,
                allow_publish=finding.allow_publish,
                notification_message=finding.notification_message,
                remediation_guidance=finding.remediation_guidance,
            )
            for finding in response.findings
        ]
        content_version = self.content_version(request.content)
        result = CheckResult(
            check_id=response.case_id,
            decision=response.decision,
            severity=self._severity(findings),
            findings=findings,
            policy_version=response.policy_version or "",
            content_version=content_version,
            spans_stale=bool(
                request.client_content_version
                and request.client_content_version != content_version
            ),
            created_at=datetime.now(UTC),
            safe_text=str(response.retrieval.get("query", "")),
            model_called=True,
            status=response.status.value,
        )
        self._record_result(response.case_id, response.trace_id, result)
        with self._lock:
            self._records[response.case_id] = (request.model_copy(deep=True), result, response)
        return result

    def _record_result(
        self,
        case_id: str,
        trace_id: str,
        result: CheckResult,
    ) -> None:
        if self._ledger is None:
            return
        event = AuditEvent(
            event_id=f"audit-{uuid.uuid4().hex}",
            case_id=case_id,
            trace_id=trace_id,
            event_type="content_check_completed",
            occurred_at=datetime.now(UTC),
            payload={
                **privacy_safe_audit_payload(
                    result,
                    Entrypoint.CONTENT,
                    model_status="called" if result.model_called else "not_called",
                ),
                "component": "content.check",
            },
            configuration_versions={
                "policy": result.policy_version,
                "content": result.content_version,
            },
        )
        try:
            self._ledger.append(event)
        except OSError as error:
            raise AuditWriteError("audit ledger write failed") from error

    def submit_case(self, request: CheckCaseRequest, actor: Actor) -> CheckCaseResponse:
        if actor.tenant_id and actor.tenant_id != request.tenant_id:
            raise PermissionError("actor cannot submit for another tenant")
        return self._orchestrator.run_check_case(request)

    def get(self, check_id: str, tenant_id: str) -> CheckResult:
        with self._lock:
            record = self._records.get(check_id)
            if record is None or record[0].tenant_id != tenant_id:
                raise KeyError(check_id)
            return record[1].model_copy(deep=True)

    def _case_request(self, request: CheckRequest) -> CheckCaseRequest:
        now = datetime.now(UTC)
        version = request.client_content_version or self.content_version(request.content)
        return CheckCaseRequest(
            case_id=f"CHECK-{uuid.uuid4().hex}",
            tenant_id=request.tenant_id,
            content=request.content,
            content_parts=list(request.content_parts),
            source="content_check",
            source_record_id=request.external_ref or None,
            source_version=version,
            market=request.market,
            language=request.language,
            product_id=request.product_id,
            channel=request.content_type.value,
            received_at=now,
            idempotency_key=f"check-{uuid.uuid4().hex}",
            extensions={
                "content_type": request.content_type.value,
                "content_subtype": request.content_subtype,
                "therapeutic_area": request.therapeutic_area,
                "structured_fields": dict(request.business_fields),
                "retention_policy": request.retention_policy,
            },
        )

    @staticmethod
    def _severity(findings: list[CheckFinding]) -> Severity:
        if not findings:
            return Severity.S3
        return min((finding.severity for finding in findings), key=SEVERITY_RANK.get)


__all__ = ["CheckFinding", "CheckRequest", "CheckResult", "CheckService"]
