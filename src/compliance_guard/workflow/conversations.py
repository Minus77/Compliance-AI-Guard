"""Guarded AI input and short-lived, bound conversation sessions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from compliance_guard.audit.ledger import AuditLedger, AuditWriteError
from compliance_guard.audit.privacy import privacy_safe_audit_payload
from compliance_guard.domain.enums import ContentType, Decision, Entrypoint, Severity
from compliance_guard.domain.models import Actor, AuditEvent, DomainModel
from compliance_guard.workflow.checks import (
    CheckFinding,
    CheckRequest,
    CheckResult,
    CheckService,
)
from compliance_guard.workflow.conversation_sessions import (
    DEFAULT_SESSION_LIFETIME,
    ConversationExpiredError,
    ConversationNotFoundError,
    ConversationPromptMismatchError,
    ConversationSession,
    ConversationStaleError,
    ConversationStore,
)


class GuardInputRequest(DomainModel):
    tenant_id: str = Field(min_length=1)
    content: str
    language: str = Field(default="zh-CN", min_length=1)
    market: str = Field(default="CN", min_length=1)
    product_id: str = ""
    content_type: ContentType = ContentType.AI_CONVERSATION
    content_subtype: str = ""
    therapeutic_area: str = ""
    business_fields: dict[str, Any] = Field(default_factory=dict)
    rule_version: str = ""
    client_content_version: str = ""


class GuardInputResult(DomainModel):
    conversation_id: str | None = None
    decision: Decision
    severity: Severity
    findings: list[CheckFinding] = Field(default_factory=list)
    safe_message: str
    policy_version: str
    content_version: str
    expires_at: datetime | None = None


class GenerateRequest(DomainModel):
    tenant_id: str = Field(min_length=1)
    content: str
    rule_version: str = ""


class GenerationResult(DomainModel):
    conversation_id: str
    state: str
    published_text: str = ""
    findings: list[CheckFinding] = Field(default_factory=list)
    model_called: bool = False
    withdrawn: bool = False


class ConversationGuard:
    """Checks untrusted AI input before any session or model request exists."""

    def __init__(
        self,
        *,
        checks: CheckService,
        store: ConversationStore,
        policy_store,
        gateway=None,
        ledger: AuditLedger | None = None,
    ) -> None:
        self._checks = checks
        self._store = store
        self._policy_store = policy_store
        self._gateway = gateway
        self._ledger = ledger

    def guard_input(self, request: GuardInputRequest, actor: Actor) -> GuardInputResult:
        if actor.tenant_id and actor.tenant_id != request.tenant_id:
            raise PermissionError("actor cannot guard content for another tenant")

        rule_version = self._policy_store.current().policy_version
        result = self._checks.precheck(
            CheckRequest(
                tenant_id=request.tenant_id,
                content_type=request.content_type,
                content_subtype=request.content_subtype,
                market=request.market,
                language=request.language,
                product_id=request.product_id,
                therapeutic_area=request.therapeutic_area,
                content=request.content,
                business_fields=dict(request.business_fields),
                rule_version=request.rule_version,
                client_content_version=request.client_content_version,
            ),
            entrypoint=Entrypoint.INPUT,
        )
        if result.policy_version != rule_version:
            raise ConversationStaleError(result.policy_version)

        may_generate = (
            result.decision not in {Decision.BLOCKED, Decision.REFUSED}
            and all(finding.allow_generate for finding in result.findings)
        )
        if not may_generate:
            return GuardInputResult(
                decision=result.decision,
                severity=result.severity,
                findings=result.findings,
                safe_message=(
                    "此请求包含无法安全处理的内容，已停止生成。"
                    "请移除指令覆盖或其他不安全要求后重试。"
                ),
                policy_version=result.policy_version,
                content_version=result.content_version,
            )

        constraints = {
            "content_type": request.content_type.value,
            "content_subtype": request.content_subtype,
            "market": request.market,
            "language": request.language,
            "product_id": request.product_id,
            "therapeutic_area": request.therapeutic_area,
            "rule_ids": [
                finding.rule_id
                for finding in result.findings
                if finding.rule_id is not None
            ],
            "allow_publish_after_output_check": True,
        }
        session = self._store.create(
            tenant_id=request.tenant_id,
            actor_id=actor.actor_id,
            inspected_content_sha256=CheckService.content_version(request.content),
            safe_content=result.safe_text,
            content_version=result.content_version,
            rule_version=result.policy_version,
            allowed_constraints=constraints,
        )
        return GuardInputResult(
            conversation_id=session.conversation_id,
            decision=result.decision,
            severity=result.severity,
            findings=result.findings,
            safe_message="输入检查通过；生成内容将在发布前再次检查。",
            policy_version=result.policy_version,
            content_version=result.content_version,
            expires_at=session.expires_at,
        )

    def get(
        self,
        conversation_id: str,
        *,
        tenant_id: str,
        actor: Actor,
        rule_version: str = "",
    ) -> ConversationSession:
        current_rule_version = self._policy_store.current().policy_version
        if rule_version and rule_version != current_rule_version:
            raise ConversationStaleError(conversation_id)
        return self._store.get(
            conversation_id,
            tenant_id,
            actor.actor_id,
            current_rule_version,
        )

    def generate(
        self,
        conversation_id: str,
        request: GenerateRequest,
        actor: Actor,
    ) -> GenerationResult:
        """Generate once from checked server state and withhold unsafe output."""
        from compliance_guard.agents.safe_generation import (
            build_constrained_request,
            extract_buffered_text,
            generation_constraints,
        )
        from compliance_guard.policy.bundles import parse_bundle_rules

        if actor.tenant_id and actor.tenant_id != request.tenant_id:
            raise PermissionError("actor cannot generate for another tenant")
        current_rules = self._policy_store.current()
        if request.rule_version and request.rule_version != current_rules.policy_version:
            raise ConversationStaleError(conversation_id)

        session = self._store.get(
            conversation_id,
            request.tenant_id,
            actor.actor_id,
            current_rules.policy_version,
        )
        if not session.inspected_content_matches(request.content):
            raise ConversationPromptMismatchError(conversation_id)
        session = self._store.consume(
            conversation_id,
            request.tenant_id,
            actor.actor_id,
            current_rules.policy_version,
        )

        model_called = False
        candidate = ""
        try:
            if self._gateway is None:
                raise RuntimeError("generation gateway is unavailable")
            model_request = build_constrained_request(
                session,
                parse_bundle_rules(current_rules),
            )
            model_called = True
            raw = self._gateway.complete(
                "conversation_generation",
                model_request,
                generation_constraints(session),
            )
            candidate = extract_buffered_text(raw)
            findings = self._check_output(session, candidate)
            may_publish = (
                findings.decision is Decision.ALLOW
                and all(finding.allow_publish for finding in findings.findings)
            )
            if not may_publish:
                audited = findings.model_copy(
                    update={
                        "check_id": f"output-{uuid.uuid4().hex}",
                        "status": "output_withdrawn",
                    }
                )
                self._audit_output(conversation_id, audited)
                return GenerationResult(
                    conversation_id=conversation_id,
                    state="output_withdrawn",
                    findings=self._safe_findings(findings.findings),
                    model_called=True,
                    withdrawn=bool(candidate),
                )
            audited = findings.model_copy(
                update={"check_id": f"output-{uuid.uuid4().hex}", "status": "published"}
            )
            self._audit_output(conversation_id, audited)
            return GenerationResult(
                conversation_id=conversation_id,
                state="published",
                published_text=candidate,
                findings=self._safe_findings(findings.findings),
                model_called=True,
                withdrawn=False,
            )
        except Exception:
            # Provider details and candidate text stay out of the response. A
            # failed guard is treated as a withdrawal, never as a soft warning.
            return GenerationResult(
                conversation_id=conversation_id,
                state="failed_safe",
                model_called=model_called,
                withdrawn=bool(candidate),
            )

    def _check_output(self, session: ConversationSession, text: str) -> CheckResult:
        constraints = session.allowed_constraints
        return self._checks.precheck(
            CheckRequest(
                tenant_id=session.tenant_id,
                content_type=ContentType(
                    str(
                        constraints.get("content_type")
                        or ContentType.AI_CONVERSATION.value
                    )
                ),
                content_subtype=str(constraints.get("content_subtype") or ""),
                market=str(constraints.get("market") or "CN"),
                language=str(constraints.get("language") or "zh-CN"),
                product_id=str(constraints.get("product_id") or ""),
                therapeutic_area=str(constraints.get("therapeutic_area") or ""),
                content=text,
                rule_version=session.rule_version,
                client_content_version=self._checks.content_version(text),
            ),
            entrypoint=Entrypoint.OUTPUT,
        )

    def _audit_output(self, conversation_id: str, result: CheckResult) -> None:
        if self._ledger is None:
            return
        event = AuditEvent(
            event_id=f"audit-{uuid.uuid4().hex}",
            case_id=conversation_id,
            trace_id=f"trace-{uuid.uuid4().hex}",
            event_type="conversation_output_checked",
            occurred_at=datetime.now(UTC),
            payload={
                **privacy_safe_audit_payload(
                    result,
                    Entrypoint.OUTPUT,
                    model_status="called",
                ),
                "component": "conversation.output_guard",
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

    @staticmethod
    def _safe_findings(findings: list[CheckFinding]) -> list[CheckFinding]:
        """Expose rule provenance without echoing withdrawn model fragments."""
        safe: list[CheckFinding] = []
        for finding in findings:
            item = finding.model_copy(deep=True)
            item.matched_terms = []
            safe.append(item)
        return safe


__all__ = [
    "ConversationExpiredError",
    "ConversationGuard",
    "ConversationNotFoundError",
    "ConversationPromptMismatchError",
    "ConversationSession",
    "ConversationStaleError",
    "ConversationStore",
    "DEFAULT_SESSION_LIFETIME",
    "GenerateRequest",
    "GenerationResult",
    "GuardInputRequest",
    "GuardInputResult",
]
