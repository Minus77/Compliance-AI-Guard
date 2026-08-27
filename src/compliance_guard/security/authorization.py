"""Demo role authorization enforcing x-demo-role semantics.

Deny-by-default: an action is permitted only when the actor's role is in the
permission matrix for that action, and configuration publish/rollback requires
an admin role. `can` returns a boolean; `require` raises PermissionError.
"""

from __future__ import annotations

from typing import Any

from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import Actor

_DEMO_HEADER_ROLES: dict[str, Role] = {
    "field_rep": Role.FIELD_REP,
    "reviewer": Role.REVIEWER,
    "pv_reviewer": Role.PV_REVIEWER,
    "medical_reviewer": Role.MEDICAL_REVIEWER,
    "compliance_admin": Role.COMPLIANCE_ADMIN,
    "architect": Role.ARCHITECT,
    "representative": Role.REPRESENTATIVE,
    "compliance": Role.COMPLIANCE,
    "medical_review": Role.MEDICAL_REVIEW,
    "pharmacovigilance": Role.PHARMACOVIGILANCE,
    "legal": Role.LEGAL,
    "security": Role.SECURITY,
    "auditor": Role.AUDITOR,
    "admin": Role.ADMIN,
    "system": Role.SYSTEM,
    "msl": Role.MSL,
    "qppv": Role.QPPV,
    "qa": Role.QA,
    "regulatory_affairs": Role.REGULATORY_AFFAIRS,
    "mlr_reviewer": Role.MLR_REVIEWER,
}

_ADMIN_ROLES = frozenset({Role.COMPLIANCE_ADMIN, Role.ADMIN})

_PERMISSION_MATRIX: dict[str, frozenset[Role]] = {
    "view_case_summary": frozenset(
        {
            Role.FIELD_REP,
            Role.REVIEWER,
            Role.PV_REVIEWER,
            Role.MEDICAL_REVIEWER,
            Role.COMPLIANCE_ADMIN,
            Role.ARCHITECT,
            Role.MSL,
            Role.QPPV,
            Role.QA,
            Role.REGULATORY_AFFAIRS,
            Role.MLR_REVIEWER,
            Role.AUDITOR,
        }
    ),
    "review_case": frozenset(
        {
            Role.REVIEWER,
            Role.PV_REVIEWER,
            Role.MEDICAL_REVIEWER,
            Role.COMPLIANCE_ADMIN,
            Role.QPPV,
            Role.MLR_REVIEWER,
        }
    ),
    # PV review and ICSR submission sit with pharmacovigilance and the QPPV.
    "pv_review": frozenset({Role.PV_REVIEWER, Role.QPPV, Role.COMPLIANCE_ADMIN}),
    "medical_review": frozenset(
        {Role.MEDICAL_REVIEWER, Role.MSL, Role.COMPLIANCE_ADMIN}
    ),
    # MLR (medical/legal/regulatory) sign-off on promotional material.
    "mlr_approve": frozenset({Role.MLR_REVIEWER, Role.COMPLIANCE_ADMIN}),
    # Only the QPPV may release a regulatory ICSR submission.
    "icsr_submit": frozenset({Role.QPPV, Role.COMPLIANCE_ADMIN}),
    "reidentify_phi": frozenset(
        {
            Role.MEDICAL_REVIEWER,
            Role.COMPLIANCE_ADMIN,
            Role.PV_REVIEWER,
            Role.QPPV,
            Role.SYSTEM,
        }
    ),
    "case_escalate": frozenset(
        {
            Role.REVIEWER,
            Role.PV_REVIEWER,
            Role.MEDICAL_REVIEWER,
            Role.COMPLIANCE_ADMIN,
            Role.QPPV,
            Role.MLR_REVIEWER,
        }
    ),
    "architecture_review": frozenset({Role.ARCHITECT, Role.COMPLIANCE_ADMIN}),
    # QA and regulatory affairs need the audit trail for inspection readiness.
    "audit_export": frozenset(
        {
            Role.AUDITOR,
            Role.SECURITY,
            Role.COMPLIANCE_ADMIN,
            Role.QA,
            Role.REGULATORY_AFFAIRS,
        }
    ),
    # QA owns the CSV/validation posture view; it does not grant publish rights.
    "validation_review": frozenset({Role.QA, Role.COMPLIANCE_ADMIN, Role.AUDITOR}),
    "config_publish": _ADMIN_ROLES,
    "config_rollback": _ADMIN_ROLES,
}

# Which SOP governs each action. Surfaced in the UI so a reviewer can see the
# controlling procedure rather than an unexplained permission name.
_ACTION_SOP: dict[str, str] = {
    "view_case_summary": "SOP-CR-002",
    "review_case": "SOP-MLR-021",
    "pv_review": "SOP-PV-007",
    "medical_review": "SOP-MED-011",
    "mlr_approve": "SOP-MLR-021",
    "icsr_submit": "SOP-PV-003",
    "reidentify_phi": "SOP-PRIV-005",
    "case_escalate": "SOP-CR-009",
    "architecture_review": "SOP-IT-030",
    "audit_export": "SOP-QA-018",
    "validation_review": "SOP-QA-001",
    "config_publish": "SOP-IT-031",
    "config_rollback": "SOP-IT-031",
}


class AuthorizationService:
    """Deny-by-default demo authorization for x-demo-role semantics."""

    def can(self, actor: Actor, action: str, resource: Any = None) -> bool:
        allowed_roles = _PERMISSION_MATRIX.get(action)
        if allowed_roles is None:
            return False
        if actor.role not in allowed_roles:
            return False
        if resource is not None and actor.tenant_id is not None:
            resource_tenant = (
                resource.get("tenant_id")
                if isinstance(resource, dict)
                else getattr(resource, "tenant_id", None)
            )
            if resource_tenant and actor.tenant_id != resource_tenant:
                return False
        return True

    def require(self, actor: Actor, action: str, resource: Any = None) -> None:
        if not self.can(actor, action, resource):
            raise PermissionError(
                f"action {action!r} denied for role {actor.role.value!r}"
            )

    @staticmethod
    def known_actions() -> list[str]:
        """Every action name in the permission matrix, sorted for stability."""
        return sorted(_PERMISSION_MATRIX)

    def capabilities(self, actor: Actor) -> dict[str, bool]:
        """Resolve the full allow/deny map for one actor.

        The UI gates its modules from this map so the permission matrix stays
        the single source of truth: a client cannot invent a capability the
        server does not grant, and no role list is duplicated in JavaScript.
        """
        return {action: self.can(actor, action) for action in self.known_actions()}

    @staticmethod
    def sop_for(action: str) -> str:
        """The SOP that governs one action, or an empty string when unmapped."""
        return _ACTION_SOP.get(action, "")

    @staticmethod
    def action_sop_map() -> dict[str, str]:
        """Full action -> SOP map, surfaced so the UI can cite the procedure."""
        return dict(_ACTION_SOP)

    @staticmethod
    def actor_from_header(x_demo_role: str | None, tenant_id: str | None = None) -> Actor:
        if x_demo_role is None or not x_demo_role.strip():
            raise ValueError("missing or empty x-demo-role header")
        role = _DEMO_HEADER_ROLES.get(x_demo_role.strip().casefold())
        if role is None:
            raise ValueError(f"unknown x-demo-role {x_demo_role!r}")
        return Actor(actor_id=f"demo-{role.value}", role=role, tenant_id=tenant_id)
