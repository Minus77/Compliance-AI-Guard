"""Demo authorization matrix for x-demo-role semantics."""

import pytest

from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import Actor
from compliance_guard.security.authorization import AuthorizationService


def actor(role, tenant_id="TENANT-CN"):
    return Actor(actor_id=f"{role}-1", role=role, tenant_id=tenant_id)


ALLOWED = [
    ("field_rep", "view_case_summary"),
    ("reviewer", "review_case"),
    ("pv_reviewer", "pv_review"),
    ("medical_reviewer", "medical_review"),
    ("compliance_admin", "config_publish"),
    ("compliance_admin", "config_rollback"),
    ("compliance_admin", "medical_review"),
    ("architect", "architecture_review"),
    ("architect", "view_case_summary"),
]

DENIED = [
    ("field_rep", "review_case"),
    ("field_rep", "config_publish"),
    ("field_rep", "medical_review"),
    ("reviewer", "medical_review"),
    ("reviewer", "pv_review"),
    ("reviewer", "config_publish"),
    ("pv_reviewer", "medical_review"),
    ("pv_reviewer", "config_publish"),
    ("medical_reviewer", "config_publish"),
    ("architect", "config_publish"),
    ("architect", "config_rollback"),
    ("architect", "medical_review"),
]


@pytest.mark.parametrize("role,action", ALLOWED)
def test_demo_role_matrix_allows(role, action):
    service = AuthorizationService()
    assert service.can(actor(role), action) is True
    service.require(actor(role), action)


@pytest.mark.parametrize("role,action", DENIED)
def test_demo_role_matrix_denies(role, action):
    service = AuthorizationService()
    assert service.can(actor(role), action) is False
    with pytest.raises(PermissionError):
        service.require(actor(role), action)


def test_config_publish_requires_admin_role():
    service = AuthorizationService()
    assert service.can(actor("compliance_admin"), "config_publish") is True
    assert service.can(actor("field_rep"), "config_publish") is False
    assert service.can(actor("architect"), "config_publish") is False


def test_unknown_action_denied_by_default():
    service = AuthorizationService()
    assert service.can(actor("compliance_admin"), "impossible_action") is False


def test_actor_from_header_maps_demo_role():
    service = AuthorizationService()
    resolved = service.actor_from_header("medical_reviewer", tenant_id="TENANT-CN")
    assert resolved.role == Role.MEDICAL_REVIEWER
    assert resolved.tenant_id == "TENANT-CN"


def test_actor_from_header_rejects_unknown_role():
    service = AuthorizationService()
    with pytest.raises(ValueError):
        service.actor_from_header("superuser")


def test_actor_from_header_missing_or_empty_raises_value_error():
    service = AuthorizationService()
    with pytest.raises(ValueError):
        service.actor_from_header(None)
    with pytest.raises(ValueError):
        service.actor_from_header("   ")


def test_actor_from_header_is_case_insensitive():
    service = AuthorizationService()
    assert service.actor_from_header("Medical_Reviewer").role == Role.MEDICAL_REVIEWER
    assert service.actor_from_header("COMPLIANCE_ADMIN").role == Role.COMPLIANCE_ADMIN


def test_tenant_mismatch_denies_tenant_scoped_action():
    service = AuthorizationService()
    foreign = Actor(actor_id="rep-9", role="field_rep", tenant_id="TENANT-EU")
    assert service.can(foreign, "view_case_summary", resource={"tenant_id": "TENANT-CN"}) is False
    assert service.can(foreign, "view_case_summary", resource={"tenant_id": "TENANT-EU"}) is True
