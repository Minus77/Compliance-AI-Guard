"""TokenService unit tests: tenant-stable tokens and fail-closed re-identification."""

import pytest

from compliance_guard.domain.models import Actor
from compliance_guard.security.token_service import TokenService


@pytest.fixture
def token_service():
    return TokenService()


@pytest.fixture
def audited_token_service():
    events = []
    service = TokenService(audit_callback=lambda event, payload: events.append((event, payload)))
    return service, events


def test_hcp_aliases_share_tenant_stable_token(token_service):
    first = token_service.tokenize("hcp", "HCP-0007", "TENANT-CN")
    second = token_service.tokenize("hcp", "HCP-0007", "TENANT-CN")
    other_tenant = token_service.tokenize("hcp", "HCP-0007", "TENANT-EU")
    assert first.token == second.token
    assert first.token != other_tenant.token


def test_tokens_are_deterministic_across_service_instances():
    one = TokenService().tokenize("patient", "PATIENT-0001", "TENANT-CN")
    two = TokenService().tokenize("patient", "PATIENT-0001", "TENANT-CN")
    assert one.token == two.token


def test_token_differs_across_entity_types(token_service):
    hcp = token_service.tokenize("hcp", "HCP-0007", "TENANT-CN")
    patient = token_service.tokenize("patient", "HCP-0007", "TENANT-CN")
    assert hcp.token != patient.token


def test_token_is_tenant_scoped(token_service):
    cn = token_service.tokenize("patient", "PATIENT-0001", "TENANT-CN")
    eu = token_service.tokenize("patient", "PATIENT-0001", "TENANT-EU")
    assert cn.token != eu.token


def test_tokenref_exposes_no_canonical_identifier(token_service):
    ref = token_service.tokenize("patient", "PATIENT-0001", "TENANT-CN")
    assert ref.token
    assert ref.entity_type == "patient"
    assert ref.tenant_id == "TENANT-CN"
    assert "PATIENT-0001" not in ref.model_dump_json()


def test_reidentification_denied_by_default(token_service):
    token = token_service.tokenize("patient", "PATIENT-0001", "TENANT-CN")
    actor = Actor(actor_id="rep-1", role="field_rep")
    with pytest.raises(PermissionError):
        token_service.reidentify(token.token, actor=actor, purpose="view")


def test_reidentification_denied_without_approved_purpose(token_service):
    token = token_service.tokenize("patient", "PATIENT-0001", "TENANT-CN")
    actor = Actor(actor_id="reviewer-1", role="medical_reviewer", tenant_id="TENANT-CN")
    with pytest.raises(PermissionError):
        token_service.reidentify(token.token, actor=actor, purpose="view")


def test_reidentification_denied_without_audit_callback(token_service):
    token = token_service.tokenize("patient", "PATIENT-0001", "TENANT-CN")
    actor = Actor(actor_id="reviewer-1", role="medical_reviewer", tenant_id="TENANT-CN")
    with pytest.raises(PermissionError):
        token_service.reidentify(token.token, actor=actor, purpose="medical_review")


def test_reidentification_granted_records_audit(audited_token_service):
    service, events = audited_token_service
    token = service.tokenize("patient", "PATIENT-0001", "TENANT-CN")
    actor = Actor(actor_id="reviewer-1", role="medical_reviewer", tenant_id="TENANT-CN")
    assert service.reidentify(token.token, actor=actor, purpose="medical_review") == "PATIENT-0001"
    assert not any(event == "reidentify_denied" for event, _ in events)
    granted = [payload for event, payload in events if event == "reidentify_granted"]
    assert granted and granted[0]["token"] == token.token


def test_reidentification_denied_records_audit(audited_token_service):
    service, events = audited_token_service
    token = service.tokenize("patient", "PATIENT-0001", "TENANT-CN")
    actor = Actor(actor_id="rep-1", role="field_rep", tenant_id="TENANT-CN")
    with pytest.raises(PermissionError):
        service.reidentify(token.token, actor=actor, purpose="medical_review")
    denied = [payload for event, payload in events if event == "reidentify_denied"]
    assert denied and denied[0]["token"] == token.token


def test_tokenize_records_audit(audited_token_service):
    service, events = audited_token_service
    service.tokenize("hcp", "HCP-0007", "TENANT-CN")
    assert any(event == "tokenize" for event, _ in events)


def test_unknown_token_reidentification_rejected(audited_token_service):
    service, events = audited_token_service
    actor = Actor(actor_id="reviewer-1", role="medical_reviewer", tenant_id="TENANT-CN")
    with pytest.raises(PermissionError):
        service.reidentify("[PATIENT_TKN_deadbeefdeadbeef]", actor=actor, purpose="medical_review")
    assert any(event == "reidentify_denied" for event, _ in events)


def test_reidentification_denied_on_tenant_mismatch(audited_token_service):
    service, events = audited_token_service
    token = service.tokenize("patient", "PATIENT-0001", "TENANT-CN")
    foreign = Actor(actor_id="reviewer-2", role="medical_reviewer", tenant_id="TENANT-EU")
    with pytest.raises(PermissionError):
        service.reidentify(token.token, actor=foreign, purpose="medical_review")
    denied = [payload for event, payload in events if event == "reidentify_denied"]
    assert denied and denied[0]["reason"] == "tenant_mismatch"
