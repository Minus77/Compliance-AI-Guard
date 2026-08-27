"""FastAPI route contract tests: shapes, demo-role enforcement, safe errors."""

from tests.conftest import build_sample_request


def sample_request_json(scenario):
    return build_sample_request(scenario).model_dump(mode="json")


def test_check_case_returns_structured_result(client):
    response = client.post("/api/cases/check", json=sample_request_json("normal"))
    assert response.status_code == 200
    body = response.json()
    assert {"case_id", "decision", "findings", "evidence", "trace_id"} <= body.keys()


def test_model_config_requires_admin(client):
    response = client.put(
        "/api/config/models", headers={"x-demo-role": "field_rep"}, json={"draft": []}
    )
    assert response.status_code == 403


def test_check_case_never_returns_raw_pii(client):
    response = client.post("/api/cases/check", json=sample_request_json("pii"))
    assert response.status_code == 200
    body = response.json()
    assert "13800138000" not in response.text
    assert "safe_view" in body
    safe_text = body["safe_view"]["tokenized_text"]
    assert "13800138000" not in safe_text
    assert body["decision"] == "blocked"


def test_case_detail_and_trace_endpoints(client):
    check = client.post("/api/cases/check", json=sample_request_json("off_label"))
    case_id = check.json()["case_id"]
    detail = client.get(f"/api/cases/{case_id}", headers={"x-demo-role": "field_rep"})
    assert detail.status_code == 200
    assert detail.json()["case_id"] == case_id
    assert "safe_view" in detail.json()
    trace = client.get(f"/api/cases/{case_id}/trace", headers={"x-demo-role": "field_rep"})
    assert trace.status_code == 200
    tbody = trace.json()
    assert tbody["case_id"] == case_id
    assert "spans" in tbody
    assert "audit_events" in tbody
    assert any(event["event_type"] == "case_finalized" for event in tbody["audit_events"])


def test_unknown_case_returns_structured_404(client):
    response = client.get("/api/cases/CASE-NOPE", headers={"x-demo-role": "field_rep"})
    assert response.status_code == 404
    assert "error" in response.json()


def test_case_read_requires_an_identity(client):
    """An anonymous read is refused as 401, not 403.

    The two codes mean different things and the distinction is load-bearing once
    sessions exist: 401 is "I do not know who you are", 403 is "I know, and you may
    not". Returning 403 to an anonymous caller would tell them a valid identity
    would not have helped, which is both wrong and unhelpful.
    """
    check = client.post("/api/cases/check", json=sample_request_json("normal"))
    case_id = check.json()["case_id"]
    for path in (f"/api/cases/{case_id}", f"/api/cases/{case_id}/trace"):
        denied = client.get(path)
        assert denied.status_code == 401
        assert "error" in denied.json()


def test_case_read_is_forbidden_for_a_role_that_lacks_permission(client):
    """The other half: a known identity without the permission gets 403."""
    check = client.post(
        "/api/cases/check",
        json=sample_request_json("normal"),
        headers={"x-demo-role": "field_rep"},
    )
    case_id = check.json()["case_id"]
    denied = client.get(f"/api/cases/{case_id}", headers={"x-demo-role": "security"})
    assert denied.status_code == 403


def test_field_rep_can_read_own_case(client):
    check = client.post(
        "/api/cases/check", json=sample_request_json("off_label"), headers={"x-demo-role": "field_rep"}
    )
    case_id = check.json()["case_id"]
    own = client.get(f"/api/cases/{case_id}", headers={"x-demo-role": "field_rep"})
    assert own.status_code == 200
    assert own.json()["case_id"] == case_id
    trace = client.get(f"/api/cases/{case_id}/trace", headers={"x-demo-role": "field_rep"})
    assert trace.status_code == 200
    assert trace.json()["case_id"] == case_id


def test_field_rep_cannot_read_another_actors_case(client):
    check = client.post(
        "/api/cases/check", json=sample_request_json("ae"), headers={"x-demo-role": "reviewer"}
    )
    case_id = check.json()["case_id"]
    for path in (f"/api/cases/{case_id}", f"/api/cases/{case_id}/trace"):
        denied = client.get(path, headers={"x-demo-role": "field_rep"})
        assert denied.status_code == 403
        assert "error" in denied.json()


def test_reviewer_and_admin_can_read_any_case(client):
    check = client.post(
        "/api/cases/check", json=sample_request_json("injection"), headers={"x-demo-role": "field_rep"}
    )
    case_id = check.json()["case_id"]
    for role in ("reviewer", "admin", "compliance_admin"):
        detail = client.get(f"/api/cases/{case_id}", headers={"x-demo-role": role})
        assert detail.status_code == 200, f"{role} should read any case detail"
        trace = client.get(f"/api/cases/{case_id}/trace", headers={"x-demo-role": role})
        assert trace.status_code == 200, f"{role} should read any case trace"


def test_health_returns_expected_fields(client):
    body = client.get("/health").json()
    assert body["mode"] == "mock"
    assert "knowledge_snapshot" in body
    assert body["knowledge_snapshot"]["label_version"] == "CN-PI-2026-01"
    assert "config_version" in body


def test_metrics_returns_bounded_snapshot(client):
    response = client.get("/api/metrics")
    assert response.status_code == 200
    body = response.json()
    assert body["bounded"] is True
    assert body["redacted"] is True
    assert "counters" in body
    assert "gauges" in body


def test_review_decision_requires_authorized_role_and_reason(client):
    check = client.post("/api/cases/check", json=sample_request_json("ae"))
    case_id = check.json()["case_id"]
    reviews = client.get("/api/reviews", headers={"x-demo-role": "reviewer"}).json()
    task = next(t for t in reviews["tasks"] if t["case_id"] == case_id)
    task_id = task["task_id"]

    denied = client.post(
        f"/api/reviews/{task_id}/decision",
        headers={"x-demo-role": "field_rep"},
        json={"decision": "accepted", "reason": "not allowed"},
    )
    assert denied.status_code == 403
    assert "error" in denied.json()

    no_reason = client.post(
        f"/api/reviews/{task_id}/decision",
        headers={"x-demo-role": "reviewer"},
        json={"decision": "accepted", "reason": "   "},
    )
    assert no_reason.status_code == 400

    unknown_task = client.post(
        "/api/reviews/review-nope/decision",
        headers={"x-demo-role": "reviewer"},
        json={"decision": "accepted", "reason": "ok"},
    )
    assert unknown_task.status_code == 404

    decided = client.post(
        f"/api/reviews/{task_id}/decision",
        headers={"x-demo-role": "reviewer"},
        json={"decision": "rejected", "reason": "PV follow-up confirmed"},
    )
    assert decided.status_code == 200
    record = decided.json()
    assert record["after_decision"] == "blocked"
    assert record["override_reason"] == "PV follow-up confirmed"
    assert record["before_decision"] == "human_review"


def test_review_decision_cannot_allow_s0_s1(client):
    check = client.post("/api/cases/check", json=sample_request_json("ae"))
    case_id = check.json()["case_id"]
    reviews = client.get("/api/reviews", headers={"x-demo-role": "reviewer"}).json()
    task = next(t for t in reviews["tasks"] if t["case_id"] == case_id)
    task_id = task["task_id"]

    denied = client.post(
        f"/api/reviews/{task_id}/decision",
        headers={"x-demo-role": "reviewer"},
        json={"decision": "accepted", "reason": "override to allow"},
    )
    assert denied.status_code == 400
    assert denied.json()["error"]["code"] == "bad_request"


def test_review_queue_listing_requires_reviewer_role(client):
    client.post("/api/cases/check", json=sample_request_json("injection"))
    denied = client.get("/api/reviews", headers={"x-demo-role": "field_rep"})
    assert denied.status_code == 403
    allowed = client.get("/api/reviews", headers={"x-demo-role": "reviewer"})
    assert allowed.status_code == 200
    assert allowed.json()["count"] >= 1


def test_config_publish_rollback_require_admin(client):
    publish = client.post("/api/config/publish", headers={"x-demo-role": "field_rep"})
    assert publish.status_code == 403
    rollback = client.post("/api/config/rollback", headers={"x-demo-role": "field_rep"})
    assert rollback.status_code == 403


def test_admin_can_draft_publish_and_rollback(client):
    profile = {
        "profile_id": "deepseek-routine",
        "provider": "deepseek",
        "display_name": "DeepSeek V4 Flash",
        "model_id": "DeepSeek V4 Flash",
        "adapter_type": "mock",
        "capabilities": ["text"],
        "allowed_data_classes": ["pii_tokenized", "confidential", "internal", "public"],
        "region": "CN",
        "credential_ref": "secrets/deepseek-routine",
        "endpoint_ref": "config/endpoints/deepseek-routine",
        "timeout_ms": 6000,
        "token_budget": 2048,
        "cost_tier": "low",
        "enabled": True,
        "version": "1",
    }
    draft = client.put(
        "/api/config/models",
        headers={"x-demo-role": "admin"},
        json={"profiles": [profile]},
    )
    assert draft.status_code == 200
    assert draft.json()["status"] == "draft_staged"

    publish = client.post("/api/config/publish", headers={"x-demo-role": "admin"})
    assert publish.status_code == 200
    assert publish.json()["version"] == "2"

    snapshot = client.get("/api/config/models", headers={"x-demo-role": "admin"}).json()
    assert snapshot["version"] == "2"
    assert snapshot["profiles"]["deepseek-routine"]["timeout_ms"] == 6000
    assert snapshot["profiles"]["deepseek-routine"]["credential_ref"] != profile["credential_ref"]

    rollback = client.post("/api/config/rollback", headers={"x-demo-role": "admin"})
    assert rollback.status_code == 200
    snapshot2 = client.get("/api/config/models", headers={"x-demo-role": "admin"}).json()
    assert snapshot2["version"] == "1"


def test_config_snapshot_masks_credential_ref(client):
    snapshot = client.get("/api/config/models", headers={"x-demo-role": "admin"}).json()
    for profile in snapshot["profiles"].values():
        assert "secrets/" not in profile.get("credential_ref", "")
        assert profile.get("credential_ref") in {None, "****"}


def test_model_test_does_not_mutate_case_state(client):
    before = client.get("/api/metrics").json()
    response = client.post(
        "/api/config/models/test",
        headers={"x-demo-role": "admin"},
        json={
            "task_type": "routine_compliance",
            "data_class": "internal",
            "region": "CN",
            "modality": "text",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["provider"] == "mock"
    after = client.get("/api/metrics").json()
    assert after["counters"].get("cases_received", 0) == before["counters"].get(
        "cases_received", 0
    )
    assert after["counters"].get("model_calls", 0) == before["counters"].get(
        "model_calls", 0
    )
    reviews = client.get("/api/reviews", headers={"x-demo-role": "reviewer"}).json()
    assert reviews["count"] == 0


def test_model_test_rejects_incompatible_route(client):
    response = client.post(
        "/api/config/models/test",
        headers={"x-demo-role": "admin"},
        json={
            "task_type": "multimodal_extraction",
            "data_class": "internal",
            "region": "CN",
            "modality": "text",
        },
    )
    assert response.status_code == 400
    assert "error" in response.json()


def test_errors_never_include_raw_pii_or_secrets(client):
    unknown = client.get("/api/cases/CASE-NOPE", headers={"x-demo-role": "field_rep"})
    assert unknown.status_code == 404
    assert "13800138000" not in unknown.text

    bad_role = client.get("/api/reviews", headers={"x-demo-role": "hacker"})
    assert bad_role.status_code == 403
    assert "error" in bad_role.json()
    assert "hacker" not in bad_role.text

    bad = dict(sample_request_json("normal"))
    bad["content"] = "身份证号13800138000，请勿外泄 sk-1234567890"
    del bad["received_at"]
    invalid = client.post("/api/cases/check", json=bad)
    assert invalid.status_code == 422
    assert "13800138000" not in invalid.text
    assert "sk-1234567890" not in invalid.text


# ---------------------------------------------------------------------------
# Permissions, pluggable sources, attachments (Task: usability upgrade)
# ---------------------------------------------------------------------------


def test_permissions_reflect_server_matrix_per_role(client):
    rep = client.get("/api/permissions", headers={"x-demo-role": "field_rep"}).json()
    admin = client.get("/api/permissions", headers={"x-demo-role": "compliance_admin"}).json()

    assert rep["role"] == "field_rep"
    assert rep["capabilities"]["view_case_summary"] is True
    # A representative can neither review nor publish configuration.
    assert rep["capabilities"]["review_case"] is False
    assert rep["capabilities"]["config_publish"] is False

    assert admin["capabilities"]["review_case"] is True
    assert admin["capabilities"]["config_publish"] is True


def test_permissions_architect_can_draft_but_not_publish(client):
    caps = client.get("/api/permissions", headers={"x-demo-role": "architect"}).json()["capabilities"]
    assert caps["architecture_review"] is True
    assert caps["config_publish"] is False
    assert caps["config_rollback"] is False


def test_permission_gating_is_advisory_not_the_only_check(client):
    """Hiding a control client-side must never be the only barrier."""
    denied = client.post("/api/config/publish", headers={"x-demo-role": "architect"})
    assert denied.status_code == 403


def test_sources_enumerate_pluggable_connectors(client):
    body = client.get("/api/sources", headers={"x-demo-role": "field_rep"}).json()
    ids = {c["connector_id"] for c in body["connectors"]}
    assert {"veeva_crm", "veeva_vault", "manual"} <= ids
    systems = {c["system"] for c in body["connectors"]}
    assert "Veeva CRM" in systems
    # Every connector must declare itself a mock so the UI cannot imply a live tenant.
    assert all(c["mode"] == "mock" for c in body["connectors"])
    assert body["records"]


def test_source_record_is_reread_from_authoritative_store(client):
    body = client.get(
        "/api/sources/veeva_crm/records/CR-2026-0002", headers={"x-demo-role": "field_rep"}
    ).json()
    assert body["record_id"] == "CR-2026-0002"
    assert body["reread"] is True
    assert body["content"]


def test_source_rejects_stale_event_version_with_conflict(client):
    stale = client.get(
        "/api/sources/veeva_crm/records/CR-2026-0002?version=v1",
        headers={"x-demo-role": "field_rep"},
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "stale_source_version"


def test_unknown_source_record_is_not_found(client):
    missing = client.get(
        "/api/sources/veeva_crm/records/CR-NOPE", headers={"x-demo-role": "field_rep"}
    )
    assert missing.status_code == 404


def test_attachment_returns_content_part_without_storing_binary(client):
    body = client.post(
        "/api/attachments",
        headers={"x-demo-role": "field_rep"},
        json={"kind": "image", "filename": "slide.png", "mime_type": "image/png", "size_bytes": 1024},
    ).json()
    part = body["content_part"]
    assert part["type"] == "image_ref"
    assert part["ref"].startswith("mock://attachment/image/")
    # The invariant: no binary is retained server-side.
    assert part["metadata"]["stored"] is False


def test_attachment_rejects_unknown_kind(client):
    bad = client.post(
        "/api/attachments",
        headers={"x-demo-role": "field_rep"},
        json={"kind": "video", "filename": "x.mp4"},
    )
    assert bad.status_code == 400


def test_attachment_routes_case_to_multimodal_profile(client):
    """An image part must resolve a multimodal route rather than failing safe."""
    payload = dict(sample_request_json("normal"))
    payload["content_parts"] = [
        {"type": "image_ref", "ref": "mock://attachment/image/abc", "metadata": {"stored": False}}
    ]
    payload["idempotency_key"] = "idem-multimodal-1"
    body = client.post("/api/cases/check", json=payload).json()
    assert body["status"] != "FAILED_SAFE"
    assert body["model_profile_id"] == "minimax-multimodal"


def test_case_response_exposes_rag_retrieval_trace(client):
    body = client.post("/api/cases/check", json=sample_request_json("normal")).json()
    retrieval = body["retrieval"]
    stages = [stage["stage"] for stage in retrieval["stages"]]
    assert stages == ["query_build", "metadata_filter", "lexical_score", "stance_split"]
    # Narrowing must be observable, not asserted.
    assert retrieval["stages"][0]["candidates_in"] >= retrieval["stages"][-1]["candidates_out"]
    assert retrieval["query_tokens"]
    assert retrieval["snapshot_id"].startswith("snap-")


def test_rag_trace_records_why_evidence_was_excluded(client):
    body = client.post("/api/cases/check", json=sample_request_json("normal")).json()
    chunks = body["retrieval"]["chunks"]
    reasons = {chunk["excluded_reason"] for chunk in chunks if not chunk["selected"]}
    assert reasons <= {"metadata_filter", "no_lexical_match", "non_release_source"}
    assert any(chunk["selected"] for chunk in chunks)


def test_findings_carry_rule_provenance_for_readable_explanations(client):
    body = client.post("/api/cases/check", json=sample_request_json("ae")).json()
    ae = [f for f in body["findings"] if f["type"] == "potential_adverse_event"][0]
    assert ae["rule_id"] == "CN-001"
    assert "皮疹" in ae["matched_terms"]
    assert ae["sla_label"] == "8h"
    assert "pharmacovigilance" in ae["required_roles"]


# ---------------------------------------------------------------------------
# Pharma-professional layers: PV/ICSR, signatures, governance, SOP binding
# ---------------------------------------------------------------------------


def test_case_response_carries_icsr_assessment(client):
    body = client.post("/api/cases/check", json=sample_request_json("redline")).json()
    icsr = body["icsr"]
    assert icsr["is_safety_relevant"] is True
    assert icsr["seriousness"] == "life_threatening"
    assert icsr["expedited"] is True
    assert icsr["reporting_clock_days"] == 7
    assert icsr["submission_due"]
    assert icsr["criteria_met_count"] == 4


def test_non_serious_case_is_aggregate_reported(client):
    body = client.post("/api/cases/check", json=sample_request_json("ae")).json()
    icsr = body["icsr"]
    assert icsr["seriousness"] == "non_serious"
    assert icsr["expedited"] is False
    assert icsr["reporting_clock_days"] is None


def test_on_label_case_is_not_safety_relevant(client):
    body = client.post("/api/cases/check", json=sample_request_json("normal")).json()
    assert body["icsr"]["is_safety_relevant"] is False


def test_review_decision_is_electronically_signed(client):
    """Every recorded decision must carry a Part 11-style manifestation."""
    client.post("/api/cases/check", json=sample_request_json("ae"))
    tasks = client.get("/api/reviews", headers={"x-demo-role": "pv_reviewer"}).json()["tasks"]
    task_id = tasks[0]["task_id"]
    record = client.post(
        f"/api/reviews/{task_id}/decision",
        headers={"x-demo-role": "pv_reviewer"},
        json={"decision": "escalated", "reason": "依据 CN-001 转药物警戒随访。"},
    ).json()
    sig = record["signature"]
    assert sig["signer_role"] == "pv_reviewer"
    assert sig["meaning"] == "escalated_for_further_review"
    assert sig["content_digest"].startswith("sha256:")
    # Honest about strength: no identity provider in the demo.
    assert sig["signature_kind"] == "demo_manifestation"


def test_audit_trail_requires_audit_export_permission(client):
    assert client.get("/api/audit-trail", headers={"x-demo-role": "qa"}).status_code == 200
    assert client.get("/api/audit-trail", headers={"x-demo-role": "auditor"}).status_code == 200
    assert client.get("/api/audit-trail", headers={"x-demo-role": "field_rep"}).status_code == 403
    assert client.get("/api/audit-trail", headers={"x-demo-role": "msl"}).status_code == 403


def test_audit_trail_declares_alcoa_integrity_model(client):
    client.post("/api/cases/check", json=sample_request_json("pii"))
    body = client.get("/api/audit-trail", headers={"x-demo-role": "qa"}).json()
    model = body["integrity_model"]
    for key in ("attributable", "legible", "contemporaneous", "original", "accurate"):
        assert model[key]
    assert body["events"]
    assert body["total"] >= len(body["events"])


def test_connector_register_exposes_governance_attributes(client):
    body = client.get("/api/connectors", headers={"x-demo-role": "qa"}).json()
    crm = [c for c in body["connectors"] if c["connector_id"] == "veeva_crm"][0]
    assert crm["vendor"] == "Veeva Systems"
    assert crm["auth_mode"] == "oauth2_client_credentials"
    assert crm["data_residency"] == "CN"
    assert crm["sop_ref"]
    assert crm["retention_period"]
    # No CSV claim is made anywhere in this demo.
    assert crm["validation_status"] == "not_validated"
    # A credential reference is a pointer, never a secret value.
    assert crm["credential_ref"].startswith("vault://")


def test_permissions_expose_governing_sop_per_action(client):
    body = client.get("/api/permissions", headers={"x-demo-role": "qppv"}).json()
    assert body["sop_refs"]["icsr_submit"] == "SOP-PV-003"
    assert body["sop_refs"]["audit_export"] == "SOP-QA-018"


def test_qppv_alone_may_release_an_icsr_submission(client):
    qppv = client.get("/api/permissions", headers={"x-demo-role": "qppv"}).json()["capabilities"]
    pv = client.get("/api/permissions", headers={"x-demo-role": "pv_reviewer"}).json()["capabilities"]
    msl = client.get("/api/permissions", headers={"x-demo-role": "msl"}).json()["capabilities"]
    assert qppv["icsr_submit"] is True
    assert pv["icsr_submit"] is False
    assert msl["icsr_submit"] is False


def test_qa_sees_validation_posture_but_cannot_publish_config(client):
    caps = client.get("/api/permissions", headers={"x-demo-role": "qa"}).json()["capabilities"]
    assert caps["validation_review"] is True
    assert caps["audit_export"] is True
    assert caps["config_publish"] is False
    assert caps["review_case"] is False


def test_mlr_reviewer_approves_material_but_is_not_a_pv_function(client):
    caps = client.get("/api/permissions", headers={"x-demo-role": "mlr_reviewer"}).json()["capabilities"]
    assert caps["mlr_approve"] is True
    assert caps["review_case"] is True
    assert caps["pv_review"] is False
    assert caps["icsr_submit"] is False


# ---------------------------------------------------------------------------
# Professional review queue scope: business judgement vs. platform security
# ---------------------------------------------------------------------------


def test_review_queue_excludes_platform_security_tasks_by_default(client):
    """A medical reviewer cannot action a prompt-injection block."""
    client.post("/api/cases/check", json=sample_request_json("injection"))
    client.post("/api/cases/check", json=sample_request_json("ae"))
    body = client.get("/api/reviews", headers={"x-demo-role": "reviewer"}).json()
    assert body["scope"] == "business"
    roles = {task["required_role"] for task in body["tasks"]}
    assert "security" not in roles
    assert "admin" not in roles
    # Business review work is still present.
    assert roles & {"pharmacovigilance", "medical_review", "compliance", "representative"}


def test_review_queue_scope_all_still_returns_security_tasks(client):
    """Excluding from the business queue must not delete the work."""
    client.post("/api/cases/check", json=sample_request_json("injection"))
    body = client.get("/api/reviews?scope=all", headers={"x-demo-role": "reviewer"}).json()
    assert body["scope"] == "all"
    assert "security" in {task["required_role"] for task in body["tasks"]}
    assert body["technical_count"] >= 1


def test_injection_case_is_still_blocked_after_queue_filtering(client):
    """The safety-critical invariant: filtering the queue never softens a decision."""
    body = client.post("/api/cases/check", json=sample_request_json("injection")).json()
    assert body["decision"] == "blocked"
    types = {finding["type"] for finding in body["findings"]}
    assert "prompt_injection" in types
    severities = {f["severity"] for f in body["findings"] if f["type"] == "prompt_injection"}
    assert severities == {"S0"}


def test_security_findings_remain_in_the_audit_trail(client):
    """A suppressed queue row must still be fully auditable."""
    case = client.post("/api/cases/check", json=sample_request_json("injection")).json()
    trail = client.get(
        f"/api/audit-trail?case_id={case['case_id']}", headers={"x-demo-role": "auditor"}
    ).json()
    assert trail["count"] > 0
    event_types = {event["event_type"] for event in trail["events"]}
    assert "review_task_created" in event_types
