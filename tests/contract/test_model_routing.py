"""Task-level model routing: registry, drafts, publish/rollback, and classifier."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from compliance_guard.agents.classifier import classify_task
from compliance_guard.domain.enums import (
    AdapterType,
    ContentPartType,
    DataClass,
    Decision,
    Modality,
    Role,
    SecurityAction,
    Severity,
    TaskType,
)
from compliance_guard.domain.models import (
    Actor,
    CheckCaseRequest,
    ContentPart,
    ModelProfile,
    SecurityFinding,
    TaskRoute,
)
from compliance_guard.llm.registry import (
    DraftValidationError,
    ModelRegistry,
    RouteValidationError,
)
from compliance_guard.policy.engine import PolicyFinding, PolicyResult

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
PROMPTS_DIR = CONFIG_DIR / "prompts"


def _request(content_parts=None) -> CheckCaseRequest:
    return CheckCaseRequest(
        case_id="case-route-1",
        tenant_id="TENANT-CN",
        content="synthetic content",
        content_parts=content_parts or [],
        source="customer_interaction_note",
        market="CN",
        language="zh-CN",
        product_id="PRODUCT-001",
        channel="customer_interaction_note",
        received_at=datetime(2026, 1, 1, tzinfo=UTC),
        idempotency_key="idem-route-1",
    )


def _policy_result(*finding_types: str) -> PolicyResult:
    findings = [
        PolicyFinding(
            finding_id=f"finding-{index}",
            type=finding_type,
            severity=Severity.S2,
            decision=Decision.HUMAN_REVIEW,
            rule_id=f"R-{index}",
        )
        for index, finding_type in enumerate(finding_types)
    ]
    return PolicyResult(
        decision=Decision.HUMAN_REVIEW,
        severity=Severity.S2,
        findings=findings,
        policy_version="CN-COMPLIANCE-2026-01",
    )


def test_multimodal_task_uses_minimax(registry):
    route = registry.resolve(
        TaskType.MULTIMODAL_EXTRACTION, modality="image", data_class="pii_tokenized", region="CN"
    )
    assert route.primary_profile.provider == "minimax"


def test_routine_task_uses_deepseek(registry):
    route = registry.resolve(
        TaskType.ROUTINE_COMPLIANCE, modality="text", data_class="pii_tokenized", region="CN"
    )
    assert route.primary_profile.provider == "deepseek"


def test_complex_task_uses_kimi(registry):
    route = registry.resolve(
        TaskType.COMPLEX_EVIDENCE_REASONING, modality="text", data_class="internal", region="CN"
    )
    assert route.primary_profile.provider == "kimi"


def test_route_rejects_profile_without_required_capability(registry):
    with pytest.raises(RouteValidationError):
        registry.resolve(
            TaskType.MULTIMODAL_EXTRACTION, modality="image", data_class="phi_tokenized", region="EU"
        )


def test_route_rejects_unknown_task_type(registry):
    with pytest.raises(RouteValidationError):
        registry.resolve("bogus_task", modality="text", data_class="internal", region="CN")


def test_route_rejects_unpublished_task_type(registry):
    with pytest.raises(RouteValidationError):
        registry.resolve("make_believe", modality="text", data_class="internal", region="CN")


def test_fallback_only_from_published_profiles(registry):
    ghost = ModelProfile(
        profile_id="ghost-fallback",
        provider="kimi",
        display_name="Ghost",
        model_id="Ghost",
        adapter_type=AdapterType.MOCK,
        capabilities=[Modality.TEXT],
        allowed_data_classes=[DataClass.INTERNAL],
        region="CN",
    )
    registry.draft(ghost)
    route = registry.resolve(
        TaskType.ROUTINE_COMPLIANCE, modality="text", data_class="internal", region="CN"
    )
    resolved_ids = [route.primary_profile.profile_id] + [
        profile.profile_id for profile in route.fallback_profiles
    ]
    assert "ghost-fallback" not in resolved_ids


def test_published_fallback_is_resolvable(registry, admin_actor):
    fallback = ModelProfile(
        profile_id="kimi-backup",
        provider="kimi",
        display_name="Kimi Backup",
        model_id="Kimi K3",
        adapter_type=AdapterType.MOCK,
        capabilities=[Modality.TEXT],
        allowed_data_classes=[DataClass.INTERNAL, DataClass.PII_TOKENIZED],
        region="CN",
    )
    registry.draft(fallback)
    route_draft = TaskRoute(
        task_type=TaskType.ROUTINE_COMPLIANCE,
        primary_profile_id="deepseek-routine",
        fallback_profile_ids=["kimi-backup"],
        required_capabilities=[Modality.TEXT],
        allowed_regions=["CN"],
        allowed_data_classes=[DataClass.PII_TOKENIZED, DataClass.INTERNAL],
        max_attempts=1,
        requires_human_on_failure=True,
        route_version="routes-v2",
    )
    registry.draft(route_draft)
    registry.validate_draft()
    registry.publish(admin_actor)
    resolved = registry.resolve(
        TaskType.ROUTINE_COMPLIANCE, modality="text", data_class="internal", region="CN"
    )
    assert "kimi-backup" in [p.profile_id for p in resolved.fallback_profiles]


def test_draft_rejects_unknown_profile_reference(registry):
    bad = TaskRoute(
        task_type=TaskType.ROUTINE_COMPLIANCE,
        primary_profile_id="no-such-profile",
        required_capabilities=[Modality.TEXT],
        allowed_regions=["CN"],
        allowed_data_classes=[DataClass.INTERNAL],
        route_version="routes-v2",
    )
    registry.draft(bad)
    with pytest.raises(DraftValidationError):
        registry.validate_draft()


def test_draft_rejects_incompatible_capability(registry):
    bad = TaskRoute(
        task_type=TaskType.ROUTINE_COMPLIANCE,
        primary_profile_id="deepseek-routine",
        required_capabilities=[Modality.VISION],
        allowed_regions=["CN"],
        allowed_data_classes=[DataClass.INTERNAL],
        route_version="routes-v2",
    )
    registry.draft(bad)
    with pytest.raises(DraftValidationError):
        registry.validate_draft()


def test_draft_rejects_incompatible_region(registry):
    us_profile = ModelProfile(
        profile_id="us-profile",
        provider="deepseek",
        display_name="US",
        model_id="US",
        adapter_type=AdapterType.MOCK,
        capabilities=[Modality.TEXT],
        allowed_data_classes=[DataClass.INTERNAL],
        region="US",
    )
    registry.draft(us_profile)
    route_draft = TaskRoute(
        task_type=TaskType.ROUTINE_COMPLIANCE,
        primary_profile_id="us-profile",
        required_capabilities=[Modality.TEXT],
        allowed_regions=["CN"],
        allowed_data_classes=[DataClass.INTERNAL],
        route_version="routes-v2",
    )
    registry.draft(route_draft)
    with pytest.raises(DraftValidationError):
        registry.validate_draft()


def test_draft_rejects_incompatible_data_class(registry):
    bad = TaskRoute(
        task_type=TaskType.ROUTINE_COMPLIANCE,
        primary_profile_id="deepseek-routine",
        required_capabilities=[Modality.TEXT],
        allowed_regions=["CN"],
        allowed_data_classes=[DataClass.PHI_TOKENIZED],
        route_version="routes-v2",
    )
    registry.draft(bad)
    with pytest.raises(DraftValidationError):
        registry.validate_draft()


def test_publish_produces_monotonic_versions(registry, admin_actor):
    first = registry.current_snapshot().version
    second = registry.publish(admin_actor)
    third = registry.publish(admin_actor)
    assert int(second) == int(first) + 1
    assert int(third) == int(second) + 1


def test_published_routes_are_immutable(registry, admin_actor):
    version_before = registry.current_snapshot().version
    route_before = registry.resolve(
        TaskType.ROUTINE_COMPLIANCE, modality="text", data_class="internal", region="CN"
    )
    registry.publish(admin_actor)
    route_after = registry.resolve(
        TaskType.ROUTINE_COMPLIANCE, modality="text", data_class="internal", region="CN"
    )
    assert route_before.primary_profile.profile_id == route_after.primary_profile.profile_id
    assert route_before.route_version == route_after.route_version
    assert registry.current_snapshot().version != version_before


def test_publish_requires_admin(registry, reviewer_actor):
    with pytest.raises(PermissionError):
        registry.publish(reviewer_actor)


def test_rollback_requires_admin(registry, reviewer_actor):
    with pytest.raises(PermissionError):
        registry.rollback(reviewer_actor)


def test_rollback_restores_previous_version(registry, admin_actor):
    original = registry.current_snapshot().version
    registry.publish(admin_actor)
    registry.publish(admin_actor)
    assert registry.current_snapshot().version != original
    restored = registry.rollback(admin_actor)
    assert restored == str(int(original) + 1)
    registry.rollback(admin_actor)
    assert registry.current_snapshot().version == original


def test_rollback_with_no_history_raises(registry, admin_actor):
    with pytest.raises(DraftValidationError):
        registry.rollback(admin_actor)


def test_runtime_snapshot_is_redacted(registry):
    snapshot = registry.current_snapshot()
    assert snapshot.redacted is True
    dump = snapshot.model_dump()
    serialized = str(dump)
    assert "sk-" not in serialized
    assert "password" not in serialized.casefold()
    for profile in snapshot.profiles.values():
        assert profile.credential_ref is not None
        assert "http" not in (profile.endpoint_ref or "")


def test_classifier_selects_multimodal_for_image_content():
    request = _request([ContentPart(type=ContentPartType.IMAGE_REF, ref="img://1")])
    classification = classify_task(request, [], _policy_result())
    assert classification.task_type is TaskType.MULTIMODAL_EXTRACTION


def test_classifier_selects_multimodal_for_audio_content():
    request = _request([ContentPart(type=ContentPartType.AUDIO_REF, ref="audio://1")])
    classification = classify_task(request, [], _policy_result())
    assert classification.task_type is TaskType.MULTIMODAL_EXTRACTION


def test_classifier_selects_complex_for_evidence_conflict():
    classification = classify_task(_request(), [], _policy_result("evidence_conflict"))
    assert classification.task_type is TaskType.COMPLEX_EVIDENCE_REASONING


def test_classifier_selects_complex_for_off_label():
    classification = classify_task(_request(), [], _policy_result("off_label"))
    assert classification.task_type is TaskType.COMPLEX_EVIDENCE_REASONING


def test_classifier_selects_complex_for_comparative_claim():
    classification = classify_task(_request(), [], _policy_result("comparative_claim"))
    assert classification.task_type is TaskType.COMPLEX_EVIDENCE_REASONING


def test_classifier_selects_routine_for_normal_content():
    classification = classify_task(_request(), [], _policy_result())
    assert classification.task_type is TaskType.ROUTINE_COMPLIANCE

# ---- Fix round 1 regression tests ----

def test_publish_requires_actor(registry):
    with pytest.raises(PermissionError):
        registry.publish()


def test_rollback_requires_actor(registry):
    with pytest.raises(PermissionError):
        registry.rollback()


def test_publish_bootstrap_allows_only_trusted_startup(registry):
    version = registry.publish(bootstrap=True)
    assert int(version) == int(registry.current_snapshot().version)


def test_publish_records_audit_event(registry, admin_actor):
    registry.publish(admin_actor)
    events = registry.audit_events()
    assert len(events) == 1
    assert events[0].event_type == "config_publish"
    assert events[0].actor is not None
    assert events[0].actor.role == Role.ADMIN
    assert events[0].configuration_versions["registry_version"] == "2"


def test_rollback_records_audit_event(registry, admin_actor):
    registry.publish(admin_actor)
    registry.rollback(admin_actor)
    assert [event.event_type for event in registry.audit_events()] == [
        "config_publish",
        "config_rollback",
    ]


def test_published_version_survives_reinstantiation(registry, admin_actor, tmp_path):
    extra = ModelProfile(
        profile_id="extra-profile",
        provider="kimi",
        display_name="Extra",
        model_id="Kimi K3",
        adapter_type=AdapterType.MOCK,
        capabilities=[Modality.TEXT],
        allowed_data_classes=[DataClass.INTERNAL],
        region="CN",
    )
    registry.draft(extra)
    registry.publish(admin_actor)
    assert registry.current_snapshot().version == "2"
    assert registry.profile("extra-profile") is not None

    reloaded = ModelRegistry(
        profiles_path=CONFIG_DIR / "model_profiles.json",
        routes_path=CONFIG_DIR / "task_routes.json",
        runtime_path=tmp_path / "runtime_config.json",
        prompts_dir=PROMPTS_DIR,
    )
    reloaded.load_defaults()
    assert reloaded.current_snapshot().version == "2"
    assert reloaded.profile("extra-profile") is not None


def test_mutating_returned_reference_cannot_corrupt_published_state(registry):
    before = registry.resolve(
        TaskType.ROUTINE_COMPLIANCE, modality="text", data_class="internal", region="CN"
    )
    snapshot = registry.current_snapshot()
    snapshot.profiles["deepseek-routine"].capabilities.append(Modality.VISION)
    snapshot.routes["routine_compliance"].fallback_profile_ids.append("injected-fallback")

    after = registry.resolve(
        TaskType.ROUTINE_COMPLIANCE, modality="text", data_class="internal", region="CN"
    )
    assert after.primary_profile.capabilities == before.primary_profile.capabilities
    assert [p.profile_id for p in after.fallback_profiles] == [
        p.profile_id for p in before.fallback_profiles
    ]


def test_historical_snapshot_survives_publish_and_rollback(registry, admin_actor):
    original = registry.route(TaskType.ROUTINE_COMPLIANCE)
    registry.publish(admin_actor)
    snapshot = registry.current_snapshot()
    snapshot.profiles["deepseek-routine"].capabilities.append(Modality.VISION)
    registry.rollback(admin_actor)
    restored = registry.route(TaskType.ROUTINE_COMPLIANCE)
    assert restored.fallback_profile_ids == original.fallback_profile_ids


def test_published_models_are_frozen(registry):
    profile = registry.profile("deepseek-routine")
    with pytest.raises(ValidationError):
        profile.timeout_ms = 1234
    route = registry.route(TaskType.ROUTINE_COMPLIANCE)
    with pytest.raises(ValidationError):
        route.route_version = "tampered"
