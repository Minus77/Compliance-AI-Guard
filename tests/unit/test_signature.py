"""21 CFR Part 11-style signature manifestation: content, binding, verification."""

from datetime import UTC, datetime

import pytest

from compliance_guard.audit.signature import (
    SIGNATURE_MEANINGS,
    content_digest,
    sign_record,
    verify_signature,
)
from compliance_guard.domain.enums import Role
from compliance_guard.domain.models import Actor

SIGNED_AT = datetime(2026, 8, 24, 3, 0, tzinfo=UTC)


def _actor(role=Role.QPPV):
    return Actor(actor_id=f"demo-{role.value}", role=role)


def _bound(reason="依据 CN-001 转药物警戒随访。"):
    return {
        "task_id": "review-1",
        "case_id": "CASE-1",
        "after_decision": "human_review",
        "reason": reason,
    }


def test_signature_carries_the_three_part_11_elements():
    """11.50 requires printed name, date/time, and the meaning of the signing."""
    sig = sign_record(
        actor=_actor(),
        action="escalated",
        reason="转药物警戒随访",
        record_type="review_decision",
        record_id="decision-1",
        signed_at=SIGNED_AT,
        bound_fields=_bound(),
    )
    assert sig.signer_name == "demo-qppv"          # printed name of the signer
    assert sig.signed_at == SIGNED_AT              # date and time of signing
    assert sig.meaning == "escalated_for_further_review"   # meaning of signing
    assert sig.signer_role == "qppv"
    assert sig.record_id == "decision-1"


def test_signature_is_bound_to_the_record_and_verifies():
    bound = _bound()
    sig = sign_record(
        actor=_actor(),
        action="rejected",
        reason="缺少证据",
        record_type="review_decision",
        record_id="decision-2",
        signed_at=SIGNED_AT,
        bound_fields=bound,
    )
    assert verify_signature(sig, bound) is True


def test_tampering_with_a_bound_field_fails_verification():
    """A signature must not survive being transferred to different content."""
    sig = sign_record(
        actor=_actor(),
        action="rejected",
        reason="缺少证据",
        record_type="review_decision",
        record_id="decision-3",
        signed_at=SIGNED_AT,
        bound_fields=_bound(),
    )
    tampered = _bound()
    tampered["after_decision"] = "allow"
    assert verify_signature(sig, tampered) is False


def test_digest_is_stable_regardless_of_key_order():
    a = {"case_id": "CASE-1", "reason": "r", "after_decision": "blocked"}
    b = {"after_decision": "blocked", "case_id": "CASE-1", "reason": "r"}
    assert content_digest(a) == content_digest(b)


@pytest.mark.parametrize(
    "action,meaning",
    [
        ("accepted", "approved_for_release"),
        ("rejected", "rejected_blocked_from_release"),
        ("escalated", "escalated_for_further_review"),
        ("needs_info", "returned_for_additional_information"),
    ],
)
def test_every_review_action_has_an_explicit_meaning(action, meaning):
    assert SIGNATURE_MEANINGS[action] == meaning


def test_unknown_action_falls_back_to_reviewed_not_approved():
    """An unmapped action must never silently mean 'approved'."""
    sig = sign_record(
        actor=_actor(),
        action="some_new_action",
        reason="r",
        record_type="review_decision",
        record_id="decision-4",
        signed_at=SIGNED_AT,
        bound_fields=_bound(),
    )
    assert sig.meaning == "reviewed"


def test_signature_strength_is_declared_honestly():
    """The demo has no IdP or second factor; the record must say so."""
    sig = sign_record(
        actor=_actor(),
        action="accepted",
        reason="r",
        record_type="review_decision",
        record_id="decision-5",
        signed_at=SIGNED_AT,
        bound_fields=_bound(),
    )
    assert sig.signature_kind == "demo_manifestation"
