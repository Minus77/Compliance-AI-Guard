"""21 CFR Part 11-style electronic signature manifestation.

Part 11 (11.50 / 11.70) requires that a signed electronic record carry, in
human-readable form:

  1. the printed name of the signer,
  2. the date and time of signing,
  3. the **meaning** of the signature (reviewed / approved / rejected ...),

and that the signature be linked to its record so it cannot be excised,
copied, or transferred to falsify another record.

This module builds that manifestation and binds it to the record with a
SHA-256 digest over the signed content. Changing any bound field changes the
digest, so tampering is detectable by re-verification.

**Scope.** This is a demo of the *shape* of a compliant signature: the demo has
no real identity provider, so there is no second authentication factor and no
certificate. It is explicitly NOT a validated Part 11 implementation and makes
no CSV/GxP claim. `signature_kind` records this honestly as
``"demo_manifestation"`` so a reviewer is never misled about its strength.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime

from pydantic import Field

from compliance_guard.domain.models import Actor, DomainModel

# The meaning of the signing, per 11.50(a)(3). Displayed verbatim to the signer.
SIGNATURE_MEANINGS: dict[str, str] = {
    "accepted": "approved_for_release",
    "approved": "approved_for_release",
    "rejected": "rejected_blocked_from_release",
    "denied": "rejected_blocked_from_release",
    "escalated": "escalated_for_further_review",
    "needs_info": "returned_for_additional_information",
}


class ElectronicSignature(DomainModel):
    """A human-readable, record-bound signature manifestation."""

    signature_id: str = Field(default_factory=lambda: f"esig-{uuid.uuid4().hex}")
    signer_id: str
    signer_role: str
    signer_name: str
    signed_at: datetime
    meaning: str
    reason: str
    record_type: str
    record_id: str
    content_digest: str
    # Honest strength marker: no IdP, no second factor, no certificate here.
    signature_kind: str = "demo_manifestation"


def content_digest(payload: dict) -> str:
    """Stable SHA-256 over the signed content, binding signature to record."""
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sign_record(
    *,
    actor: Actor,
    action: str,
    reason: str,
    record_type: str,
    record_id: str,
    signed_at: datetime,
    bound_fields: dict,
) -> ElectronicSignature:
    """Produce a signature manifestation bound to ``bound_fields``."""
    meaning = SIGNATURE_MEANINGS.get(str(action).casefold(), "reviewed")
    return ElectronicSignature(
        signer_id=actor.actor_id,
        signer_role=actor.role.value,
        # Demo identities have no directory name; the actor id is the printed name.
        signer_name=actor.actor_id,
        signed_at=signed_at,
        meaning=meaning,
        reason=reason,
        record_type=record_type,
        record_id=record_id,
        content_digest=content_digest(bound_fields),
    )


def verify_signature(signature: ElectronicSignature, bound_fields: dict) -> bool:
    """Re-derive the digest and confirm the signature still matches the record."""
    return signature.content_digest == content_digest(bound_fields)


__all__ = [
    "SIGNATURE_MEANINGS",
    "ElectronicSignature",
    "content_digest",
    "sign_record",
    "verify_signature",
]
