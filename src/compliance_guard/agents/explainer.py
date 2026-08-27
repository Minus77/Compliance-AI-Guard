"""Constrained explanation agent.

Explanations are assembled from server-owned facts only: policy rule reasons,
review routing, and evidence IDs that exist in the EvidencePack. Model output and
content are never echoed as instructions, and explanations never reveal model
registry, routes, mappings, endpoints, or credentials.
"""

from __future__ import annotations

from typing import Any

from compliance_guard.knowledge.evidence_pack import EvidencePack


def explain_policy_result(policy_result: Any, evidence_pack: EvidencePack | None = None) -> str:
    """Build a short, audit-safe explanation from server-controlled facts."""
    reasons = list(getattr(policy_result, "reasons", []) or [])
    lines = [f"decision={getattr(policy_result, 'decision', None)}"]
    lines.append(f"severity={getattr(policy_result, 'severity', None)}")
    lines.append(f"policy_version={getattr(policy_result, 'policy_version', None)}")
    if reasons:
        lines.append("reasons: " + "; ".join(reasons))

    evidence_ids = sorted({item.evidence_id for item in (evidence_pack.items if evidence_pack else [])})
    if evidence_ids:
        lines.append("evidence: " + ", ".join(evidence_ids))
    else:
        lines.append("evidence: none (explicit gap)")

    routing = getattr(policy_result, "routing", None)
    if routing is not None:
        roles = [role.value for role in getattr(routing, "required_roles", [])]
        lines.append("review_roles: " + ", ".join(roles) if roles else "review_roles: none")
        lines.append(f"route_version={getattr(routing, 'route_version', None)}")
    return "\n".join(lines)


__all__ = ["explain_policy_result"]
