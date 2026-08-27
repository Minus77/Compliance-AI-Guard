# 1. Workflow-first controlled agent

Date: 2026-08-20

## Status

Accepted

## Context

Pharma compliance pre-check touches patient safety, personal data, off-label
promotion, commercial redlines, evidence versioning, professional review, and
audit. A wrong `allow` is not a bad answer; it is a released statement that should
not have left the building.

An open multi-agent design, where the agent chooses its own steps, tools, and
final release verdict, makes each of those outcomes a probabilistic function of a
prompt. That is hard to verify, hard to replay, and hard to explain to a reviewer
who has to sign the decision.

## Decision

Control flow lives in a deterministic orchestrator and state machine. Final routing
is controlled by rules, permissions, evidence packs, schema validation, and human
review.

The model is scoped to bounded semantic work: reading Chinese narrative,
structured extraction, candidate findings, and evidence explanation. It cannot set
decision, severity, routing, approval status, or tool permissions.

## Consequences

- High-risk paths can fail safe, hand off to a human, and be replayed from
  immutable snapshot ids.
- New models, tasks, and providers integrate through the model gateway and versioned
  policy without changing the final compliance gate.
- More engineering than a single chat call, and the model cannot rescue a case the
  rules get wrong — a false positive needs a rule fix, not a better prompt. The
  appeal channel and feedback loop exist because of this tradeoff.
- Reviewer trust becomes the real constraint, which is why oversight is measured in
  both directions rather than assumed.
