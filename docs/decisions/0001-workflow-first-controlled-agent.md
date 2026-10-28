# 1. Workflow-first controlled agent

**English** · [简体中文](../zh/decisions/0001-workflow-first-controlled-agent.md)

Date: 2026-08-20

Amended: 2026-10-28

## Status

Accepted

## Context

Medical content checking and AI conversation guarding affect patient safety,
personal data, evidence accuracy, professional review, and release permission. A
false `allow` can let an unsafe statement leave the organization.

An open agent that chooses its own tools, state transitions, and final release
verdict makes each of those outcomes depend on a prompt. That design is difficult
to reproduce, inspect, replay, or defend to the person who signs the decision.

The product now serves two entries: checks for submitted content and protection for
AI conversations. Both need one rule library, one finding schema, one review queue,
and one audit chain. Their entry-specific controls differ, so the workflow also needs
explicit scope for content, input, generation, and output.

## Decision

Control flow lives in deterministic server code and state machines. Rules, policy
precedence, permissions, evidence admissibility, schema validation, human review,
and audit determine routing and release.

The model is limited to bounded semantic work: reading language, extracting
structured fields, proposing findings, and drafting a candidate response. It cannot
set the final decision, severity, approval status, review route, release permission,
or tool permissions.

Content checks, AI input, and AI output share policy evaluation and findings. Rule
scope constrains which rules apply at each entrypoint. The AI path adds server-bound
conversation sessions:

- Input is checked before model access.
- Generation uses the server-held checked prompt, actor, tenant, source hash, rule
  version, and expiry.
- Output is buffered and checked before release.
- A prompt, actor, tenant, or rule-version change requires rechecking.

Failure closes the path. Provider failure, malformed output, masking failure,
permission denial, missing evidence, or audit-write failure cannot become approval.
Unsafe output remains withdrawn. `MANUAL_DEGRADED`, `FAILED_RETRYABLE`, and
`FAILED_SAFE` remain visible and cannot transition to `ALLOWED`.

Roles use neutral professional capabilities such as author, reviewer, safety
reviewer, medical reviewer, legal reviewer, auditor, architect, and administrator.
Rules require role sets rather than a particular organizational job title. The
content model uses generic types and optional caller metadata; external record ids
do not participate in policy decisions.

## Consequences

- High-risk paths can hold, fail safely, route to a person, and be replayed from
  immutable versions.
- The same risk cannot acquire different meanings because it entered through
  content checking or AI conversation.
- Reviewers can inspect the exact rule, evidence, source span, profile, and policy
  version behind a result.
- New models and providers integrate behind a versioned gateway without gaining
  release authority.
- The service needs more engineering than an unconstrained chat call, and a poor
  rule remains a rule defect. Prompt changes do not repair it.
- The model can still produce useful candidates while final authority remains
  attributable, testable, and reversible.
- Review workload and automation bias remain operational constraints. Oversight
  must be measured in both directions rather than assumed.
