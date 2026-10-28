# Security and Risk

**English** · [简体中文](zh/security-and-risk.md)

Trust boundaries, the AI risk register, and the controls that mitigate each risk.
The controls correspond to the implemented service and its regression suite.

## 1. Trust boundaries

Three boundaries matter in every request:

| Boundary | Rule | Enforced by |
| --- | --- | --- |
| **Client → check service** | Content and claims are untrusted data. The server derives identity, tenant, policy scope, severity, routing, and release permission | Session or demo-role resolution, tenant checks, request schemas, reserved-field rejection, deterministic policy |
| **Check service → model** | Prompt injection is scanned and identifiers are masked before external model access. Only bounded facts and the server-held safe input are sent | Injection scanner, entity resolution, span-only masking, data-class routing, profile validation |
| **Model candidate → publication** | Model output cannot set a decision or release itself. The complete candidate must pass schema validation and the output policy check | Bounded gateway, output buffering, policy engine, audit-before-release |

Connector responses and imported rule files are untrusted inputs inside the first
boundary. Rules are schema-validated and connector records are re-read by id and
version. A response that names a role, route, tool, or approval does not acquire
that authority.

## 2. AI risk register

L = likelihood, I = impact.

| # | Risk | L | I | Control |
| --- | --- | --- | --- | --- |
| R1 | Model hallucination | M | H | Candidate-only output; schema validation; deterministic policy; S0/S1 evidence requirements |
| R2 | Stale or cross-version evidence | M | H | Snapshot ids; current-version retrieval; cross-version release gate |
| R3 | Missed adverse-event signal | M | H | CN-001 and CN-002 safety patterns; safety and medical routing; no automatic regulatory submission |
| R4 | Personal or health data leakage | M | H | Entity resolution and span-only masking before model access; CN-006/007 S1 and CN-008 S0 controls |
| R5 | Prompt injection | H | H | Scan before model access; CN-005 S0 block; attempted tool or route changes are recorded and never executed |
| R6 | Evidence gap or retrieval poisoning | M | M | Closed-world retrieval; admissibility checks; explicit `needs_info` or review; no silent allow |
| R7 | Provider outage, timeout, or malformed output | M | M | Failure-safe states; bounded retries; manual takeover; no unchecked publication |
| R8 | Wrong model for the task | L | M | Published task route checked on capability, region, data class, and enabled state |
| R9 | Duplicate external event | M | M | Idempotency keyed by `(tenant_id, event_id)`; deterministic records; visible dead-letter replay |
| R10 | Queue overload | L | M | Bounded aggregate metrics; severity/SLA ordering; degraded cases still create work |
| R11 | Bad model-policy publication | L | H | Versioned draft validation; administrator-only publish and rollback; audit event |
| R12 | Commercial inducement | H | H | CN-003 detects bribery or inducement wording, blocks release, and routes to compliance and legal |
| R13 | Wrong reviewer or role | M | M | Rule-level required roles and SLA; one review task per required role; server permission check |
| R14 | Automation bias | M | H | Override-rate floor alarm; abandonment signal; S0/S1 cannot be self-approved |
| R15 | Data residency or cross-border access | M | H | Tenant and market filtering; region-constrained profiles; synthetic repository data; zero network calls in mock mode |
| R16 | Audit tampering | L | H | Append-only hash chain; verification endpoint; no purge path |
| R17 | Self-declared identity | M | H | Server sessions; demo role headers accepted only under `DEMO_MODE`; protected APIs check permission |

## 3. Input, generation, and output

An AI request traverses three stages:

1. **Input** — scan injection, resolve and mask identifiers, apply entrypoint
   rules, and stop before the model when the decision is `blocked`.
2. **Generation** — create a 15-minute server session bound to actor, tenant,
   inspected source hash, rule version, safe input, and allowed constraints. Only
   the same checked prompt may generate.
3. **Output** — buffer the complete candidate, validate its schema, and apply the
   shared policy plus output-scoped rules. Release only when the overall decision
   is `allow` and every finding permits publication.

A blocked output is withdrawn. Its model text is not echoed as part of the safe
response. An output-check exception returns `failed_safe` or a manual-degraded
state. No failure path publishes unchecked text.

The generated response may propose facts and wording. It cannot decide severity,
the final disposition, review route, approval, or tool permission. Prompt changes,
actor changes, tenant changes, expired sessions, and rule-version changes all
invalidate the authorization to generate.

## 4. Masking: both failure directions

Under-masking leaks an identifier. Over-masking damages the narrative and can
remove an adverse-event word before the safety rules read it. Both are release
gates with a floor of 1.0.

- Names and identifiers are replaced only at selected entity spans.
- Entity resolution runs before masking so aliases of one person receive one
  stable token.
- Uncertain identity merges become `needs_info`; the system does not silently
  combine two possible people.
- Masking recall and source fidelity are measured separately. A perfect recall
  score cannot compensate for deleted symptoms.
- The mapping from a token back to a person is restricted operational data and is
  absent from model requests and default audit payloads.

## 5. Injection and model-boundary defence

The injection scan runs before model access. CN-005 is S0, `blocked`, and routed
for immediate security or compliance handling. Known injection cases are quarantined
from prompt tuning, and a single dangerous `allow` fails the release report.

Content can attempt to change routes, call tools, reveal prompts, change a
decision, or name a privileged role. These strings remain data. Server routing is
resolved from trusted configuration, and no tool edge exists from model output to
release permission.

Masking and injection scanning also apply to output where the rule scope requires
it. Output buffering prevents partial publication before the complete candidate is
checked.

## 6. Review, signatures, and override

Review tasks are created from findings and required roles. A reviewer may agree,
request information, block, or escalate with a reason. S0 and S1 findings cannot be
self-approved. A signature manifestation is bound to the reviewed content version;
editing the content invalidates the prior decision.

The review queue preserves the underlying decision, finding, tasks, and audit
events. A filtered queue hides work from a view; it does not delete evidence.

Oversight is measured in both directions. The system tracks whether reviewers trust
the tool enough to use it and whether work is being corrected or abandoned. Both
false positives and missed risks can become regression candidates after a second
person confirms them.

## 7. Data integrity and audit

The audit log is an append-only hash chain. Each record includes the prior hash, a
canonical safe payload, and a digest. `GET /api/audit-trail/verify` identifies the
first position that cannot be verified.

Default audit records contain:

- Actor and tenant identifiers, request identifiers, and time.
- Entrypoint, content type, policy and rule versions, and safe content hashes.
- Decisions, severities, finding references, review routes, and model profile ids.
- Model-call status, timing, output-check status, withdrawal, and failure category.

They do not contain raw source text, complete model output, sensitive entity values,
token-to-identity mappings, system prompts, or credentials. Audit access and audit
export are separately authorised.

Audit-before-release is a control. If the audit event cannot be written, the release
operation fails. A successful release without the corresponding audit event would
break both traceability and attribution.

## 8. Secrets and connectors

Model credentials live in environment variables or a gitignored secret file.
Profiles store references and redacted values. Draft validation rejects plaintext
secrets and literal provider endpoints. Published configuration is versioned.

Optional content-source, safety-intake, and review-export connectors are separate
trust boundaries. They declare capabilities, data classes, permitted actions, and
health. Event delivery is a notification; the server re-reads an authoritative
source by record id and version. Connector failure never turns missing evidence or
a safety signal into approval.

## 9. Scope and non-claims

This repository is a working reference for medical content and AI conversation
controls. It does not claim GxP/CSV qualification, regulatory approval,
pharmacovigilance validation, or fitness for a particular market. Repository data
is synthetic.

The local identity store, JSON persistence, mock connectors, and demonstration
views are not a production validation package. A deployed system needs its own
threat model, identity integration, retention design, monitoring, access review,
backup and recovery plan, and qualified validation evidence.
