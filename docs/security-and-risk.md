# Security and Risk

**English** · [简体中文](zh/security-and-risk.md)

Trust boundaries, the AI risk register, and the control that mitigates each risk.
Every control listed here is implemented and covered by a test.

## 1. Trust boundaries

Four boundaries, in the order a request crosses them.

| Boundary | Rule | Enforced by |
| --- | --- | --- |
| **Client → server** | Client input is data, never fact or authority. Structured fields become `claimed_fields`; the server derives `resolved_fields` | `claim_discrepancy` (CN-020); reserved keys rejected |
| **Server → model** | Identifiers are masked before the process boundary. The model receives tokens and structured facts, never raw names or label prose | `security/pii_gateway.py`, entity resolution, data-class routing |
| **Model → decision** | Model output is a candidate. It cannot set decision, severity, approval status, routing, or tool permissions | `agents/extractor.py` → schema validation → `policy/engine.py` |
| **Server → external system** | Content is re-read from the source of record; writes require an approval token plus an idempotency key | `integrations/` adapters; no generic admin tool exists |

The third boundary is the one that matters most, and it is structural rather than
prompted: there is no code path from model output to a final verdict.

## 2. Risk register

| # | Risk | L | I | Implemented control |
| --- | --- | --- | --- | --- |
| R1 | Model hallucination | M | H | Candidate-only output; server policy decides; schema validation fails safe; S0/S1 findings must carry evidence refs or an explicit gap |
| R2 | Evidence staleness / cross-version release | M | H | Version-gated retrieval; immutable knowledge snapshot ids; release gate on cross-version release |
| R3 | Missed safety signal (AE/SAE) | M | H | CN-001 / CN-002 with Chinese pattern sets and aliases; PV + medical routing; never auto-submitted to PV |
| R4 | PII/PHI leakage | M | H | Tokenization before the model call; DLP; data-class-aware routing; CN-006/007 (S1), CN-008 (S0) |
| R5 | Prompt injection | H | H | Scan before the model call; CN-005 S0 block; tool/route tamper recorded, never executed; red-team holdout cases |
| R6 | Retrieval poisoning / evidence gap | M | M | Release gating mirrors ingestion gates (source type, active, scope, signed); empty or contradictory packs become explicit gaps, never a silent allow |
| R7 | Provider outage, timeout, bad output | M | M | Fail-safe state machine; every route requires human on failure; fallback profiles |
| R8 | Route drift (wrong model for task) | L | M | Deterministic routing validated per call on capability, region, data class, enabled state; immutable published routes |
| R9 | Duplicate external events | M | M | Idempotent event bus keyed by `(tenant_id, event_id)`; deterministic case ids; DLQ with replay |
| R10 | Queue overload | L | M | Bounded metrics store holding aggregates only; severity/SLA-ordered queue; degraded cases always enqueue a task |
| R11 | Bad model-policy publish | L | H | Versioned registry; admin-gated publish/rollback; draft validation; audited |
| R12 | Commercial redline (bribery/inducement) | H | H | CN-003 with Chinese patterns (回扣/宴请/红包/礼品/好处费); blocked; compliance + legal |
| R13 | Wrong reviewer (RACI misrouting) | M | M | `required_roles` and SLA per rule; review tasks keyed by finding; evaluator checks expected roles per case |
| R14 | Over-trust in the tool (automation bias) | M | H | Override-rate floor alarm; abandonment tracking; S0/S1 cannot be self-approved |
| R15 | Data residency / cross-border | M | H | Tenant/market-filtered retrieval; region-constrained profiles; synthetic data only; no network calls in mock mode |
| R16 | Audit tampering | L | H | Hash-chained ledger; verification endpoint; no purge method, and a test pins its absence |
| R17 | Self-declared identity | M | H | Server sessions replace the role header; `x-demo-role` only under `DEMO_MODE`, refused otherwise |

L = likelihood, I = impact.

## 3. Masking: both failure directions

Under-masking leaks an identifier. Over-masking deletes narrative — and that is
the failure mode that hides risk, because it can strip an adverse-event keyword
before the safety rules read the text.

Both are release gates with a floor of 1.0: **masking recall** (nothing that must
be masked survives) and **source fidelity** (nothing that is not an identifier is
damaged). Neither is a tunable target. There is no acceptable number of unmasked
names, and no acceptable number of deleted symptoms.

Entity resolution adds a third measure: **wrong-merge rate must stay below 0.01**,
tighter than the 0.95 coreference-accuracy target beside it, because merging two
clinicians attributes one person's opinion to another.

## 4. Injection defence

The scan runs **before** the model call, so hostile instructions never reach the
model. A detection is CN-005: S0, `blocked`, routed to security, immediate SLA.

Attempts to tamper with tools or routing are **recorded and routed, never
executed**. Reserved form keys cannot be set from intake. Red-team cases
(G-37..G-42) are quarantined as a never-tune holdout set, and a release gate fails
if any known injection ends in `allow`.

Injection also demonstrates the queue-scope rule below: it stays blocked, but it
does not clutter a medical reviewer's queue.

## 5. Review queue scope

The professional review queue lists only findings a medical or compliance reviewer
can act on. Platform-security work — prompt injection, permission failures,
irreversible-write blocks — routes to security/admin and is excluded from the
default queue. A medical reviewer has no action to take on an injection attempt.

**Excluding a queue row never suppresses a finding.** The decision stays
`blocked`, the finding stays on the case and in the representative's result, the
review task is still created and still written to the ledger, and
`GET /api/reviews?scope=all` returns the security tasks. The response reports
`business_count` and `technical_count`, so the existence of technical work is
visible even when it is not listed. Four tests lock this, including that an
injection case is still blocked after filtering.

## 6. Pharmacovigilance assessment

When a narrative contains an adverse-reaction term, the case carries an ICSR
assessment against the four minimum criteria:

| Criterion | Satisfied by |
| --- | --- |
| Identifiable patient | A patient term, or a tokenized patient entity |
| Identifiable reporter | A reporter term, or the submitting representative |
| Suspect medicinal product | The product in the case context |
| Suspect adverse reaction | A reaction term in the narrative |

Criteria ask whether an identifiable party **exists**, never that the system holds
their identifiers — the assessment runs on the tokenized narrative, so it is
compatible with the masking invariant.

Reporting clock, anchored on first company awareness rather than triage time:

| Seriousness | Clock |
| --- | --- |
| Fatal, life-threatening | 7 calendar days, expedited |
| Other serious (hospitalisation, disability, congenital anomaly) | 15 calendar days, expedited |
| Non-serious | Aggregate reporting, no expedited clock |

**An incomplete ICSR never suppresses a signal.** Missing criteria become a
follow-up task and the case still routes to pharmacovigilance. That is the single
most important behaviour in the module and it is pinned by a test. The panel also
surfaces `assessment_conflict` when the policy engine flagged a safety finding but
the ICSR read is not safety-relevant — a discrepancy a reviewer must see rather
than a silent disagreement.

This is a triage aid, not a safety database, and not regulatory advice. Clock
conventions vary by market and product lifecycle.

## 7. Electronic signatures

Every recorded review decision carries a Part 11-style manifestation with the
three required elements: printed name of the signer, date and time, and the
**meaning** of the signature (approved for release / rejected / escalated /
returned for information).

The signature is bound to the decision with a SHA-256 digest over the signed
content, so it cannot be transferred to different content to falsify a record;
verification fails if any bound field changes.

**Honest about strength.** There is no identity provider, no second factor, and no
certificate, so `signature_kind` is recorded and displayed as
`demo_manifestation`. It demonstrates the shape of a compliant signature and makes
no validation claim.

## 8. Data integrity (ALCOA+)

The quality workspace states how the ledger satisfies attributable, legible,
contemporaneous, original, accurate, and complete/consistent/enduring/available.
Automated pipeline steps are attributed to the system rather than to a person,
which the panel says explicitly instead of implying a human actor.

The interface governance register records, per connector: vendor, interface
version, auth mode, credential *reference* (never a value), data residency, data
classification, validation status, GxP relevance, governing SOP, retention period,
and write capability. Every connector reports `validation_status: not_validated`.

The audit trail is permission-restricted because it names who did what:
`field_rep` and `msl` receive `403`.

## 9. Human oversight, measured in both directions

A high override rate is the obvious alarm. The low one matters just as much: if
reviewers almost never disagree, review may have become a formality, and a
rubber-stamping reviewer looks identical to a flawless system in the record. So the
oversight metric warns **below 2%** as well.

Abandonment is tracked for the same reason — a warning shown, the paragraph
deleted. Nothing is blocked and no finding is raised, so that failure is invisible
in the safety numbers. A falling detection count beside a rising abandonment count
means the rules got tighter, not that risk went away.

S0 and S1 cannot be self-approved, which puts a structural floor under both.

## 10. Secrets

Credentials never enter the repository. Profiles hold a `credential_ref`; the real
key comes from `COMPLIANCE_GUARD_LLM_API_KEY` or the gitignored
`config/secrets/llm.local.json`. Draft validation rejects plaintext secrets and
literal endpoints before publish. Logs and audit payloads carry digests, ids, and
aggregates only. Profile responses redact credential refs to `****`.

## 11. Scope and non-claims

This is an MVP. It demonstrates the *shape* of these controls so the design can be
reviewed; it is not a validated implementation.

- **No claim** of GxP/CSV, PV, MLR, or regulatory validation.
- **No live integration** with any CRM, content vault, or safety system. Adapters
  are contract-only, with `mock://` receipts and an in-memory store; contract tests
  assert no network call by monkeypatching the socket layer.
- The ICSR module is a triage aid, not a safety database.
- Signatures are `demo_manifestation`: no identity provider, no second factor.
- Sessions are a minimal local store, not enterprise SSO.
- Every connector reports `validation_status: not_validated`.
- All data is synthetic or de-identified. No real patient, HCP, or market data.

Nothing here is regulatory advice.
