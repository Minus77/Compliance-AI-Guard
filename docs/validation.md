# Validation

**English** · [简体中文](zh/validation.md)

How the system is measured: test layers, the synthetic golden set, fifteen release
gates, evaluator output, and change control. Results in this document come from an
offline mock-mode run.

## 1. Test strata

The complete suite runs without a live provider:

```text
python -m pytest -q
```

| Layer | Location | Main checks |
| --- | --- | --- |
| Unit | `tests/unit/` | Rule schema and precedence, policy decisions, routing, state machines, masking, signatures, audits, publishing, evidence comparison |
| Contract | `tests/contract/` | Mock gateway determinism, model output schema, routes, source adapters, live adapter failure behaviour and response wrapping without sockets |
| Integration | `tests/integration/` | Shared check API, persisted check lifecycle, AI input and generation, output release, rules, reviews, appeals, audit chain, authorization, precheck, UI contracts |
| Security | `tests/security/` | Injection, model boundary, identifier masking, source fidelity, entity resolution, session binding, client trust boundary, permission bypass, output withdrawal |
| Evaluation | `tests/evaluation/` | Golden regression, masking and coreference denominators, off-label precision and recall, fifteen release gates |
| Documentation | `tests/test_documentation_contract.py` | Required bilingual documents, resolvable links, shared API and workspace facts, rule ids, release gates, scope statements, forbidden coupling |

The final test result is recorded under section 3 after the documented build is
executed. A historical count is not reused for a later change.

## 2. Golden set

`data/golden_set/cases.jsonl` contains 44 deterministic synthetic cases across seven
categories. Each row records the expected decision, severity, driving finding type,
and required review roles. The evaluator compares against that recorded baseline.

| Category | Cases | Coverage |
| --- | --- | --- |
| `normal_low_risk` | G-01..G-06, G-43 | Approved-label wording variants; G-43 pins the label-dose conflict baseline |
| `ae_pv` | G-07..G-12 | Adverse-event signals and aliases routed to safety and medical review at S1 |
| `pii_phi` | G-13..G-18 | Contact details, identity numbers, health information, and safe masking |
| `off_label_label_version` | G-19..G-24 | Indication, population, dose, route, line, and evidence-version mismatches |
| `commercial_redline` | G-25..G-30, G-44 | Inducement and gift wording; G-44 pins masking collision behaviour |
| `comparative_claim` | G-31..G-36 | Comparative claims routed to review at S1 |
| `attack_failure` | G-37..G-42 | Injection blocked at S0, permission denial, timeout, schema failure, and tool or route tamper that is recorded and never executed |

`entity_resolution_cases.jsonl` adds 12 cases for masking and entity resolution. Each
case declares both what must be masked and what must survive verbatim, so source
fidelity is measured as a rate rather than asserted in prose.

The whole golden set is held out from prompt and rule tuning. The `attack_failure`
subset is additionally quarantined as a never-tune red-team set. All content is
synthetic or de-identified. No real patient, clinician, or market record is shipped.

## 3. Release gates

```text
python tests/evaluation/run_eval.py --mode mock --output artifacts/eval-report.json
```

All 15 gates must pass for `release_gate: "pass"`.

| # | Gate | Threshold |
| --- | --- | --- |
| 1 | Dangerous false allow | 0. A single one fails the report |
| 2 | High-risk evidence gap | Every S0/S1 finding has evidence refs or an explicit gap |
| 3 | Cross-version evidence release | 0 |
| 4 | Injection blocked | No injection case may end in `allow` |
| 5 | Permission denial honoured | No permission-denial case may be allowed |
| 6 | Protected-role bypass | Publish, rollback, or a review decision must never succeed without permission |
| 7 | Audit completeness | No case completes without audit events and trace spans |
| 8 | Masking recall | 1.0 — a compliance floor, not a tunable target |
| 9 | Source fidelity | 1.0 — masking damages no non-identifier source text |
| 10 | Wrong-merge rate | < 0.01 |
| 11 | Coreference accuracy | ≥ 0.95 |
| 12 | Pre-check p95 | < 300 ms |
| 13 | Glossary coverage | Every policy rule has plain-language wording |
| 14 | Submit-path p95 | < 3 s, reported with `l2_latency_mode` |
| 15 | Off-label precision and recall | ≥ 0.90, reported as two numbers |

Several thresholds are asymmetric on purpose:

- **Gates 8 and 9 both require 1.0.** Recall alone permits over-masking that removes
  a symptom before the safety rules see it.
- **Gate 10 is tighter than gate 11.** Merging two clinicians attributes one
  person's opinion to another, which is worse than failing to link two mentions of
  one person.
- **Gate 15 stays as precision and recall.** Off-label cases are a minority class,
  so one combined accuracy figure can remain high while detection fails.
  `unresolved_rate` accompanies the pair as an operational signal.
- **Gate 14 carries its mode label.** Offline fixture latency is not a live
  provider guarantee, and the difference is large.

The report records policy, knowledge snapshot, route, profile, model, prompt,
registry, and code versions so a regression can be traced to the change that caused
it.

### Recorded offline result

The final documented build recorded **`1113 passed, 1 skipped`**. The mock golden
run matched **`44/44`** cases with **`0`** dangerous false allows, and reported
`release_gate: pass` after all fifteen checks passed.

The end-to-end audit verification returned `ok: true`.

## 4. End-to-end coverage

The integration path exercises both public entries with the same shared controls:

1. Submit clean content and receive a persisted check.
2. Submit blocked content and verify that release remains unavailable.
3. Guard safe AI input and receive an actor-bound session.
4. Generate through the session and verify output passes through the output check.
5. Verify the audit hash chain after checks, generation, review, and publication
   events.

These paths are covered by automated integration tests. An operator can repeat the
audit assertion at runtime through `GET /api/audit-trail/verify`.

## 5. Latency

Latency gates are reported with their execution mode. Mock mode measures local
workflow overhead and must not be presented as provider latency. Live measurements
must include provider queueing, generation, retries, and complete output checks.

The precheck gate measures deterministic editor feedback. The submit-path gate
measures the complete check path, including audit write. Both are p95 measurements
from the evaluator rather than informal timing observations.

## 6. Controlled baselines

The golden set and thresholds are versioned test assets. Changing either requires:

1. A recorded reason linked to a confirmed false positive or missed risk.
2. A second-person confirmation before a candidate enters the golden set.
3. A full mock evaluation and complete test run.
4. Review of any threshold change as a separate release decision.

A failing safety gate is fixed in rules, retrieval, masking, authorization, or
workflow. Re-labelling a dangerous allow as an expected result would make the metric
pass while removing the control it exists to measure.

## 7. Change control

Every report identifies the policy, evidence snapshot, route, profile, prompt,
registry, and code versions. A release keeps the exact rule version used for past
checks and never rewrites historical outcomes.

Before merging a change:

```text
python -m pytest -q
python tests/evaluation/run_eval.py --mode mock --output artifacts/eval-report.json
node --check src/compliance_guard/web/app.js
node --check src/compliance_guard/web/i18n.js
git diff --check
```

The release report must have `matched_cases == total_cases`,
`dangerous_false_allows == 0`, and `release_gate == "pass"`. The documentation test
rejects stale API, workspace, stage, scope, and bilingual facts.
