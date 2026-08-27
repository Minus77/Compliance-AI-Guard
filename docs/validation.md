# Validation

How the system is measured: test strata, the golden set, the 15 release gates, and
the defects that only a real model exposed.

## 1. Test strata

1029 tests, all offline in `LLM_MODE=mock`.

| Stratum | Location | Verifies |
| --- | --- | --- |
| Unit | `tests/unit/` | Contracts, policy engine, routing, state machine, token service, signatures, ICSR, indication resolution, retention |
| Contract | `tests/contract/` | Mock gateway determinism, model output schema, routing, source adapter boundary, live-adapter fail-safe behaviour and output-framing tolerance (hermetic, no socket) |
| Integration | `tests/integration/` | API surface, case workflow and lifecycle, audit replay and hash chain, idempotent events, retrieval filters, UI contract, auth, pre-check, live-mode wiring without secret leakage |
| Security | `tests/security/` | Authorization, injection, model boundary, masking, source fidelity, entity resolution, client trust boundary, client-bypass red team, session boundary |
| Evaluation | `tests/evaluation/` | Golden-set regression, masking and resolution metrics with denominators, off-label precision/recall, the release-gate report |

```text
python -m pytest -q
```

## 2. The golden set

`data/golden_set/cases.jsonl` holds 44 deterministic synthetic cases across seven
categories. Every row records the expected decision, severity, driving finding
type, and required review roles, so the evaluator compares observed behaviour to a
recorded baseline rather than to a human's memory.

| Category | Cases | Covers |
| --- | --- | --- |
| `normal_low_risk` | G-01..G-06, G-43 | On-label allow across Chinese wording variants. G-43 pins the label-dose evidence-conflict baseline |
| `ae_pv` | G-07..G-12 | AE/PV signals (rash, nausea, vomiting, dizziness, pruritus, aliases) → PV + medical at S1 |
| `pii_phi` | G-13..G-18 | Phone, email, HCP-title masking; ID numbers and PHI wording → security at S1 |
| `off_label_label_version` | G-19..G-24 | Dose, indication, population, line, route mismatches; old-label-version dose comparison |
| `commercial_redline` | G-25..G-30, G-44 | Kickbacks, gifts, entertainment, red packets, incentives. G-44 pins the masked-redline collision baseline |
| `comparative_claim` | G-31..G-36 | Comparative claims → S1 review |
| `attack_failure` | G-37..G-42 | Chinese and English injection blocked at S0; tool/route tamper recorded never executed; schema failure, timeout, permission denial degrade to manual review |

`entity_resolution_cases.jsonl` holds 12 further cases for masking and resolution.
Each declares what must be masked **and** what must survive verbatim, which is how
source fidelity is measured as a rate rather than asserted in prose.

The whole golden set is held out from prompt and rule tuning; the evaluator only
measures. The `attack_failure` subset is additionally quarantined as a never-tune
red-team set.

All content is synthetic or de-identified. No real patient, HCP, or market data.

## 3. Release gates

```text
python tests/evaluation/run_eval.py --mode mock --output artifacts/eval-report.json
```

All 15 must pass for `release_gate: "pass"`.

| # | Gate | Threshold |
| --- | --- | --- |
| 1 | Dangerous false allow | 0. A single one fails the report |
| 2 | High-risk evidence gap | An S0/S1 finding must carry evidence refs or an explicit gap |
| 3 | Cross-version evidence release | 0 |
| 4 | Injection blocked | No injection case may end in `allow` |
| 5 | Permission denial honoured | No permission-denial case may be allowed |
| 6 | Protected-role bypass | Publish/rollback or a review decision must never succeed without permission |
| 7 | Audit completeness | No case completes without audit events and trace spans |
| 8 | Masking recall | 1.0 — a compliance floor, not a tunable target |
| 9 | Source fidelity | 1.0 — masking damaged nothing that was not an identifier |
| 10 | Wrong-merge rate | < 0.01 |
| 11 | Coreference accuracy | ≥ 0.95 |
| 12 | Pre-check p95 | < 300 ms |
| 13 | Glossary coverage | Every policy rule has plain-language wording |
| 14 | Submit-path p95 | < 3 s, reported with `l2_latency_mode` |
| 15 | Off-label precision and recall | ≥ 0.90, reported as two numbers |

Several thresholds are deliberately asymmetric, and the reasoning is the point:

- **Gates 8 and 9 are both 1.0** because masking fails in two directions. Recall
  alone would let over-masking quietly delete adverse-event keywords.
- **Gate 10 is tighter than gate 11** because merging two clinicians attributes one
  person's opinion to another — worse than failing to link two mentions of one
  person.
- **Gate 15 is two numbers, never one.** Most golden cases are not off-label, so a
  combined accuracy score would stay high even if detection stopped working
  entirely; the class imbalance would hide the only regression that matters.
  `unresolved_rate` accompanies them as the operational signal: it rises when the
  ontology falls behind the vocabulary representatives actually use, which surfaces
  as more clarifying questions rather than as a wrong answer.
- **Gate 14 carries its mode label** because a mock figure and a live one differ by
  three orders of magnitude. A mock number read as a live guarantee would be the
  most misleading figure in the report.

The report records policy, knowledge-snapshot, route, profile, model, prompt,
registry, and code versions, so any regression traces to the exact change.

Current offline result: 44/44 matched, 0 dangerous false allows, `release_gate:
pass`.

## 4. Latency

| | Live provider | Offline fixtures |
| --- | --- | --- |
| p95 per case | 5.1 s – 19.7 s | ≈ 2 ms |
| Average per case | 3.8 s – 9.8 s | ≈ 2 ms |
| Slowest single case | up to 20.7 s | ≈ 3 ms |

Measured across seven full golden-set runs against a live provider on one host.
The spread is provider variance, not code: the same commit produced p95 of 5.1 s
and 18.3 s on different runs. Quote the **range**, not one good run.

Two design consequences follow directly:

- Real-time feedback while typing cannot depend on the model. That is why the
  deterministic layer at ≈ 2 ms carries the interactive path and the model runs
  behind it.
- A 20 s worst case needs a visible waiting state and a timeout that fails to human
  review, which is what the provider-timeout path does.

A latency regression gate is therefore not asserted against a live run. The offline
p95 is the stable regression signal; live runs measure accuracy and grounding.

## 5. Defects only a real model exposed

Seven defects surfaced only once a real provider answered, because the offline
fixtures never produced these response shapes. All seven are now regression-tested
offline.

| # | Defect | Why it mattered |
| --- | --- | --- |
| 1 | Model returns the full field template with `null` values | Read downstream as "every label field contradicts the label", fabricating an off-label finding on compliant copy |
| 2 | Model volunteers `missing_context` on clean on-label copy | Downgraded `allow` to `needs_info`: model prose moved a server decision |
| 3 | Model prefixes prose before the JSON fence | Parsed as malformed, sending a good check to `FAILED_SAFE` for a cosmetic reason |
| 4 | Model returns `{"refused": true}` with no error category | "I decline to assess this" was indistinguishable from "assessed, found nothing" |
| 5 | Only evidence **ids** were sent, never the text | The model correctly refused to reason from facts it could not see, so off-label detection silently produced nothing |
| 6 | Hedged, non-quantitative field values (`口服（推断）`, `dose: "一次"`) | Compared as factual claims, fabricating route and dose mismatches |
| 7 | `unapproved_promotion` (S0, pattern-less) stacked onto comparative claims | Model output alone escalated S1 review to an S0 block, including on content that promotes nothing |

Defects 2 and 7 are the same class and the most important: a pattern-less rule
reachable only from model output could set the gravest decision in the system. The
engine now refuses to promote candidates for conditions the server determines from
its own state, and keeps an uncorroborated S0 candidate as a finding at full
severity while routing it to a human rather than letting it block. Neither change
can turn a case into `allow`.

**The general lesson.** Offline fixtures validate the *workflow*; only a real model
exercises the *contract*. Prompt wording alone did not hold finding types apart —
defect 7 recurred after a prompt fix and needed a deterministic precedence rule in
the policy engine. Instruction is not a control.

## 6. Known baselines, pinned deliberately

**On-label dose wording collides with the contradict fixture.** Content stating the
current label dose ("每天80mg口服") also matches an external contradicting study
fixture, so retrieval returns both supporting and contradicting evidence and the
engine reports `evidence_conflict` at S1 instead of allowing. G-43 records this as
expected; the ordinary `normal_low_risk` cases use wording that does not collide,
so the clean allow path is still exercised.

Recorded as a baseline so it is never mistaken for a regression. The earlier
masking-collision baseline (a redline keyword adjacent to an HCP title being
partially masked) was **fixed** rather than accepted, because the same mechanism
could remove adverse-event keywords — a missed-detection path, not a cosmetic
quirk. G-44 now asserts the redline fires for the right reason.

## 7. Change control

Re-run the full suite and the evaluator whenever any of these change: policy
bundles, prompts, model profiles or routes, knowledge fixtures or
ingestion/retrieval, security controls, the workflow or policy engine or domain
models, or the evaluator, golden set, and red-team tests themselves.

A regression is: `matched_cases < total_cases`, `dangerous_false_allows > 0`, any
gate failing, `release_gate` becoming `fail`, or any previously passing test
failing.

```text
python -m pytest tests/evaluation/test_regression.py tests/security/test_red_team_cases.py -q
python -m pytest -q
python tests/evaluation/run_eval.py --mode mock --output artifacts/eval-report.json
RUN_LIVE_LLM_TESTS=1 python -m pytest tests/contract/test_live_adapter.py -q
```

Golden-set metrics are demonstration targets, not a production performance
commitment.
