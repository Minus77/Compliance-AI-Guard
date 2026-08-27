# Compliance AI Guard

A deterministic, fail-safe compliance pre-check for pharmaceutical field
communications. It sits in front of a call-report narrative and decides — before
anything is released — whether the content can be allowed, needs more information,
must go to a human, or must be blocked.

The interesting part is not that it uses an LLM. It is **how little authority the
LLM has**. The model reads Chinese free text and proposes candidates; every
decision, severity, route, and permission is produced by server-side code. That
constraint is the design, and it is what makes a case replayable, auditable, and
explainable to the reviewer who has to sign it.

```text
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
LLM_MODE=mock DEMO_MODE=1 PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --port 8000
```

Open http://127.0.0.1:8000. Runs fully offline — `LLM_MODE=mock` is the default and
makes no network calls. Or `LLM_MODE=mock DEMO_MODE=1 python3 run.py` to pick a free
port and open a browser in one command.

**Scope.** This is a working MVP built to explore how an AI layer can be controlled
in a regulated workflow. It makes no claim of GxP/CSV, PV, MLR, or regulatory
validation, integrates with no live CRM/vault/safety system (adapters are
contract-only), and uses only synthetic data. The regulatory-flavoured features —
ICSR assessment, reporting clocks, Part 11-style signatures, ALCOA+ audit view —
demonstrate the *shape* of those controls, not validated implementations. Nothing
here is regulatory advice.

## Why it is built this way

Three design choices carry most of the weight.

**The model proposes; the server decides.** There is no code path from model output
to a final verdict. Candidates pass through schema validation into a deterministic
policy engine. This was not paranoia: during live-model testing, a pattern-less S0
rule reachable only from model output could escalate a routine review into a block
on content that promoted nothing. Prompt wording did not hold the finding types
apart — a deterministic precedence rule did. Instruction is not a control.

**Off-label is decided by field comparison, not by asking.** A full Chinese label is
tens of thousands of characters, irrelevant label prose pollutes the judgement, and
"I think this is off-label" cannot be checked. So labels are structured at ingestion
into versioned facts, the model extracts seven fixed fields (indication, population,
line, dose, route, duration, combination), and the server compares them field by
field. A mismatch names the exact field that failed.

**Masking fails in two directions, and the quiet one is worse.** Under-masking leaks
an identifier. Over-masking deletes narrative — an early regex implementation
replaced its whole match, so "赠送礼品给医生" lost the characters carrying "礼品"
and the bribery rule stopped firing. The same mechanism could strip an
adverse-event keyword before the safety rules ran. Names are now anchored on a
surname dictionary and only the name span is replaced, entity resolution runs
*before* masking so one person gets one token, and both directions are release
gates pinned at 1.0.

## What it does

**Four decisions** — `allow`, `needs_info`, `human_review`, `blocked` — each with a
severity (S0 redline through S3 advisory), evidence, plain-language reasoning, and
routing to the professional role that can act on it. S0 and S1 can never be
self-approved.

**21 policy rules** covering adverse events, serious adverse events, personal and
health data, off-label claims, commercial redlines, comparative claims, prompt
injection, evidence conflicts and gaps, permission failures, and claim
discrepancies. Each carries its own severity, routing, and SLA.

**Four workspaces** — representative (submit and read a masked result), reviewer
(evidence, decision, electronic signature), model policy (draft/test/publish/
rollback), quality and audit (ALCOA+ posture, interface register, audit trail) —
bilingual 简体中文 / English, with server codes always shown as a readable phrase
*plus* the raw code so a reviewer can read the screen and an auditor can still
verify the trace.

**A fail-safe state machine.** Model timeout, schema violation, permission denial,
or an unhandled error routes to `MANUAL_DEGRADED`, `FAILED_RETRYABLE`, or
`FAILED_SAFE` and enqueues a human. A case can never reach `ALLOWED` from a failed
state.

**Writing-time pre-check in two layers**, neither of which calls a model: local
word cues on every keystroke, and a deterministic server pre-check at p95 well
inside its 300 ms budget. Neither creates a record — a draft is not a submission.
L0 never says the content looks clean, because a local word list cannot support
"no problems found" and false reassurance teaches the reader that silence means
safety.

**A tamper-evident audit trail.** Every entry carries
`sha256(prev_hash + canonical body)`; `GET /api/audit-trail/verify` reports the
first position that cannot be trusted. Append-only is a promise about this program;
the chain is what makes an edit by anyone else detectable.

**Pharmacovigilance triage** against the four ICSR minimum criteria plus the
reporting clock (7 days fatal/life-threatening, 15 for other serious, aggregate for
non-serious), anchored on first company awareness. An incomplete ICSR never
suppresses a safety signal.

**Oversight measured in both directions.** A *low* human-override rate raises a
rubber-stamping warning, and abandonment — a warning shown, the paragraph deleted —
is counted. That failure mode leaves nothing blocked and no finding raised, so it is
invisible in the safety numbers unless you look for it.

**A closed loop.** My records, notifications on review outcomes, revision that keeps
its parent, and an appeal channel that creates work for a person without lifting the
block.

## Verification

```text
python -m pytest -q                                          # 1029 tests, offline
python tests/evaluation/run_eval.py --mode mock --output artifacts/eval-report.json
```

Current state: **1029 passing**, golden set **44/44 matched**, **0** dangerous false
allows, all **15 release gates** pass.

The gates are deliberately asymmetric where symmetry would hide something. Masking
recall and source fidelity are both pinned at 1.0. Wrong-merge rate (0.01) is
tighter than coreference accuracy (0.95), because merging two clinicians attributes
one person's opinion to another. Off-label is reported as precision *and* recall,
never a single accuracy figure — most cases are not off-label, so a blended score
would stay high even if detection stopped working entirely.

Against a real provider the same 44 cases matched 44/44 with the gate passing, at a
p95 between 5.1 s and 19.7 s across seven runs on one commit. That spread is
provider variance, which is why the interactive path is deterministic and the model
runs behind it. Details in [docs/validation.md](docs/validation.md).

## Live model mode

```text
COMPLIANCE_GUARD_LLM_BASE_URL=https://<provider-host> \
COMPLIANCE_GUARD_LLM_API_KEY=<your-key> \
LLM_MODE=live PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --port 8000
```

Any OpenAI-compatible chat-completions provider. The key can live in the gitignored
`config/secrets/llm.local.json` instead, and each business profile maps to an
upstream model in `config/endpoints/`, so `model_profile_id` stays the stable
routing name in the audit trail while `model_upstream` records what actually
answered. Repointing a profile never rewrites the meaning of a past case.

Masking still happens before the request leaves the process, the model still only
proposes, and any provider failure degrades to human review rather than an
approval.

## Documentation

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | The workflow-first decision, containers, request path, state machine, policy rules, off-label and masking design, routing, layout |
| [docs/operations.md](docs/operations.md) | Running it, the six-case walkthrough, roles and workspaces, model policy publish/rollback, live mode, failure playbooks, retention |
| [docs/security-and-risk.md](docs/security-and-risk.md) | Trust boundaries, 17-risk register with implemented controls, injection defence, PV assessment, signatures, oversight, scope limits |
| [docs/validation.md](docs/validation.md) | Test strata, golden set, the 15 release gates and why their thresholds differ, latency, the seven defects only a live model exposed |
| [docs/integration-contracts.md](docs/integration-contracts.md) | Source-of-record, content vault, and PV adapter contracts; approval-gated writes; idempotency and DLQ semantics |
| [docs/decisions/0001-workflow-first-controlled-agent.md](docs/decisions/0001-workflow-first-controlled-agent.md) | The architecture decision record |

## Stack

Python 3.12+, FastAPI, Pydantic v2, uvicorn. Four direct dependencies, all pure
Python, all pinned. The UI is vanilla JavaScript with no build step. Storage is
local JSON and JSONL — there is no database, because the interesting problems here
are boundaries and determinism, not persistence.
