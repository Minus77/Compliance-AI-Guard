# Compliance AI Guard

**English** · [简体中文](README.zh.md)

An independently deployable compliance gateway for medical content and AI
conversations. It checks text submitted by people, constrains and inspects model
generation, and blocks unsafe output before publication. The standalone mode needs
no vendor SDK, external database, queue, identity provider, or live model.

The model has a bounded role: it may propose findings or draft a response. A
deterministic policy engine decides the outcome, severity, review route, and
release permission. A failed or degraded check never becomes an approval.

```text
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
LLM_MODE=mock DEMO_MODE=1 PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --port 8000
```

Open <http://127.0.0.1:8000>. `LLM_MODE=mock` is the default and makes no network
calls. `LLM_MODE=mock DEMO_MODE=1 python3 run.py` starts the app on a free port and
opens the browser.

**Scope.** This is a working MVP for exploring how an AI layer can be controlled
in a regulated environment. It makes no claim of GxP/CSV, pharmacovigilance,
medical-legal review, or regulatory validation, and contains no live connector to
a customer system. All data shipped with the repository is synthetic. Features
such as adverse-event triage, reporting clocks, Part 11-style signature
manifestations, and ALCOA+ views demonstrate the shape of those controls, not a
validated implementation. Nothing here is regulatory advice.

## Two check entries

| Entry | API | Purpose |
| --- | --- | --- |
| Content check | `POST /api/checks` | Check arbitrary medical or promotional text before it is saved, sent, or released |
| AI conversation guard | `POST /api/conversations/guard-input` | Inspect untrusted input before a generation session exists |

`POST /api/checks/precheck` provides the fast deterministic preview used while
editing. It creates no case, stores no submitted text, and never calls a model.

## Three AI stages

1. **Input** — the gateway checks the user message, masks identifiers, and blocks
   prompt injection or other prohibited requests before any model call. A safe
   input creates a short-lived, actor-bound conversation session.
2. **Generation** — only the server-held checked input can be used. The model
   receives bounded context and applicable rule constraints, and returns a
   buffered candidate.
3. **Output** — the candidate runs through the same policy path before release.
   Unsafe output is withdrawn without echoing the model text. A failed output
   check returns `failed_safe`.

Sessions cannot substitute a different prompt after input approval, be reused by
another actor or tenant, outlive their 15-minute window, or survive a rule-version
change. The browser does not control release permission.

## Decisions

Every result uses one of four public decisions:

- `allow` — the current rules found no issue requiring a hold; this does not
  assert legal or regulatory approval.
- `needs_info` — required context or evidence is missing.
- `human_review` — a professional must assess the finding.
- `blocked` — release or generation is prohibited.

Each finding carries a severity from S0 through S3, a rule version, a plain
language explanation, optional Unicode character spans, the permitted actions,
and the required review roles. `refused` remains an internal terminal state for
unsafe requests. S0 and S1 findings cannot be self-approved.

## Seven workspaces

| Workspace | Purpose |
| --- | --- |
| `overview` | Business context, recent activity, and shortcuts into both primary checks |
| `content_check` | Submit arbitrary text and read the decision, spans, findings, and versions |
| `conversation_guard` | Guard input, create a server session, and show only output released by the output check |
| `reviews` | Evidence, review decisions, and signature manifestations |
| `rules` | Active rules, version history, test, batch evaluation, diff, publish, and rollback |
| `quality_audit` | Audit-chain integrity, oversight metrics, regression candidates, connectors, and audit events |
| `settings` | Model profiles, task routes, draft validation, test, publish, and rollback |

Workspace visibility comes from the server permission matrix. Hiding a control is
a usability aid; every protected API route checks permission independently.

## Controls

**The model proposes; server code decides.** Model output cannot set the decision,
severity, approval status, route, or tool permissions. Candidate claims are checked
against server-derived facts and the published rule version.

**Identifiers are masked before external model calls.** Masking applies only to the
identified entity span. Entity resolution runs first so one person receives one
stable token. Over-masking is tested as a separate failure because it can remove
an adverse-event word before the safety rules see it.

**Evidence is versioned and closed-world.** Missing evidence becomes `needs_info`
or review; it never becomes an allow. Expired or cross-version evidence is
rejected.

**Audit payloads avoid source text.** The append-only hash chain records actor,
time, rule and content versions, decisions, rule references, and safe digests.
`GET /api/audit-trail/verify` reports the first unverifiable position.

**Failure is not approval.** Provider timeout, malformed output, masking failure,
permission denial, or an audit-write failure routes to `MANUAL_DEGRADED`,
`FAILED_RETRYABLE`, or `FAILED_SAFE`. A case cannot reach `ALLOWED` from a failed
state.

**Connectors are optional contracts.** Content source, safety intake, and review
export use provider-neutral JSON contracts with version checks, idempotency, and
dead-letter handling. The core checks, rule lifecycle, reviews, and audit work
without a connector.

## Verification

```text
python -m pytest -q
python tests/evaluation/run_eval.py --mode mock --output artifacts/eval-report.json
```

The release report covers the 44-case synthetic golden set, 12 masking and entity
resolution cases, dangerous false allows, evidence constraints, audit
completeness, masking recall, source fidelity, review permission, latency, glossary
coverage, and off-label precision and recall. `release_gate` must be `pass`.

The exact test count and evaluation result are recorded in
[validation.md](docs/validation.md).

## Live model mode

```text
COMPLIANCE_GUARD_LLM_BASE_URL=https://<provider-host> \
COMPLIANCE_GUARD_LLM_API_KEY=<your-key> \
LLM_MODE=live PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --port 8000
```

Any OpenAI-compatible chat-completions provider can be used through a configured
profile. Credentials can live in the gitignored
`config/secrets/llm.local.json`. Profile publication is versioned; changing a
profile does not rewrite the meaning of a past case. Generation remains
server-mediated, output remains buffered, and provider failures never release
unchecked text.

## Documentation

| Document | 中文 | Contents |
| --- | --- | --- |
| [Product guide](docs/product-guide.md) | [产品手册](docs/zh/product-guide.md) | Audience-focused setup, feature walkthroughs, APIs, architecture diagrams, security boundaries, limitations |
| [architecture.md](docs/architecture.md) | [架构设计](docs/zh/architecture.md) | Shared control plane, request paths, three AI stages, policy rules, data model, failure states |
| [operations.md](docs/operations.md) | [运维手册](docs/zh/operations.md) | Setup, seven workspaces, rule and model lifecycle, live mode, failure playbooks, retention |
| [security-and-risk.md](docs/security-and-risk.md) | [安全与风险](docs/zh/security-and-risk.md) | Trust boundaries, risk register, masking, injection defence, audit privacy, scope limits |
| [validation.md](docs/validation.md) | [验证](docs/zh/validation.md) | Test strata, golden set, release gates, evaluator results, change control |
| [integration-contracts.md](docs/integration-contracts.md) | [集成契约](docs/zh/integration-contracts.md) | Optional content source, safety intake, and review export contracts |
| [decisions/0001](docs/decisions/0001-workflow-first-controlled-agent.md) | [决策记录 0001](docs/zh/decisions/0001-workflow-first-controlled-agent.md) | The workflow-first controlled-agent decision |

## Stack

Python 3.12+, FastAPI, Pydantic v2, uvicorn, and `httpx`. The interface is vanilla
JavaScript with no build step. Standalone storage is local JSON and JSONL.

## License

Released under the [MIT License](LICENSE).

Copyright (c) 2026 trooly
