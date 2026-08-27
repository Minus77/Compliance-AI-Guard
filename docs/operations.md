# Operations

**English** · [简体中文](zh/operations.md)

Running the app, the demo walkthrough, live-model mode, failure playbooks, and
retention. Written against the implemented code.

## 1. Run

Requires Python 3.12+ (verified on 3.13). `LLM_MODE=mock` is the default and
makes no network calls.

```text
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
LLM_MODE=mock DEMO_MODE=1 PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. On Windows PowerShell set the variables first:
`$env:LLM_MODE = "mock"; $env:DEMO_MODE = "1"; $env:PYTHONPATH = "src"`.

Or one command, which picks a free port, opens the browser, and reports a taken
port or unwritable data directory as an instruction rather than a traceback:

```text
LLM_MODE=mock DEMO_MODE=1 python3 run.py
```

Two details in the uvicorn command are deliberate. **`python -m uvicorn`** rather
than the console script: that wrapper hard-codes an absolute interpreter path at
install time, so it breaks with a confusing `bad interpreter` error the moment the
folder is moved or renamed. **`DEMO_MODE=1`** skips the login, because identity
otherwise comes from a session and a four-workspace walkthrough would need four
sign-ins.

A virtualenv is recommended because a Homebrew or system Python is usually
externally managed (PEP 668) and refuses a bare `pip install`. `PYTHONPATH=src`
works whether or not the editable install resolves.

## 2. Running it as a deployment would

Drop `DEMO_MODE` and a real session is required:

```text
LLM_MODE=mock PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

On first start an initial `admin` password is generated and **printed to the
console once**. It is never written to the log or to disk, and it must be changed
before anything else can be done. Changing it ends every session for the account,
including the current one, because a rotation is usually performed precisely
because something leaked.

If the account has never been signed into, a later start re-issues and re-prints
that password. An account that *has* been used keeps its credential: a never-used
account has no history to protect, while silently re-keying a working identity
would be a way in rather than a recovery.

Lost the password on an account that has been used? Move `data/users.json` aside
and restart. That file holds scrypt password hashes and live session tokens, so it
is gitignored — a committed credential store is one shared with everyone who
clones the repository.

**Scope, stated plainly.** This is a minimal local session store, not enterprise
SSO: no identity provider, no second factor, no user management. It exists so the
trust boundary sits in the right place, with a seam an OIDC integration can
replace.

## 3. The six-case walkthrough

Scenario buttons live in the collapsed **示例与教学 / Examples and training**
drawer, below the working flow — six sample buttons above the editor make a daily
tool look like a demo, and the working order for a representative is source →
context → narrative → submit. With `DEMO_MODE=0` the drawer is hidden entirely.

| # | Scenario | Content | Expected result |
| --- | --- | --- | --- |
| 1 | `normal` | On-label hypertension guidance | `allow` (S3) |
| 2 | `ae` | Potential adverse event (皮疹) | `human_review` (S1) → PV + medical |
| 3 | `pii` | Personal identifier (身份证号) | `blocked` (S1) → security; value masked |
| 4 | `off_label` | Off-label dose / indication (糖尿病, 100mg) | `human_review` (S1) → compliance + medical |
| 5 | `redline` | Serious adverse event (昏迷, 危及生命) | `human_review` (S0) → PV + medical |
| 6 | `injection` | Prompt injection (忽略所有规则…) | `blocked` (S0) → security |

For each case open the **trace** to see the audit timeline
(`case_received → … → decision → workflow.complete`) and the model-route versions.
That is where the code-controlled, never-fail-open behaviour is visible.

Scenario text stays Chinese in every interface language, and that is enforced by a
test. Risk detection matches Chinese keywords and the evidence corpus is
`zh-CN`/`zh-HK` only, so translating the payload would silently disable AE,
redline, and injection detection and return an empty evidence set.

## 4. The four workspaces

| Workspace | For | Shows |
| --- | --- | --- |
| Representative | field rep | submit, pre-check hints, masked result, own trace |
| Reviewer | medical / PV / compliance / legal | evidence, findings, decision form, electronic signature |
| Model policy | architect (draft/test), admin (publish/rollback) | profiles, routes, versions, history |
| Quality & audit | QA, audit, regulatory | ALCOA+ posture, interface governance register, audit trail |

Role-based visibility is resolved from `GET /api/permissions` against the server
permission matrix. **Hiding is a usability aid, not the control** — every
protected route re-checks permission independently, and a test verifies that an
`architect` who forces a publish call still receives `403`.

### Demo roles

With `DEMO_MODE=1` a role selector sets `x-demo-role`, labelled *仅演示模式 /
demo mode only*. With the flag off it is hidden and the header is refused with
`401`. That gating closes a real hole: the header previously let a caller name
their own role, so one changed header was enough to publish model policy or read
the audit trail. `GET /health/ready` reports `demo_mode`, so the active posture is
never a guess.

| Role | Can do | Reachable workspaces |
| --- | --- | --- |
| `field_rep` | submit; read own result + trace | Representative |
| `reviewer` | read evidence, record signed decisions | + Reviewer |
| `auditor` | audit export, validation posture | + Quality & audit |
| `architect` | view/draft/test model policy (**not** publish) | + Model policy |

The wider pharma matrix stays server-side — `msl`, `pv_reviewer`, `qppv`,
`medical_reviewer`, `mlr_reviewer`, `compliance_admin`, `qa`,
`regulatory_affairs` — and a test locks that narrowing the picker did not reduce
the model. Separation of duties worth noting: only `qppv` may release an ICSR
submission (a PV reviewer can assess a signal but not submit it); `qa` and
`auditor` read the audit trail but hold neither `review_case` nor
`config_publish`, because quality oversight is not operational authority.
`GET /api/permissions` also returns `sop_refs`, mapping each action to the SOP
that governs it, so a permission reads as a controlled procedure rather than a
bare capability.

To drive the full publish/rollback loop, call the API as
`x-demo-role: compliance_admin`. Pressing publish as `architect` returns `403`,
which is the point.

## 5. Model policy: draft, test, publish, rollback

1. **View** — published version, redacted profiles (credential refs shown as
   `****`), routes, history, registry audit events.
2. **Draft** — edit a profile's timeout, token budget, region, enabled state, or a
   route's primary/fallback profile, capabilities, data classes, and
   `requires_human_on_failure` (`PUT /api/config/models`). The server validates
   the draft: approved adapter, no plaintext secrets, no literal endpoints,
   compatible capability/region/data class.
3. **Test** — `POST /api/config/models/test` runs a synthetic connectivity check
   and reports provider, model, route, and latency, or an error category. In mock
   mode this never leaves the machine.
4. **Publish** — `POST /api/config/publish`. Drafts become a new immutable version
   `v{n}`. Requires an admin role.
5. **Rollback** — `POST /api/config/rollback` restores the previous stable
   version. Every publish and rollback is audited.

The runtime snapshot persists to `data/runtime_config.json` so a published state
survives a restart.

## 6. Live model mode

`LLM_MODE=live` routes the semantic check to a real OpenAI-compatible
chat-completions provider. Everything else is unchanged: the same policy engine
decides, the same audit events are written, the same fail-safe rules apply.

```text
COMPLIANCE_GUARD_LLM_BASE_URL=https://<provider-host> \
COMPLIANCE_GUARD_LLM_API_KEY=<your-key> \
LLM_MODE=live PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --port 8000
```

The key can instead live in the gitignored `config/secrets/llm.local.json`
(`{"base_url": "...", "api_key": "..."}`); the environment wins over the file. The
key is never written to a snapshot, an API response, an audit event, or a log.
Endpoint files must contain no secrets, and the loader rejects them if they do.

The header badge changes from **离线演示模式 / Offline demo mode** to **已接入真实
大模型 / Live model connected**. If live mode is on but the provider is not usable,
the badge reads **大模型未就绪 / Model not ready** and `/health` reports
`model_service.ready: false`; nothing high-risk is released in that state.

**What still holds in live mode**, enforced by tests rather than convention:

- The model only proposes candidates. It cannot set decision, severity, approval
  status, routing, or tool permissions.
- Identifiers are masked **before** the request leaves the process; the model sees
  tokens such as `[HCP_TKN_…]`, never a real name.
- Every provider failure (timeout, 4xx/5xx, truncation, non-JSON, missing
  credential) becomes a fail-safe error category, so an outage degrades to human
  review and can never look like an approval.
- Candidates for conditions the server determines (missing evidence, missing
  context, permission failure, evidence conflict) are recorded in the audit trail
  but never promoted into findings, so model prose cannot move the decision.

No new dependency is needed; the adapter uses the already-pinned `httpx`.

## 7. Failure playbooks

| Situation | What happens | What to do |
| --- | --- | --- |
| **Model timeout** | `error_category=timeout` → `MANUAL_DEGRADED`, `human_review` S1, reviewer task enqueued | Check `/health` and the trace; confirm which route timed out; review manually |
| **Schema failure** | Invalid model output → `MANUAL_DEGRADED` with a reviewer task (or `FAILED_SAFE` → `REFUSED` if a route disabled `requires_human_on_failure`) | Treat as a data-quality incident; inspect output schema and profile; re-run the golden set |
| **Retrieval gap** | No evidence → `needs_info` (CN-012, S2); contradiction → `human_review` (CN-010, S1) | Supply evidence or resolve the conflict; the case stays queued |
| **Prompt injection** | Flagged before the model call; CN-005, S0, `blocked`, routed to security. Tool/route tamper is recorded, never executed | Escalate to security; do not retry the content as-is |
| **Permission denial** | `403` with `{"error":{"code":"forbidden"}}`; audited | Fix the role; never bypass the denial |
| **Duplicate event** | Deduped by `(tenant_id, event_id)`; duplicate returns the original result, no repeated side effects | Confirm `created_case_count` is 1; check DLQ if side effects repeated |
| **Event processing failure** | Transient → DLQ `next_action=retry` up to `max_attempts` (3), then `manual_review`; permanent → `manual_review` immediately | Read the DLQ, replay retryables, handle `manual_review` as incidents |
| **Bad publish** | — | Roll back as `compliance_admin`; verify the version reverted and the snapshot persisted |
| **Unsafe error** | Any uncaught exception → `REFUSED` + `FAILED_SAFE`, human review enqueued. The HTTP body never echoes the exception or request content | Reproduce from the trace, fix, re-run the suite |
| **Audit chain broken** | `GET /api/audit-trail/verify` returns `ok: false` with `first_broken_seq` | A data-integrity incident, not a bug. Preserve the file before touching anything, then establish who had write access. The chain says something changed, not what |
| **Service refuses to start** | Startup raises `ConfigurationError` naming the file | Fix that file. An expired policy bundle is refused on purpose |
| **Ready false, live true** | `/health/ready` lists the failing dependency | The process is alive but cannot answer correctly. Do not restart — restarting a healthy process will not fix a bad file |

### Two alarms that point the unusual way

| Signal | Where | Why it matters |
| --- | --- | --- |
| **Override rate below 2%** | `GET /api/metrics` → `oversight.status: warning` | Investigate whether review has become a formality. This alarm points *downward* on purpose: a reviewer who never disagrees looks identical to a flawless system in the record |
| **Abandonment above 20%** | `GET /api/metrics` → `usability.status: warning` | Representatives are clearing the editor after a warning. Nothing is blocked and no finding is raised, so this failure is invisible in the safety numbers. Read it *beside* them: a falling detection count next to a rising abandonment count means the rules got tighter, not that risk went away |

Appeals with a high sustained overturn rate (`GET /api/appeals` →
`summary.overturn_rate`) mean the rule needs fixing, not the queue. Absorbing the
same false positive case by case leaves the cause in place.

## 8. Graded health

| Endpoint | Answers |
| --- | --- |
| `GET /health/live` | Is the process up? Touches no dependency, so a brief file-read failure cannot trigger a restart loop |
| `GET /health/ready` | Can it answer, on which versions, under which retention policy, in which posture |
| `GET /health` | Retained for existing callers and the UI mode badge |

Configuration is validated at **startup**, and an invalid configuration refuses to
start with the filename in the message. Previously a malformed bundle surfaced on
the first request that needed it — which means the first *user* found it,
mid-sentence.

## 9. Retention

Declared in `runtime_config.retention_policy()` and reported by `/health/ready`.
The `enforced` column is the one to read first: a retention period nothing
implements reads as a control while the store grows forever, so the two states are
reported separately rather than implied.

| Store | Retention | Enforced | Why |
| --- | --- | --- | --- |
| Audit ledger | never auto-deleted | no sweep exists | Must equal or exceed the records it describes. A sweep would defeat the chain that exists to make deletion detectable |
| Feedback candidates | never auto-deleted | no sweep exists | Confirmed candidates become regression cases |
| Notifications | 90 days | yes, swept on read | An **unread** notification is never swept: expiring an outcome the author has not seen would lose it silently |
| Resolved appeals | 90 days | yes, same sweep | A **pending** appeal never expires; expiring outstanding work would close it by neglect |
| Pre-check log | 7 days | not yet | Latency telemetry only; no decision depends on it |
| Drafts | 7 days, browser-local | yes, in the browser | Never uploaded; the server never holds them |

The sweep runs opportunistically on read rather than on a timer: this is a single
local process with no scheduler, and a background thread whose only job is
deleting records is a poor trade when the sweep is cheap.

## 10. Runtime artifacts (all gitignored)

- `data/audit/` — append-only, hash-chained JSONL ledger
- `data/runtime_config.json` — persisted published model-policy snapshot
- `data/users.json` — local accounts and session tokens
- `data/golden_set/candidates.jsonl` — misclassification reports awaiting a second
  person's confirmation before they may enter the golden set
- `artifacts/` — evaluator reports
