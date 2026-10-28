# Operations

**English** · [简体中文](zh/operations.md)

Run the app, operate the seven workspaces, manage rules and model routes, handle
failures, and retain evidence. This guide describes the implemented service.

## 1. Local run

Requires Python 3.12+ (verified on 3.13). `LLM_MODE=mock` is the default and makes
no network calls.

```text
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test]"
LLM_MODE=mock DEMO_MODE=1 PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. On Windows PowerShell, set the environment variables
first: `$env:LLM_MODE = "mock"; $env:DEMO_MODE = "1"; $env:PYTHONPATH = "src"`.

The one-command launcher selects a free port and opens the browser:

```text
LLM_MODE=mock DEMO_MODE=1 python3 run.py
```

Use `python -m uvicorn` instead of the generated console script because the latter
can hard-code the virtualenv path and break when the checkout moves.
`PYTHONPATH=src` works with either an editable package install or a direct source
run. A virtualenv avoids externally managed Python restrictions.

## 2. Identity and deployment mode

`DEMO_MODE=1` skips login and exposes a four-role selector for a local
walkthrough. The roles are:

| Demo role | Intended use |
| --- | --- |
| `author` | Submit content, guard AI input, and inspect owned results |
| `reviewer` | Open review tasks and record professional decisions |
| `auditor` | Read audit evidence, quality posture, and connectors |
| `architect` | Inspect and draft model configuration; cannot publish it |

The server permission matrix supports the wider professional role set required by
review routing. Demo roles are request headers, not authentication. Use real
sessions outside a trusted local demonstration.

To run with sessions, remove `DEMO_MODE`:

```text
LLM_MODE=mock PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

The first start prints an initial `admin` password once. It is not written to the
audit ledger or persisted in clear text. The account must change it before normal
use. A password change ends every session for that account, including the current
session.

If an account that has never been used loses its initial password, restarting
reissues it. For an account that has been used, move `data/users.json` aside and
restart to recover access. That file contains scrypt password hashes and session
tokens and is gitignored.

This local identity store provides no identity provider, second factor, or user
administration. It is intentionally a replaceable seam for an enterprise identity
integration.

## 3. Seven workspaces

| Workspace | Purpose |
| --- | --- |
| `overview` | Current context, recent activity, and shortcuts into both check entries |
| `content_check` | Submit arbitrary text and inspect decisions, spans, findings, and versions |
| `conversation_guard` | Guard input, create a session, generate, and show only released output |
| `reviews` | Review tasks, evidence, decisions, and signature manifestations |
| `rules` | Rule versions, testing, batch evaluation, diff, publish, and rollback |
| `quality_audit` | Audit-chain verification, oversight metrics, regression candidates, connectors, and events |
| `settings` | Model profiles, task routes, validation, testing, publish, and rollback |

Workspace visibility comes from the capability matrix returned by the server.
Hidden controls improve navigation; every protected endpoint still checks the
actor and permission.

## 4. Check operations

### Content checking

`POST /api/checks/precheck` is the fast deterministic editor check. It creates no
case, stores no submitted content, and does not call a model. Treat an empty finding
list as the result of the current rule pass. It is not a regulatory approval.

`POST /api/checks` persists a versioned check. It resolves entities, masks only the
identified spans, retrieves admissible evidence, invokes bounded model extraction
when configured, and sends candidate fields through the deterministic policy
engine. The response includes the decision, severity, findings, source spans,
policy version, content version, safe text, and whether a model was called.

Text is checked against the exact submitted version. If a client edits it, the
client must check the new version rather than reusing an earlier result.

### AI conversation guard

The protected path has three stages:

1. **input** — `POST /api/conversations/guard-input` checks the user message before
   a model call. A blocked input creates no session and invokes no model.
2. **generation** — `POST /api/conversations/{conversation_id}/generate` verifies
   the actor, tenant, checked prompt hash, rule version, and session lifetime. The
   model receives the server-held safe input and bounded constraints.
3. **output** — the complete candidate is checked by the shared policy path before
   release. A blocked or failed output is withdrawn without returning its model
   text.

A safe input creates a server-side session for 15 minutes. It is bound to the actor,
tenant, inspected source hash, and rule version. A changed prompt returns
`conversation_prompt_mismatch`; a changed rule version returns
`conversation_requires_recheck`; an expired or closed session returns
`conversation_expired`.

`GET /api/audit-trail/verify` validates the append-only hash chain. It should return
`ok: true` after normal operation. Investigate before accepting new releases if it
returns a failing sequence number.

## 5. Six-case walkthrough

The examples in **Examples and training** provide deterministic coverage of the six
scenario families:

| # | Scenario | Example risk | Expected handling |
| --- | --- | --- | --- |
| 1 | `normal` | Statements consistent with approved product information | `allow` when current evidence supports them |
| 2 | `ae` | Possible adverse event such as rash | `human_review` with safety and medical routing |
| 3 | `pii` | Contact or identity details | review or block according to severity; masked before model access |
| 4 | `off_label` | Unapproved indication or dose | `human_review` with compliance and medical routing |
| 5 | `redline` | Serious adverse event or commercial inducement | immediate block or professional escalation |
| 6 | `injection` | Instruction override or permission fabrication | `blocked`; attempt recorded, never executed |

The examples are synthetic. `DEMO_MODE=0` hides the training drawer so it is not
mistaken for production content.

## 6. Rule lifecycle

A rule package is immutable once published. The lifecycle is:

1. Start from the current package and record rule and policy versions.
2. Draft scope by tenant, market, language, product, therapeutic area, content
   type, and entrypoint (`content`, `input`, or `output`).
3. Add deterministic conditions, severity, decision, permitted actions, required
   review roles, remediation, and evidence requirements.
4. Test representative positive, negative, overlap, and span cases with
   `POST /api/rules/test`.
5. Run the batch or golden regression with `POST /api/rules/evaluate`.
6. Review `GET /api/rules/diff` before publication.
7. Publish through `POST /api/rules/publish`, or restore a prior immutable version
   through `POST /api/rules/rollback`.

A rule version change does not rewrite historical checks. An active AI session
checked against the old version requires rechecking. Publish and rollback require
an authorised administrator; architecture access alone permits drafting and
inspection.

## 7. Model profile and route lifecycle

Model configuration is separated into profiles and task routes.

- A profile names capabilities, region, data-class limits, timeout, credential
  reference, and upstream model identity.
- A route selects a profile for a task, such as text extraction, guarded response
  generation, or multimodal input.
- Credentials stay in environment variables or a gitignored local secret file.
  Stored configuration and audit events contain references and redacted values.
- Draft validation rejects plaintext secrets, literal endpoints, incomplete
  capability declarations, and incompatible region or data-class combinations.
- `GET/PUT /api/config/models` inspect and draft configuration.
- `POST /api/config/models/test` validates a candidate route.
- `POST /api/config/publish` creates a versioned snapshot.
- `POST /api/config/rollback` restores the previous stable snapshot.

Architect access can draft, test, and inspect. Publication and rollback require an
administrator. Each publish and rollback writes an audit event.

## 8. Live model mode

Mock mode is appropriate for development, automated tests, and demonstrations.
Live mode uses an OpenAI-compatible chat-completions provider selected by the
published profile:

```text
COMPLIANCE_GUARD_LLM_BASE_URL=https://<provider-host> \
COMPLIANCE_GUARD_LLM_API_KEY=<your-key> \
LLM_MODE=live PYTHONPATH=src .venv/bin/python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

Keep the provider host and key outside committed files. The provider sees only the
bounded, masked request. Model output remains a candidate and cannot set release
permission. Conversation output is fully buffered and checked before display.

## 9. Failure playbooks

| Condition | Expected state | Operator action |
| --- | --- | --- |
| Provider timeout or malformed candidate | `MANUAL_DEGRADED` | Keep release held; retry only under the current policy and profile |
| Transient dependency failure | `FAILED_RETRYABLE` | Use bounded retries, then hand the case to a person |
| Unsafe condition cannot be resolved | `FAILED_SAFE` | Do not publish; preserve the safe error and escalate |
| Masking component failure | Failed or held | Do not send source text to the model |
| Audit write failure | Release fails | Restore audit service health before retrying the release |
| Rule version unavailable or changed | Rejected or held | Recheck against the current published version |
| Conversation expired | `conversation_expired` | Run input checks again; do not extend a stale approval |

`MANUAL_DEGRADED`, `FAILED_RETRYABLE`, and `FAILED_SAFE` never transition to
`ALLOWED`. Publication requires a successful output check and audit event.

Two health signals can move in an unexpected direction. A rising override rate can
show that reviewers are losing trust in the rules; a falling review completion rate
can show that the queue is blocking work. Inspect both with the case evidence rather
than optimising either number alone.

## 10. Health and retention

`GET /health/live` proves the process is alive. `GET /health/ready` checks startup
dependencies. `GET /health` provides the graded health view used by operators.

Audit events record identifiers, actor, time, versions, decisions, rule references,
safe hashes, and failure categories. They do not include raw source text, sensitive
entity mappings, token maps, system prompts, or complete model output by default.
Access to audit content and release actions remain separately authorised.

Standalone state lives under `data/` as local JSON and JSONL. Treat those files as
operational records: restrict filesystem access, back them up according to the
deployment retention policy, and never commit them. `artifacts/` contains generated
reports and is also gitignored.
