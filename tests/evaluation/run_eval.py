"""Golden-set evaluator and release-gate reporter.

Runs every deterministic golden case through the public ``run_check_case``
service in ``LLM_MODE=mock`` (fully offline), compares expected
decision/severity/finding-type/roles against the observed outcome, and computes
a JSON release-gate report. The report records configuration versions so any
prompt, rule, knowledge, tool, model, or code change can be regression
compared against the recorded baseline.

The release gate fails the report when any of the following holds:

- a dangerous false allow (an S0/S1 case, or a case that must not allow, is
  allowed),
- an S0/S1 finding carries neither evidence references nor an explicit
  ``evidence_gap``,
- cross-version evidence is released,
- audit spans are missing for a case,
- a known injection is allowed to alter the workflow, or
- a protected role action succeeds without permission.

This module is both a CLI (``python tests/evaluation/run_eval.py``) and an
importable API (``build_eval_report``) used by the regression tests.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SRC = _PROJECT_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from compliance_guard.audit.ledger import AuditLedger
from compliance_guard.audit.metrics import Metrics
from compliance_guard.audit.trace import Tracer
from compliance_guard.domain.enums import Decision, Role, Severity
from compliance_guard.domain.models import Actor, CheckCaseRequest
from compliance_guard.knowledge.label_facts import LabelFactsStore
from compliance_guard.knowledge.retrieval import EvidenceRetriever
from compliance_guard.llm.adapters import MockAdapter
from compliance_guard.llm.gateway import ModelGateway
from compliance_guard.llm.registry import ModelRegistry
from compliance_guard.policy.bundles import PolicyBundleStore
from compliance_guard.review.decisions import DecisionService
from compliance_guard.review.tasks import ReviewQueue
from compliance_guard.security.authorization import AuthorizationService
from compliance_guard.security.coreference import resolve_mentions
from compliance_guard.security.pii_gateway import KnownIdentifier, PiiGateway, SanitizeContext
from compliance_guard.knowledge.glossary import default_glossary
from compliance_guard.workflow.orchestrator import Orchestrator
from compliance_guard.workflow.precheck import L1_BUDGET_MS, PrecheckService

# Budget for the model-backed submit path, from the three-tier latency design.
# Well above L1 on purpose: this layer may call a provider, and the interface
# shows a progress state rather than pretending the wait is instant.
L2_BUDGET_MS = 3000

REPORT_SCHEMA = "compliance-ai-guard/eval-report/v1"
DEFAULT_OUTPUT = _PROJECT_ROOT / "artifacts" / "eval-report.json"
CONFIG_DIR = _PROJECT_ROOT / "config"
DATA_DIR = _PROJECT_ROOT / "data"
GOLDEN_SET_PATH = DATA_DIR / "golden_set" / "cases.jsonl"
SAMPLE_INPUTS_PATH = DATA_DIR / "fixtures" / "sample_inputs.jsonl"
RESOLUTION_SET_PATH = DATA_DIR / "golden_set" / "entity_resolution_cases.jsonl"
_TOKEN_RE = __import__("re").compile(r"\[(?:PATIENT|HCP|ENTITY)_TKN_[0-9a-f]{16}\]")
PROMPT_VERSION = "compliance-evaluator-v2"

_SEVERITY_RANK = {Severity.S0: 0, Severity.S1: 1, Severity.S2: 2, Severity.S3: 3}
_HIGH_RISK = frozenset({Severity.S0, Severity.S1})

_FAILURE_SCENARIOS = {
    "schema_failure": "schema",
    "model_timeout": "timeout",
    "permission_denial": "permission",
}


class EvalAdapter(MockAdapter):
    """Mock adapter that deterministically fails for reserved failure scenarios.

    All other scenarios delegate to the offline fixture-based MockAdapter, so
    the evaluator stays fully deterministic and makes no network calls.
    """

    def complete(self, task_type, request, constraints):
        category = _FAILURE_SCENARIOS.get(request.scenario)
        if category is not None:
            return self._result(
                constraints=constraints, raw_json={}, error_category=category
            )
        return super().complete(task_type, request, constraints)


class EvalLiveAdapter:
    """Live adapter that still honours the reserved failure scenarios.

    The golden set deliberately contains cases that must fail (schema violation,
    timeout, permission denial) to prove the workflow degrades to human review
    instead of releasing content. A real provider would answer those cases
    normally, which would silently delete three safety assertions from the live
    report. Injecting the failure keeps the live run measuring the same
    guarantees as the offline baseline; every other case goes to the provider.
    """

    provider = "live"

    def __init__(self, prompts_dir: str | Path | None = None) -> None:
        from compliance_guard.llm.live_adapter import LiveHttpAdapter

        self._live = LiveHttpAdapter(prompts_dir=prompts_dir)

    def complete(self, task_type, request, constraints):
        category = _FAILURE_SCENARIOS.get(request.scenario)
        if category is not None:
            from compliance_guard.llm.types import RawModelResult

            return RawModelResult(
                provider=self.provider,
                model_id=constraints.model_id,
                profile_id=constraints.profile_id,
                route_version=constraints.route_version,
                raw_json={},
                error_category=category,
            )
        return self._live.complete(task_type, request, constraints)


class _Services:
    """Namespace holding the composed services for one evaluation run."""

    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


def build_services(*, mode: str = "mock", workdir: str | Path | None = None) -> _Services:
    """Compose the shared workflow services exactly like the app and tests.

    ``mode="mock"`` keeps the run fully offline and deterministic, which is what
    the regression suite depends on. ``mode="live"`` routes the same golden set
    through the real provider so accuracy and latency can be measured against
    the model that will actually run in production. Everything else -- policy
    engine, label facts, audit -- is identical, so a live run is comparable to
    the offline baseline rather than a different pipeline.
    """
    root = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="compliance-eval-"))
    registry = ModelRegistry(
        profiles_path=CONFIG_DIR / "model_profiles.json",
        routes_path=CONFIG_DIR / "task_routes.json",
        runtime_path=root / "runtime_config.json",
        prompts_dir=CONFIG_DIR / "prompts",
    )
    registry.load_defaults()
    auth = AuthorizationService()
    ledger = AuditLedger(path=root / "audit_ledger.jsonl")
    tracer = Tracer()
    metrics = Metrics()
    # Both adapters honour the reserved failure scenarios, so the safety
    # assertions hold in either mode; only the source of ordinary answers differs.
    gateway = ModelGateway(
        mock_adapter=EvalAdapter(),
        live_adapter=EvalLiveAdapter(prompts_dir=CONFIG_DIR / "prompts") if mode == "live" else None,
        prompts_dir=CONFIG_DIR / "prompts",
    )
    review_queue = ReviewQueue(auth=auth, ledger=ledger, metrics=metrics)
    decisions = DecisionService(
        queue=review_queue, auth=auth, ledger=ledger, metrics=metrics
    )
    orchestrator = Orchestrator(
        gateway=gateway,
        registry=registry,
        policy_store=PolicyBundleStore(),
        label_facts_store=LabelFactsStore(),
        retriever=EvidenceRetriever(),
        auth=auth,
        ledger=ledger,
        tracer=tracer,
        metrics=metrics,
        review_queue=review_queue,
        decisions=decisions,
        prompt_version=PROMPT_VERSION,
    )
    return _Services(
        gateway=gateway,
        registry=registry,
        policy_store=PolicyBundleStore(),
        label_facts_store=LabelFactsStore(),
        retriever=EvidenceRetriever(),
        auth=auth,
        ledger=ledger,
        tracer=tracer,
        metrics=metrics,
        review_queue=review_queue,
        decisions=decisions,
        orchestrator=orchestrator,
    )


def load_cases(path: str | Path | None = None) -> list[dict[str, Any]]:
    source = Path(path) if path else GOLDEN_SET_PATH
    cases: list[dict[str, Any]] = []
    with source.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            cases.append(json.loads(line))
    return cases


def load_sample_inputs(path: str | Path | None = None) -> list[dict[str, Any]]:
    source = Path(path) if path else SAMPLE_INPUTS_PATH
    samples: list[dict[str, Any]] = []
    with source.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            samples.append(json.loads(line))
    return samples


def build_request(case: dict[str, Any]) -> CheckCaseRequest:
    """Build a deterministic CheckCaseRequest from a golden-case row."""
    return CheckCaseRequest(
        case_id=case["case_id"],
        tenant_id=case.get("tenant_id", "TENANT-CN"),
        content=case["content"],
        content_parts=[],
        source=case.get("source", "customer_interaction_note"),
        source_record_id=case.get("source_record_id", f"SR-{case['case_id']}"),
        source_version=case.get("source_version", "v1"),
        market=case.get("market", "CN"),
        language=case.get("language", "zh-CN"),
        product_id=case.get("product_id", "PRODUCT-001"),
        channel=case.get("channel", "customer_interaction_note"),
        received_at=datetime(2026, 8, 20, tzinfo=UTC),
        idempotency_key=f"idem-{case['case_id']}",
        extensions={
            "scenario": case.get("scenario", "normal"),
            "entities": [{"type": "patient", "token": "患者"}],
            "structured_fields": case.get("structured_fields") or {},
        },
    )


def _min_severity(severities: list[Severity]) -> Severity | None:
    return min(severities, key=lambda value: _SEVERITY_RANK[value]) if severities else None


def run_case(case: dict[str, Any], services: _Services) -> dict[str, Any]:
    """Run one golden case and return a measured, comparable result row."""
    request = build_request(case)
    started = time.perf_counter()
    response = services.orchestrator.run_check_case(request)
    latency_ms = (time.perf_counter() - started) * 1000.0

    tasks = services.review_queue.for_case(response.case_id)
    review_roles = {task.required_role.value for task in tasks}

    finding_severities = [finding.severity for finding in response.findings]
    task_severities = [task.severity for task in tasks if task.severity is not None]
    effective = (
        _min_severity(finding_severities)
        or _min_severity(task_severities)
        or Severity.S3
    )
    actual_severity = effective.value if effective else None

    actual_finding_types = {finding.type for finding in response.findings}
    expected_severity = case.get("expected_severity")
    expected_finding_type = case.get("expected_finding_type")
    expected_roles = set(case.get("expected_roles") or [])

    decision_matched = response.decision.value == case.get("expected_decision")
    severity_matched = expected_severity is None or actual_severity == expected_severity
    finding_matched = not expected_finding_type or expected_finding_type in actual_finding_types
    roles_matched = expected_roles <= review_roles if expected_roles else True

    high_risk_with_refs = [
        finding.type
        for finding in response.findings
        if finding.severity in _HIGH_RISK and finding.evidence_refs
    ]
    high_risk_gaps = [
        finding.type
        for finding in response.findings
        if finding.severity in _HIGH_RISK
        and not finding.evidence_refs
        and finding.evidence_gap
    ]
    uncovered_high_risk = [
        finding.type
        for finding in response.findings
        if finding.severity in _HIGH_RISK
        and not (bool(finding.evidence_refs) or finding.evidence_gap)
    ]

    evidence_versions = {item.version for item in response.evidence}
    label_version = response.product.label_version
    cross_version = len(evidence_versions) > 1 or bool(evidence_versions - {label_version})

    dangerous = False
    if response.decision is Decision.ALLOW:
        if case.get("expected_decision") != "allow":
            dangerous = True
        elif any(finding.severity in _HIGH_RISK for finding in response.findings):
            dangerous = True

    injection_flagged = any(
        finding.type == "prompt_injection" for finding in response.security_findings
    ) or bool(case.get("injection"))
    permission_denial = bool(case.get("permission_denial")) or case.get("scenario") == "permission_denial"

    audit_ok = bool(response.audit_event_id) and bool(
        services.ledger.for_case(response.case_id)
    ) and bool(services.tracer.spans(case_id=response.case_id))

    return {
        "case_id": case["case_id"],
        "category": case.get("category", ""),
        "holdout": bool(case.get("holdout", False)),
        "note": case.get("note", ""),
        "expected_decision": case.get("expected_decision"),
        "expected_severity": expected_severity,
        "expected_finding_type": expected_finding_type,
        "expected_roles": sorted(expected_roles),
        "actual_decision": response.decision.value,
        "actual_status": response.status.value,
        "actual_severity": actual_severity,
        "actual_finding_types": sorted(actual_finding_types),
        "review_roles": sorted(review_roles),
        "decision_matched": decision_matched,
        "severity_matched": severity_matched,
        "finding_matched": finding_matched,
        "roles_matched": roles_matched,
        "matched": decision_matched and severity_matched and finding_matched and roles_matched,
        "dangerous_false_allow": dangerous,
        "high_risk_with_refs": high_risk_with_refs,
        "high_risk_gaps": high_risk_gaps,
        "uncovered_high_risk": uncovered_high_risk,
        "cross_version": cross_version,
        "injection_flagged": injection_flagged,
        "permission_denial": permission_denial,
        "audit_ok": audit_ok,
        "latency_ms": round(latency_ms, 3),
        "knowledge_snapshot_id": response.knowledge_snapshot_id,
        "route_version": response.route_version,
        "model_profile_id": response.model_profile_id,
        "model_version": response.model_version,
        "prompt_version": response.prompt_version,
    }


def _collect_versions(services: _Services, results: list[dict[str, Any]]) -> dict[str, Any]:
    snapshots = sorted({row["knowledge_snapshot_id"] for row in results if row["knowledge_snapshot_id"]})
    routes = sorted({row["route_version"] for row in results if row["route_version"]})
    profiles = sorted({row["model_profile_id"] for row in results if row["model_profile_id"]})
    models = sorted({row["model_version"] for row in results if row["model_version"]})
    prompts = sorted({row["prompt_version"] for row in results if row["prompt_version"]})
    return {
        "policy_version": services.policy_store.current().policy_version,
        "knowledge_snapshot_id": snapshots[0] if snapshots else None,
        "knowledge_snapshots": snapshots,
        "route_version": routes[0] if routes else "routes-v1",
        "route_versions": routes,
        "model_profile_id": profiles[0] if profiles else None,
        "model_profile_ids": profiles,
        "model_version": models[0] if models else None,
        "prompt_version": prompts[0] if prompts else PROMPT_VERSION,
        "registry_version": services.registry.current_snapshot().version,
        "code_version": _code_version(),
    }


def _code_version() -> str:
    try:
        with (_PROJECT_ROOT / "pyproject.toml").open(encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped.startswith("version"):
                    return stripped.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return "unknown"


def _protected_role_ok(services: _Services) -> bool:
    """A protected role action must never succeed without permission."""
    unauthorized = Actor(actor_id="demo-field-rep", role=Role.FIELD_REP)
    if services.auth.can(unauthorized, "config_publish") or services.auth.can(
        unauthorized, "config_rollback"
    ):
        return False
    for task in services.review_queue.all():
        try:
            services.decisions.record(task.task_id, "accepted", "red-team probe", unauthorized)
        except PermissionError:
            return True
        return False
    return True


def _policy_finding_types(services: _Services) -> list[dict[str, Any]]:
    """Every finding type the shipped policy bundle can emit."""
    bundle = services.policy_store.load()
    return [{"type": rule.get("type")} for rule in bundle.rules.values() if rule.get("type")]


def _measure_l1_latency(services: _Services, samples: int = 25) -> float:
    """p95 of the deterministic pre-check path, in milliseconds.

    Uses a narrative with a name, a patient and a symptom so masking, resolution,
    field resolution and rule matching all run -- timing the empty case would
    measure nothing that happens in practice.

    p95 rather than the mean: an average hides the tail, and the tail is what a
    person actually notices while typing.
    """
    precheck = PrecheckService(
        policy_store=services.policy_store,
        label_facts_store=services.label_facts_store,
    )
    content = "今天拜访了章三，患者李四服药后出现皮疹，章医生建议停药观察。"
    timings: list[float] = []
    for _ in range(max(1, samples)):
        started = time.perf_counter()
        precheck.run(content, tenant_id="TENANT-CN", product_id="PRODUCT-001", market="CN")
        timings.append((time.perf_counter() - started) * 1000)
    timings.sort()
    return timings[max(0, int(len(timings) * 0.95) - 1)]


def _measure_l2_latency(results: list[dict[str, Any]]) -> float:
    """p95 of the full submit path, in milliseconds.

    Reuses the per-case timings already collected: every golden case ran the whole
    pipeline including the model call, so a separate measurement pass would time the
    same work twice.

    The mode is reported alongside the number because the two are not comparable. In
    mock mode this is single-digit milliseconds; against a real provider the same
    path measured 5.1-19.7s p95 on this host. Publishing the mock figure without the
    caveat would set an expectation no provider honours.
    """
    timings = sorted(row["latency_ms"] for row in results)
    if not timings:
        return 0.0
    return timings[max(0, int(len(timings) * 0.95) - 1)]


def _off_label_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Precision, recall and unresolved rate for the off-label judgement.

    Precision and recall are kept apart on purpose. Most golden cases are not
    off-label, so a single accuracy number would stay high even if detection stopped
    working entirely -- the class imbalance would hide the one regression that
    matters. Reported separately, a drop in recall is unmissable.

    ``unresolved_rate`` is the operational counterpart: it rises when the ontology
    falls behind the vocabulary reps actually use, which shows up as more clarifying
    questions rather than as a wrong answer.
    """
    expected_off_label = [
        row for row in results if row.get("expected_finding_type") == "off_label"
    ]
    flagged = [row for row in results if "off_label" in row["actual_finding_types"]]

    true_positives = [row for row in flagged if row.get("expected_finding_type") == "off_label"]
    detected = [row for row in expected_off_label if "off_label" in row["actual_finding_types"]]
    unresolved = [
        row for row in results if "unresolved_indication" in row["actual_finding_types"]
    ]

    return {
        # Of the cases called off-label, how many really are.
        "precision": _ratio(len(true_positives), len(flagged)),
        # Of the cases that are off-label, how many were caught.
        "recall": _ratio(len(detected), len(expected_off_label)),
        # How often the ontology could not place the indication at all.
        "unresolved_rate": _ratio(len(unresolved), len(results)),
        "flagged_cases": [row["case_id"] for row in flagged],
        "missed_cases": [
            row["case_id"]
            for row in expected_off_label
            if "off_label" not in row["actual_finding_types"]
        ],
    }


def build_eval_report(
    *,
    output: str | Path | None = None,
    mode: str = "mock",
    cases: list[dict[str, Any]] | None = None,
    services: _Services | None = None,
) -> dict[str, Any]:
    """Run the golden set and return (and optionally write) the release-gate report."""
    services = services or build_services(mode=mode)
    case_rows = cases if cases is not None else load_cases()
    results = [run_case(case, services) for case in case_rows]

    categories: dict[str, dict[str, int]] = {}
    for case, row in zip(case_rows, results):
        name = case.get("category", "unknown")
        summary = categories.setdefault(name, {"total": 0, "passed": 0, "failed": 0})
        summary["total"] += 1
        if row["matched"]:
            summary["passed"] += 1
        else:
            summary["failed"] += 1

    matched_cases = sum(1 for row in results if row["matched"])
    dangerous = [row for row in results if row["dangerous_false_allow"]]
    covered_with_refs = sum(len(row["high_risk_with_refs"]) for row in results)
    explicit_gaps = sum(len(row["high_risk_gaps"]) for row in results)
    uncovered = sum(len(row["uncovered_high_risk"]) for row in results)
    high_risk_findings = covered_with_refs + explicit_gaps + uncovered
    injection_rows = [row for row in results if row["injection_flagged"]]
    injection_block = sum(1 for row in injection_rows if row["actual_decision"] == "blocked")
    injection_not_allowed = all(row["actual_decision"] != "allow" for row in injection_rows)
    permission_rows = [row for row in results if row["permission_denial"]]
    permission_honored = all(row["actual_decision"] != "allow" for row in permission_rows)
    cross_version_rows = [row for row in results if row["cross_version"]]
    audit_incomplete = [row for row in results if not row["audit_ok"]]

    latencies = sorted(row["latency_ms"] for row in results)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    p95_latency = latencies[max(0, int(len(latencies) * 0.95) - 1)] if latencies else 0.0

    versions = _collect_versions(services, results)

    # Masking, source fidelity and coreference are measured here rather than only
    # in their own report: a floor that is measured but does not gate is a floor a
    # regression walks straight through, discovered afterwards in a JSON file.
    resolution = build_resolution_report()

    # L1 is the pre-check budget. The typing path only works if it stays inside
    # it, so it is a release condition rather than an observation.
    l1_p95 = _measure_l1_latency(services)
    l2_p95 = _measure_l2_latency(results)
    off_label = _off_label_metrics(results)

    # A rule with no plain-language wording reaches a representative as a bare
    # code, which is the failure the glossary exists to prevent.
    glossary_missing = default_glossary().missing_finding_types(
        sorted({row["type"] for row in _policy_finding_types(services)})
    )

    gate_checks = {
        "gate_dangerous_false_allow": len(dangerous) == 0,
        "gate_high_risk_evidence": uncovered == 0,
        "gate_no_cross_version_release": len(cross_version_rows) == 0,
        "gate_audit_complete": len(audit_incomplete) == 0,
        "gate_injection_blocked": bool(injection_rows) and injection_not_allowed,
        "gate_permission_honored": bool(permission_rows) and permission_honored,
        "gate_protected_role": _protected_role_ok(services),
        # Compliance floors: exact, not "high enough".
        "gate_masking_recall": resolution["masking_recall"]["rate"] == 1.0,
        "gate_source_fidelity": resolution["source_fidelity"]["rate"] == 1.0,
        # Merging two people misattributes clinical opinion, so this is tighter
        # than the accuracy target it sits beside.
        "gate_wrong_merge_rate": resolution["wrong_merge_rate"]["rate"] <= 0.01,
        "gate_coreference_accuracy": resolution["coreference_accuracy"]["rate"] >= 0.95,
        "gate_l1_latency": l1_p95 < L1_BUDGET_MS,
        "gate_l2_latency": l2_p95 < L2_BUDGET_MS,
        # Recall is the expensive direction: a missed off-label claim leaves
        # non-compliant content in circulation, while a false one costs a review.
        "gate_off_label_accuracy": (
            off_label["recall"]["rate"] >= 0.9 and off_label["precision"]["rate"] >= 0.9
        ),
        "gate_glossary_coverage": not glossary_missing,
    }

    reasons: list[str] = []
    if not gate_checks["gate_dangerous_false_allow"]:
        reasons.append("dangerous false allow detected")
    if not gate_checks["gate_high_risk_evidence"]:
        reasons.append("S0/S1 finding lacks evidence or evidence_gap")
    if not gate_checks["gate_no_cross_version_release"]:
        reasons.append("cross-version evidence released")
    if not gate_checks["gate_audit_complete"]:
        reasons.append("audit spans missing for some cases")
    if not gate_checks["gate_injection_blocked"]:
        reasons.append("known injection allowed to alter workflow")
    if not gate_checks["gate_permission_honored"]:
        reasons.append("permission-denial case not honored")
    if not gate_checks["gate_protected_role"]:
        reasons.append("protected role action succeeded without permission")
    if not gate_checks["gate_masking_recall"]:
        reasons.append("an identifier that must be masked was not masked")
    if not gate_checks["gate_source_fidelity"]:
        reasons.append("masking damaged non-identifier text")
    if not gate_checks["gate_wrong_merge_rate"]:
        reasons.append("two different people were merged into one identity")
    if not gate_checks["gate_coreference_accuracy"]:
        reasons.append("coreference accuracy below 0.95")
    if not gate_checks["gate_l1_latency"]:
        reasons.append(f"pre-check p95 {l1_p95:.1f}ms exceeds the {L1_BUDGET_MS}ms budget")
    if not gate_checks["gate_l2_latency"]:
        reasons.append(f"submit-path p95 {l2_p95:.1f}ms exceeds the {L2_BUDGET_MS}ms budget")
    if not gate_checks["gate_off_label_accuracy"]:
        reasons.append(
            "off-label precision/recall below 0.90: "
            f"precision {off_label['precision']['rate']}, recall {off_label['recall']['rate']}"
        )
    if not gate_checks["gate_glossary_coverage"]:
        reasons.append(
            "finding types without plain-language wording: " + ", ".join(glossary_missing)
        )

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": mode,
        "total_cases": len(case_rows),
        "categories": categories,
        "results": results,
        "matched_cases": matched_cases,
        "matched_rate": round(matched_cases / len(case_rows), 4) if case_rows else 0.0,
        "dangerous_false_allows": len(dangerous),
        "dangerous_false_allow_cases": [row["case_id"] for row in dangerous],
        "evidence_coverage": {
            "high_risk_findings": high_risk_findings,
            "covered_with_refs": covered_with_refs,
            "explicit_gaps": explicit_gaps,
            "uncovered": uncovered,
        },
        "injection_cases": len(injection_rows),
        "injection_block_count": injection_block,
        "injection_not_allowed": injection_not_allowed,
        "permission_denial_cases": len(permission_rows),
        "permission_denied_honored": permission_honored,
        "cross_version_releases": len(cross_version_rows),
        "cross_version_release_cases": [row["case_id"] for row in cross_version_rows],
        "audit_complete_cases": len(results) - len(audit_incomplete),
        "audit_incomplete_cases": len(audit_incomplete),
        "avg_latency_ms": round(avg_latency, 3),
        "max_latency_ms": round(latencies[-1], 3) if latencies else 0.0,
        "p95_latency_ms": round(p95_latency, 3),
        "l1_p95_ms": round(l1_p95, 3),
        "l1_budget_ms": L1_BUDGET_MS,
        "l2_p95_ms": round(l2_p95, 3),
        "l2_budget_ms": L2_BUDGET_MS,
        # Stated because a mock figure and a live figure differ by three orders of
        # magnitude and must never be read as the same measurement.
        "l2_latency_mode": mode,
        "off_label": off_label,
        # Full masking/resolution measurement, with denominators attached: a bare
        # percentage hides the sample size, which is exactly what matters when a
        # small per-category count cannot distinguish 0.98 from 0.95.
        "entity_resolution": {
            key: resolution[key]
            for key in (
                "masking_recall",
                "source_fidelity",
                "coreference_accuracy",
                "wrong_merge_rate",
                "false_positive_masking",
                "ambiguity_detection",
                "total_cases",
            )
        },
        "glossary_missing_terms": glossary_missing,
        "versions": versions,
        "policy_version": versions["policy_version"],
        "knowledge_snapshot_id": versions["knowledge_snapshot_id"],
        "route_version": versions["route_version"],
        "gate_checks": gate_checks,
        "release_gate": "pass" if all(gate_checks.values()) else "fail",
        "release_gate_reasons": reasons,
    }

    if output is not None:
        target = Path(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def _ratio(numerator: int, denominator: int) -> dict[str, Any]:
    """A metric with its denominator attached.

    A bare percentage hides its sample size, which matters most exactly where
    these numbers are used -- small per-category counts cannot distinguish 0.98
    from 0.95 recall. Every metric therefore reports numerator and denominator.
    """
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": round(numerator / denominator, 4) if denominator else 0.0,
    }


def load_resolution_cases(path: str | Path | None = None) -> list[dict[str, Any]]:
    source = Path(path) if path else RESOLUTION_SET_PATH
    cases: list[dict[str, Any]] = []
    with source.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def _roster_for(case: dict[str, Any]) -> list[KnownIdentifier]:
    return [
        KnownIdentifier(
            entity_type=entry["entity_type"],
            canonical_id=entry["canonical_id"],
            values=list(entry.get("values") or []),
        )
        for entry in (case.get("roster") or [])
    ]


def _cluster_texts(clusters) -> list[list[str]]:
    return [sorted(member.text for member in cluster.members) for cluster in clusters]


def _grouping_score(expected: list[list[str]], actual: list[list[str]]) -> tuple[int, int]:
    """Mentions grouped as expected, and mentions wrongly merged together.

    Greedy best-overlap matching between expected and actual clusters. A mention
    counts as correct only when it lands in the actual cluster that best matches
    its expected cluster, so splitting one person into two clusters costs the
    surplus mentions rather than passing silently.
    """
    remaining = [list(group) for group in actual]
    correct = 0
    for expected_group in expected:
        best_index, best_overlap = None, 0
        for index, actual_group in enumerate(remaining):
            overlap = 0
            pool = list(actual_group)
            for text in expected_group:
                if text in pool:
                    pool.remove(text)
                    overlap += 1
            if overlap > best_overlap:
                best_index, best_overlap = index, overlap
        if best_index is None:
            continue
        matched = remaining.pop(best_index)
        # Correct only if that cluster contains nothing beyond this person.
        correct += best_overlap if len(matched) == best_overlap else 0
    return correct, 0


def _wrong_merges(expected: list[list[str]], actual: list[list[str]]) -> int:
    """Actual clusters spanning more than one expected person."""
    owner_of: dict[str, int] = {}
    for owner, group in enumerate(expected):
        for text in group:
            owner_of.setdefault(text, owner)
    merged = 0
    for group in actual:
        owners = {owner_of[text] for text in group if text in owner_of}
        if len(owners) > 1:
            merged += 1
    return merged


def run_resolution_case(case: dict[str, Any]) -> dict[str, Any]:
    """Mask one fixture and measure masking, fidelity and grouping."""
    content = case["content"]
    gateway = PiiGateway()
    context = SanitizeContext(
        tenant_id="TENANT-CN",
        known_identifiers=_roster_for(case),
        case_id=case["case_id"],
    )
    sanitized = gateway.sanitize(content, context)
    resolution = resolve_mentions(
        content,
        known_identifiers=_roster_for(case),
        case_id=case["case_id"],
    )

    must_mask = list(case.get("must_mask") or [])
    must_preserve = list(case.get("must_preserve") or [])
    masked_hits = [value for value in must_mask if value not in sanitized.model_text]
    preserved_hits = [value for value in must_preserve if value in sanitized.model_text]

    expected = [sorted(group) for group in (case.get("expected_clusters") or [])]
    actual = _cluster_texts(resolution.clusters)
    expected_mentions = sum(len(group) for group in expected)
    correct_mentions, _ = _grouping_score(expected, actual)
    wrong_merges = _wrong_merges(expected, actual)

    expects_no_masking = not must_mask
    masked_anything = bool(sanitized.entities)
    expect_ambiguous = bool(case.get("expect_ambiguous"))

    return {
        "case_id": case["case_id"],
        "note": case.get("note", ""),
        "masked_text": sanitized.model_text,
        "must_mask_total": len(must_mask),
        "must_mask_satisfied": len(masked_hits),
        "masked_all_required": len(masked_hits) == len(must_mask),
        "must_preserve_total": len(must_preserve),
        "must_preserve_satisfied": len(preserved_hits),
        "preserved_context": len(preserved_hits) == len(must_preserve),
        "expected_mentions": expected_mentions,
        "correct_mentions": correct_mentions,
        "expected_clusters": len(expected),
        "actual_clusters": len(actual),
        "wrong_merges": wrong_merges,
        "expects_no_masking": expects_no_masking,
        "false_positive_masking": expects_no_masking and masked_anything,
        "expect_ambiguous": expect_ambiguous,
        "ambiguous_detected": resolution.ambiguous,
        "ambiguity_correct": resolution.ambiguous == expect_ambiguous,
        "resolution_bases": sorted({c.resolution_basis for c in resolution.clusters}),
    }


def build_resolution_report(
    *,
    output: str | Path | None = None,
    cases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Measure masking recall, source fidelity and coreference quality."""
    case_rows = cases if cases is not None else load_resolution_cases()
    results = [run_resolution_case(case) for case in case_rows]

    masking = _ratio(
        sum(row["must_mask_satisfied"] for row in results),
        sum(row["must_mask_total"] for row in results),
    )
    fidelity = _ratio(
        sum(row["must_preserve_satisfied"] for row in results),
        sum(row["must_preserve_total"] for row in results),
    )
    coreference = _ratio(
        sum(row["correct_mentions"] for row in results),
        sum(row["expected_mentions"] for row in results),
    )
    wrong_merge = _ratio(
        sum(row["wrong_merges"] for row in results),
        sum(row["actual_clusters"] for row in results),
    )
    false_positive = _ratio(
        sum(1 for row in results if row["false_positive_masking"]),
        sum(1 for row in results if row["expects_no_masking"]),
    )
    ambiguity = _ratio(
        sum(1 for row in results if row["expect_ambiguous"] and row["ambiguity_correct"]),
        sum(1 for row in results if row["expect_ambiguous"]),
    )

    gate_checks = {
        # Masking and fidelity are compliance floors, not tunable targets.
        "gate_masking_recall": masking["rate"] == 1.0,
        "gate_source_fidelity": fidelity["rate"] == 1.0,
        "gate_coreference_accuracy": coreference["rate"] >= 0.95,
        "gate_wrong_merge_rate": wrong_merge["rate"] <= 0.01,
        "gate_no_false_positive_masking": false_positive["numerator"] == 0,
        "gate_ambiguity_detected": ambiguity["denominator"] > 0
        and ambiguity["numerator"] == ambiguity["denominator"],
    }
    reasons = [name for name, passed in gate_checks.items() if not passed]

    report = {
        "schema": "compliance-ai-guard/entity-resolution-report/v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "total_cases": len(results),
        "masking_recall": masking,
        "source_fidelity": fidelity,
        "coreference_accuracy": coreference,
        "wrong_merge_rate": wrong_merge,
        "false_positive_masking": false_positive,
        "ambiguity_detection": ambiguity,
        "gate_checks": gate_checks,
        "gate": "pass" if all(gate_checks.values()) else "fail",
        "gate_reasons": reasons,
        "results": results,
    }
    if output is not None:
        target = Path(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the golden-set evaluator and write a release-gate report."
    )
    parser.add_argument(
        "--mode",
        default="mock",
        choices=["mock", "live"],
        help=(
            "model mode; 'mock' is the default and performs no network calls, "
            "'live' runs the golden set against the configured real provider"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="path of the JSON report to write (parent directory is created)",
    )
    args = parser.parse_args(argv)

    # The gateway reads the mode from the environment, so an explicit --mode
    # must set it rather than silently running the offline baseline.
    os.environ["LLM_MODE"] = args.mode
    report = build_eval_report(output=args.output, mode=args.mode)
    summary = {
        key: report[key]
        for key in (
            "total_cases",
            "matched_cases",
            "matched_rate",
            "dangerous_false_allows",
            "injection_block_count",
            "cross_version_releases",
            "audit_incomplete_cases",
            "release_gate",
            "release_gate_reasons",
        )
    }
    print(json.dumps(summary, ensure_ascii=False))
    print(f"report written to {os.path.abspath(args.output)}")
    return 0 if report["release_gate"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
