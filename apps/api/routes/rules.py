from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header

from compliance_guard.policy.bundles import parse_bundle_rules

from ..errors import ApiError
from ..schemas import RuleBatchPayload, RuleTestPayload, RuleVersionPayload
from ..security import _require_rule_manager, _require_rule_reader


def register_routes(app: FastAPI, services: Any) -> None:
    @app.get("/api/rules")
    def list_rules(x_demo_role: str | None = Header(default=None)) -> dict[str, Any]:
        _require_rule_reader(services.auth, x_demo_role)
        bundle = services.rule_lifecycle.current()
        history = services.rule_lifecycle.history()
        return {
            "current_version": services.rule_lifecycle.current_version,
            "rules": [
                rule.model_dump(mode="json")
                for rule in parse_bundle_rules(bundle)
            ],
            "history": [
                {
                    "version": item.version,
                    "status": item.status.value,
                    "created_at": item.created_at.isoformat(),
                    "published_at": (
                        item.published_at.isoformat()
                        if item.published_at is not None
                        else None
                    ),
                    "published_by": item.published_by,
                    "rule_count": len(item.rules),
                }
                for item in history
            ],
        }

    @app.post("/api/rules/test")
    def test_rule(
        payload: RuleTestPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_rule_manager(services.auth, x_demo_role)
        rules = {
            rule.rule_id: rule
            for rule in parse_bundle_rules(
                services.rule_lifecycle.bundle(payload.version)
            )
        }
        if payload.rule_id not in rules:
            raise KeyError(payload.rule_id)
        result = services.rule_workbench.test_rule(
            rules[payload.rule_id],
            payload.case,
        )
        return result.model_dump(mode="json")

    @app.post("/api/rules/evaluate")
    def evaluate_rules(
        payload: RuleBatchPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_rule_reader(services.auth, x_demo_role)
        try:
            result = services.rule_workbench.evaluate_batch(
                payload.cases,
                payload.version,
            )
        except ValueError as error:
            raise ApiError("validation_error", 422, str(error)) from None
        return result.model_dump(mode="json")

    @app.post("/api/rules/publish")
    def publish_rules(
        payload: RuleVersionPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _require_rule_manager(services.auth, x_demo_role)
        report = services.rule_lifecycle.test(payload.version)
        if not report.passed:
            messages = "; ".join(
                f"{failure.rule_id}: {failure.message}"
                for failure in report.failures
            )
            raise ApiError(
                "validation_error",
                422,
                f"rule version did not pass its tests{': ' + messages if messages else ''}",
            )
        published = services.rule_lifecycle.publish(
            payload.version,
            actor.actor_id,
        )
        return {
            "version": published.version,
            "status": published.status.value,
            "published_at": (
                published.published_at.isoformat()
                if published.published_at is not None
                else None
            ),
            "published_by": published.published_by,
        }

    @app.post("/api/rules/rollback")
    def rollback_rules(
        payload: RuleVersionPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _require_rule_manager(services.auth, x_demo_role)
        try:
            restored = services.rule_lifecycle.rollback(
                payload.version,
                actor.actor_id,
            )
        except ValueError as error:
            raise ApiError("validation_error", 422, str(error)) from None
        return {
            "version": restored.version,
            "status": restored.status.value,
            "published_at": (
                restored.published_at.isoformat()
                if restored.published_at is not None
                else None
            ),
            "published_by": restored.published_by,
        }

    @app.get("/api/rules/diff")
    def diff_rules(
        before: str,
        after: str,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_rule_reader(services.auth, x_demo_role)
        result = services.rule_workbench.diff_versions(before, after)
        return result.model_dump(mode="json")
