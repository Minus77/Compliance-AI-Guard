from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, Response

from compliance_guard.workflow.conversations import (
    ConversationExpiredError,
    ConversationNotFoundError,
    ConversationPromptMismatchError,
    ConversationStaleError,
    GenerateRequest,
    GuardInputRequest,
)

from ..errors import ApiError
from ..security import _actor_from_header


def register_routes(app: FastAPI, services: Any) -> None:
    @app.post("/api/conversations/guard-input")
    def guard_conversation_input(
        payload: GuardInputRequest,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _actor_from_header(services.auth, x_demo_role)
        try:
            result = services.conversations.guard_input(payload, actor)
        except PermissionError as error:
            raise ApiError("forbidden", 403, str(error)) from None
        except ConversationStaleError:
            raise ApiError(
                "conversation_requires_recheck",
                409,
                "input must be checked again against the current rule version",
            ) from None
        except ValueError as error:
            raise ApiError("rule_version_conflict", 409, str(error)) from None
        return result.model_dump(mode="json")

    @app.get("/api/conversations/{conversation_id}")
    def get_guarded_conversation(
        conversation_id: str,
        tenant_id: str = "",
        rule_version: str = "",
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _actor_from_header(services.auth, x_demo_role)
        tenant = actor.tenant_id or tenant_id
        if not tenant:
            raise ApiError("tenant_required", 422, "tenant_id is required")
        try:
            session = services.conversations.get(
                conversation_id,
                tenant_id=tenant,
                actor=actor,
                rule_version=rule_version,
            )
        except ConversationNotFoundError:
            raise KeyError(conversation_id) from None
        except ConversationExpiredError:
            raise ApiError(
                "conversation_expired",
                410,
                "conversation session expired; run the input guard again",
            ) from None
        except ConversationStaleError:
            raise ApiError(
                "conversation_requires_recheck",
                409,
                "rule version changed; run the input guard again",
            ) from None
        return session.model_dump(mode="json")

    @app.post("/api/conversations/{conversation_id}/generate")
    def generate_guarded_response(
        conversation_id: str,
        payload: GenerateRequest,
        response: Response,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = _actor_from_header(services.auth, x_demo_role)
        try:
            result = services.conversations.generate(
                conversation_id,
                payload,
                actor,
            )
        except ConversationNotFoundError:
            raise KeyError(conversation_id) from None
        except ConversationExpiredError:
            raise ApiError(
                "conversation_expired",
                410,
                "conversation session expired; run the input guard again",
            ) from None
        except ConversationPromptMismatchError:
            raise ApiError(
                "conversation_prompt_mismatch",
                409,
                "generation must use the input checked by the server",
            ) from None
        except ConversationStaleError:
            raise ApiError(
                "conversation_requires_recheck",
                409,
                "rule version changed; run the input guard again",
            ) from None
        except PermissionError as error:
            raise ApiError("forbidden", 403, str(error)) from None

        if result.state == "failed_safe":
            response.status_code = 503
        return result.model_dump(mode="json")
