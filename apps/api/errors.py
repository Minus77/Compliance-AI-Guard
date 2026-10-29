"""Structured API errors and request validation redaction."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from compliance_guard.audit.ledger import AuditWriteError
from compliance_guard.integrations import StaleVersionError
from compliance_guard.llm.registry import DraftValidationError, RouteValidationError


class ApiError(Exception):
    """Structured, client-safe error with a stable code."""

    def __init__(self, code: str, status: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.message = message


def _error_body(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


def _redact_validation_details(details: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Strip the ``input`` field from validation details (may hold raw PII)."""
    return [
        {key: value for key, value in item.items() if key != "input"}
        for item in details
    ]


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def _on_request_validation(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "request validation failed",
                    "details": _redact_validation_details(exc.errors()),
                }
            },
        )

    @app.exception_handler(ValidationError)
    async def _on_model_validation(
        request: Request, exc: ValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "payload validation failed",
                    "details": _redact_validation_details(exc.errors()),
                }
            },
        )

    @app.exception_handler(ApiError)
    async def _on_api_error(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status, content=_error_body(exc.code, exc.message)
        )

    @app.exception_handler(PermissionError)
    async def _on_permission(request: Request, exc: PermissionError) -> JSONResponse:
        return JSONResponse(status_code=403, content=_error_body("forbidden", str(exc)))

    @app.exception_handler(KeyError)
    async def _on_key_error(request: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(
            status_code=404, content=_error_body("not_found", "resource not found")
        )

    @app.exception_handler(AuditWriteError)
    async def _on_audit_write_error(
        request: Request, exc: AuditWriteError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content=_error_body(
                "audit_unavailable",
                "the compliance record could not be stored; content was not released",
            ),
        )

    @app.exception_handler(ValueError)
    async def _on_value_error(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content=_error_body("bad_request", str(exc)))

    @app.exception_handler(DraftValidationError)
    async def _on_draft_error(
        request: Request, exc: DraftValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400, content=_error_body("draft_validation_error", str(exc))
        )

    @app.exception_handler(RouteValidationError)
    async def _on_route_error(
        request: Request, exc: RouteValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400, content=_error_body("route_validation_error", str(exc))
        )

    @app.exception_handler(StaleVersionError)
    async def _on_stale_version(
        request: Request, exc: StaleVersionError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409, content=_error_body("stale_source_version", str(exc))
        )

    @app.exception_handler(StarletteHTTPException)
    async def _on_http(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body("http_error", str(exc.detail)),
        )

    @app.exception_handler(Exception)
    async def _on_unhandled(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content=_error_body("internal_error", "unexpected internal error"),
        )
