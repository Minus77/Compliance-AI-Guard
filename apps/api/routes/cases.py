"""Case HTTP route groups.

Registration order is part of the API contract: the static check and collection
routes must be registered before ``/api/cases/{case_id}``.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from .cases_lifecycle import register_routes as register_lifecycle_routes
from .cases_read import register_routes as register_read_routes
from .cases_trace import register_routes as register_trace_routes


def register_routes(app: FastAPI, services: Any) -> None:
    register_read_routes(app, services)
    register_lifecycle_routes(app, services)
    register_trace_routes(app, services)
