from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, Header

from compliance_guard.integrations import ContentSource

from ..errors import ApiError
from ..schemas import AttachmentPayload
from ..security import _actor_from_header


def register_routes(app: FastAPI, services: Any) -> None:
    @app.get("/api/sources")
    def list_sources(
        connector_id: str | None = None,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Enumerate source connectors and their available upstream records."""
        _actor_from_header(services.auth, x_demo_role)
        sources = [
            connector
            for connector in services.connectors.list()
            if connector.connector_kind == "content_source"
        ]
        source_records: list[dict[str, str]] = []
        for source_info in sources:
            if connector_id and source_info.connector_id != connector_id:
                continue
            source = services.connectors.get(source_info.connector_id)
            if isinstance(source, ContentSource):
                source_records.extend(source.records())
        return {
            "connectors": [
                connector.model_dump(mode="json") for connector in sources
            ],
            "records": sorted(source_records, key=lambda item: item["record_id"]),
        }

    @app.get("/api/sources/{connector_id}/records/{record_id}")
    def fetch_source_record(
        connector_id: str,
        record_id: str,
        version: str | None = None,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Re-read one authoritative record through its connector adapter.

        Stale event versions are rejected by the adapter, which surfaces as a
        400 rather than silently trusting the caller-supplied version.
        """
        _actor_from_header(services.auth, x_demo_role)
        source = services.connectors.get(connector_id)
        if not isinstance(source, ContentSource):
            raise ApiError(
                "not_a_content_source",
                400,
                f"connector {connector_id!r} does not expose content reads",
            )
        return source.fetch(record_id, version=version).model_dump(mode="json")

    @app.post("/api/attachments")
    def register_attachment(
        payload: AttachmentPayload,
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Register an image/audio reference and return a content part.

        Metadata only: no binary is accepted or stored. The response is shaped
        as a ``ContentPart`` so the caller can append it to ``content_parts``,
        which is what drives multimodal task classification.
        """
        _actor_from_header(services.auth, x_demo_role)
        kind = payload.kind.strip().lower()
        if kind not in {"image", "audio"}:
            raise ApiError("bad_request", 400, "kind must be 'image' or 'audio'")
        part_type = "image_ref" if kind == "image" else "audio_ref"
        digest = uuid.uuid4().hex
        metadata: dict[str, Any] = {
            "filename": payload.filename,
            "mime_type": payload.mime_type,
            "size_bytes": payload.size_bytes,
            "stored": False,
        }
        if payload.duration_seconds is not None:
            metadata["duration_seconds"] = payload.duration_seconds
        return {
            "content_part": {
                "type": part_type,
                "ref": f"mock://attachment/{kind}/{digest}",
                "metadata": metadata,
            }
        }

    @app.get("/api/connectors")
    def get_connectors(
        x_demo_role: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Connector governance view: ownership, auth mode, residency, CSV status."""
        _actor_from_header(services.auth, x_demo_role)
        connectors: list[dict[str, Any]] = []
        for connector in services.connectors.list():
            payload = connector.model_dump(mode="json")
            payload["health"] = services.connectors.health(
                connector.connector_id
            ).model_dump(mode="json")
            connectors.append(payload)
        return {
            "connectors": connectors,
            "note": (
                "Contract-only in-memory connectors. No live tenant, credential, "
                "or network call is used, and no validation or certification "
                "claim is made."
            ),
        }
