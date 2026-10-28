"""Registry for vendor-neutral connector contracts."""

from __future__ import annotations

from typing import Any

from .contracts import ConnectorContract, ConnectorInfo, HealthStatus


class ConnectorRegistryError(ValueError):
    """Base connector registry failure."""


class ConnectorAlreadyRegisteredError(ConnectorRegistryError):
    """A connector id is unique within one application."""


class ConnectorNotFoundError(ConnectorRegistryError, KeyError):
    """No connector is registered under the requested id."""


class ConnectorRegistry:
    """Register, enumerate, resolve and health-check connectors."""

    def __init__(self) -> None:
        self._connectors: dict[str, ConnectorContract] = {}

    def register(self, connector: ConnectorContract) -> ConnectorInfo:
        if not isinstance(connector, ConnectorContract):
            raise TypeError("connector does not implement ConnectorContract")
        info = connector.info
        if info.connector_id in self._connectors:
            raise ConnectorAlreadyRegisteredError(
                f"connector {info.connector_id!r} is already registered"
            )
        self._connectors[info.connector_id] = connector
        return info

    def get(self, connector_id: str) -> Any:
        connector = self._connectors.get(connector_id)
        if connector is None:
            raise ConnectorNotFoundError(f"unknown connector {connector_id!r}")
        return connector

    def list(self) -> list[ConnectorInfo]:
        return [
            self._connectors[connector_id].info
            for connector_id in sorted(self._connectors)
        ]

    def health(self, connector_id: str) -> HealthStatus:
        return self.get(connector_id).health()


__all__ = [
    "ConnectorAlreadyRegisteredError",
    "ConnectorNotFoundError",
    "ConnectorRegistry",
    "ConnectorRegistryError",
]
