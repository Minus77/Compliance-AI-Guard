"""Stable source-version rejection shared by connector contracts."""


class StaleVersionError(ValueError):
    """The caller supplied a version other than the current source version."""

    def __init__(
        self,
        record_id: str,
        requested_version: str,
        current_version: str,
    ) -> None:
        self.record_id = record_id
        self.requested_version = requested_version
        self.current_version = current_version
        super().__init__(
            f"source record {record_id!r} is at version {current_version!r}; "
            f"requested version {requested_version!r} was rejected"
        )


__all__ = ["StaleVersionError"]
