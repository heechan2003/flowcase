"""Typed operational paths and storage controls loaded from the environment."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from network_behaviour.publication import GIB


class OperationsConfigurationError(ValueError):
    """Raised when operational controls are missing or unsafe."""


def _gib(values: Mapping[str, str], name: str, default: int) -> int:
    raw = values.get(name, str(default)).strip()
    try:
        parsed = float(raw)
    except ValueError as exc:
        raise OperationsConfigurationError(f"{name} must be numeric") from exc
    if parsed <= 0:
        raise OperationsConfigurationError(f"{name} must be positive")
    return int(parsed * GIB)


@dataclass(frozen=True, slots=True)
class OperationsPaths:
    sql_dir: Path
    lock_path: Path

    @classmethod
    def from_env(cls, database_path: Path, env: Mapping[str, str] | None = None) -> OperationsPaths:
        values = os.environ if env is None else env
        return cls(
            Path(values.get("NETWORK_BEHAVIOUR_SQL_DIR", "sql/clickhouse")),
            Path(values.get("NETWORK_BEHAVIOUR_LOCK_PATH", f"{database_path}.lock")),
        )


@dataclass(frozen=True, slots=True)
class StorageControls:
    alert_bytes: int
    stop_bytes: int

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> StorageControls:
        values = os.environ if env is None else env
        controls = cls(
            _gib(values, "NETWORK_BEHAVIOUR_STORAGE_ALERT_GIB", 40),
            _gib(values, "NETWORK_BEHAVIOUR_STORAGE_STOP_GIB", 45),
        )
        if controls.alert_bytes >= controls.stop_bytes:
            raise OperationsConfigurationError("storage alert must be below the stop threshold")
        return controls
