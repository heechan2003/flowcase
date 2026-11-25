"""Single-engine DuckDB repository lifecycle."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import duckdb

from network_behaviour.storage.migrations import MigrationRunner


@dataclass(frozen=True, slots=True)
class StorageConfig:
    database_path: Path
    migration_path: Path

    def __post_init__(self) -> None:
        if self.database_path.stem.casefold() in {"history", "detect", "feed", "review", "ops"}:
            raise ValueError("DuckDB filename cannot collide with a repository schema name")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> StorageConfig:
        values = os.environ if env is None else env
        database = values.get("NETWORK_BEHAVIOUR_DUCKDB_PATH", "").strip()
        if not database:
            raise ValueError("NETWORK_BEHAVIOUR_DUCKDB_PATH is required")
        migrations = values.get("NETWORK_BEHAVIOUR_MIGRATION_DIR", "sql/migrations").strip()
        if not migrations:
            raise ValueError("NETWORK_BEHAVIOUR_MIGRATION_DIR is required")
        return cls(Path(database), Path(migrations))


class DuckDbStore:
    """Own one writable DuckDB connection and enforce migrations on open."""

    def __init__(self, config: StorageConfig) -> None:
        self._config = config
        self._connection: duckdb.DuckDBPyConnection | None = None

    def __enter__(self) -> DuckDbStore:
        self.open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @property
    def connection(self) -> duckdb.DuckDBPyConnection:
        if self._connection is None:
            raise RuntimeError("DuckDB store is not open")
        return self._connection

    def open(self) -> int:
        if self._connection is not None:
            raise RuntimeError("DuckDB store is already open")
        self._config.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = duckdb.connect(str(self._config.database_path))
        try:
            version = MigrationRunner(self._config.migration_path).apply(connection)
        except Exception:
            connection.close()
            raise
        self._connection = connection
        return version

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
