"""Storage reporting and verified single-file DuckDB backup/restore."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

import duckdb

from network_behaviour.operations.config import StorageControls
from network_behaviour.storage.migrations import MigrationRunner


class BackupRestoreError(RuntimeError):
    """Raised when backup or restore cannot be completed atomically and safely."""


@dataclass(frozen=True, slots=True)
class StorageReport:
    database_bytes: int
    history_client_rows: int
    history_service_rows: int
    candidate_rows: int
    alert: bool
    stop: bool

    def render(self) -> str:
        status = "stop" if self.stop else "alert" if self.alert else "ok"
        return "\n".join(
            (
                f"status: {status}",
                f"database bytes: {self.database_bytes}",
                f"history client rows: {self.history_client_rows}",
                f"history service rows: {self.history_service_rows}",
                f"complete feed candidate rows: {self.candidate_rows}",
            )
        )


def storage_report(
    connection: duckdb.DuckDBPyConnection, controls: StorageControls
) -> StorageReport:
    row = connection.execute(
        """
        SELECT
            (SELECT count(*) FROM history.client_day),
            (SELECT count(*) FROM history.client_service_day),
            (SELECT count(*) FROM feed.candidate_episode)
        """
    ).fetchone()
    if row is None:
        raise BackupRestoreError("storage row counts are unavailable")
    connection.execute("CHECKPOINT")
    size_row = connection.execute("SELECT database_size FROM pragma_database_size()").fetchone()
    if size_row is None:
        raise BackupRestoreError("database size is unavailable")
    database_bytes = _duckdb_size_bytes(str(size_row[0]))
    return StorageReport(
        database_bytes,
        int(row[0]),
        int(row[1]),
        int(row[2]),
        database_bytes >= controls.alert_bytes,
        database_bytes >= controls.stop_bytes,
    )


def create_backup(connection: duckdb.DuckDBPyConnection, database_path: Path, output: Path) -> None:
    if not database_path.is_file():
        raise BackupRestoreError("source database does not exist")
    if output.exists():
        raise BackupRestoreError("backup output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.partial")
    if temporary.exists():
        raise BackupRestoreError("backup temporary path already exists")
    connection.execute("CHECKPOINT")
    try:
        shutil.copy2(database_path, temporary)
        _verify_database(temporary)
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def restore_backup(source: Path, output: Path, migrations: Path) -> None:
    if not source.is_file():
        raise BackupRestoreError("backup source does not exist")
    if output.exists():
        raise BackupRestoreError("restore output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.restore-partial")
    if temporary.exists():
        raise BackupRestoreError("restore temporary path already exists")
    try:
        shutil.copy2(source, temporary)
        _verify_database(temporary)
        connection = duckdb.connect(str(temporary))
        try:
            MigrationRunner(migrations).apply(connection)
            connection.execute("CHECKPOINT")
        finally:
            connection.close()
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _verify_database(path: Path) -> None:
    connection = duckdb.connect(str(path), read_only=True)
    try:
        row = connection.execute("SELECT max(version) FROM _schema_migrations").fetchone()
        if row is None or row[0] is None:
            raise BackupRestoreError("backup schema version is unavailable")
        connection.execute("SELECT count(*) FROM history.client_day").fetchone()
        connection.execute("SELECT count(*) FROM feed.daily_publication").fetchone()
    finally:
        connection.close()


def _duckdb_size_bytes(raw: str) -> int:
    parts = raw.split()
    if len(parts) != 2:
        raise BackupRestoreError("DuckDB returned an unsupported size")
    try:
        value = float(parts[0])
    except ValueError as exc:
        raise BackupRestoreError("DuckDB returned an unsupported size") from exc
    scale = {"bytes": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    if parts[1] not in scale:
        raise BackupRestoreError("DuckDB returned an unsupported size")
    return int(value * scale[parts[1]])
