"""Ordered, immutable DuckDB migration application."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import duckdb

# Schema versions a published day may have been written under and still stream back. Every
# migration since 0005 is additive, so a day's rows read the same through any later schema; the
# recorded version says when it was written, not what it needs. Days at schema 7 (2026-07-13 to
# 08-09) were stranded until this list replaced strict equality with the current version. A new
# migration joins here deliberately — `tests/integration/storage/test_migrations.py` fails until
# it does.
COMPATIBLE_SCHEMA_VERSIONS = frozenset({5, 6, 7, 8, 9, 10})

_MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]{4})_(?P<name>[a-z][a-z0-9_]*)\.sql$")

# Phase 8 baseline-review migration 0006 was applied to operational databases before
# its SQL file entered this repository snapshot. Accept only that released checksum;
# every other name/checksum mismatch still fails closed.
_RELEASED_CHECKSUMS: dict[tuple[int, str], frozenset[str]] = {
    (6, "phase8_baseline_review"): frozenset(
        {"6491769659f29877c276c2a58bf1c374fe5c041961395b5a6fee9a8502dd4513"}
    ),
}


class MigrationError(RuntimeError):
    """Raised when migration ordering, integrity, or execution fails closed."""


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    sql: str
    checksum: str


class MigrationRunner:
    def __init__(self, root: Path) -> None:
        self._root = root

    def discover(self) -> tuple[Migration, ...]:
        migrations: list[Migration] = []
        for path in sorted(self._root.glob("*.sql")):
            match = _MIGRATION_NAME.fullmatch(path.name)
            if match is None:
                raise MigrationError(f"invalid migration filename: {path.name}")
            sql = path.read_text(encoding="utf-8")
            migrations.append(
                Migration(
                    version=int(match.group("version")),
                    name=match.group("name"),
                    sql=sql,
                    checksum=hashlib.sha256(sql.encode()).hexdigest(),
                )
            )
        if not migrations:
            raise MigrationError("no DuckDB migrations found")
        versions = [migration.version for migration in migrations]
        if versions != list(range(1, len(migrations) + 1)):
            raise MigrationError("migration versions must be consecutive from 0001")
        return tuple(migrations)

    def apply(
        self, connection: duckdb.DuckDBPyConnection, *, target_version: int | None = None
    ) -> int:
        migrations = self.discover()
        if target_version is not None and not 0 <= target_version <= migrations[-1].version:
            raise MigrationError("target migration version is unavailable")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS _schema_migrations (
                version INTEGER PRIMARY KEY,
                name VARCHAR NOT NULL,
                checksum VARCHAR NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL
            )
            """
        )
        applied = {
            int(version): (str(name), str(checksum))
            for version, name, checksum in connection.execute(
                "SELECT version, name, checksum FROM _schema_migrations ORDER BY version"
            ).fetchall()
        }
        for migration in migrations:
            existing = applied.get(migration.version)
            if existing is not None:
                existing_name, existing_checksum = existing
                accepted_checksums = {
                    migration.checksum,
                    *_RELEASED_CHECKSUMS.get((migration.version, migration.name), ()),
                }
                if existing_name != migration.name or existing_checksum not in accepted_checksums:
                    raise MigrationError(f"migration {migration.version:04d} integrity mismatch")
        pending = [
            migration
            for migration in migrations
            if migration.version not in applied
            and (target_version is None or migration.version <= target_version)
        ]
        for migration in pending:
            try:
                connection.execute("BEGIN TRANSACTION")
                connection.execute(migration.sql)
                connection.execute(
                    "INSERT INTO _schema_migrations VALUES (?, ?, ?, ?)",
                    [migration.version, migration.name, migration.checksum, datetime.now(UTC)],
                )
                connection.execute("COMMIT")
            except Exception as exc:
                connection.execute("ROLLBACK")
                raise MigrationError(f"migration {migration.version:04d} failed") from exc
        current = connection.execute(
            "SELECT coalesce(max(version), 0) FROM _schema_migrations"
        ).fetchone()
        if current is None:
            raise MigrationError("cannot read current migration version")
        return int(current[0])
