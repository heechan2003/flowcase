"""A read-only DuckDB client for the source tables, shaped like the client the runner expects.

The source SQL keeps ClickHouse-style typed placeholders (`{start:DateTime('UTC')}`), because
`source/sql.py: validate_sql` checks them. This client rewrites each one to a DuckDB parameter cast
to the matching type, binds only the parameters the query names, and reports the rows the scan read.

The connection is read-only, sees only its own file (external access is off and the configuration
locked before any query runs), runs in UTC, and interrupts a query that outlives its timeout.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import count
from pathlib import Path
from typing import Any, Protocol

import duckdb

BLOCK_ROWS = 50_000
_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*):([^{}]+)\}", re.IGNORECASE)
_QUERY_IDS = count(1)


class DuckDbSourceError(RuntimeError):
    """Raised without SQL, parameters or source values."""


class _Timer(Protocol):
    def start(self) -> None: ...

    def cancel(self) -> None: ...


def duckdb_type(clickhouse_type: str) -> str:
    """The DuckDB type a ClickHouse placeholder type binds as."""
    name = clickhouse_type.strip()
    if name.startswith("Array("):
        return duckdb_type(name[len("Array(") : -1]) + "[]"
    if name.startswith("Nullable("):
        return duckdb_type(name[len("Nullable(") : -1])
    if name.startswith("DateTime"):
        return "TIMESTAMPTZ"
    if name.startswith("Date"):
        return "DATE"
    if name in {"String", "FixedString", "IPv4", "IPv6"} or name.startswith("FixedString("):
        return "VARCHAR"
    if name.startswith(("UInt", "Int")):
        return "BIGINT"
    if name.startswith("Float"):
        return "DOUBLE"
    if name == "Bool":
        return "BOOLEAN"
    raise DuckDbSourceError(f"unsupported placeholder type {name}")


def translate(query: str) -> tuple[str, tuple[str, ...]]:
    """Rewrite typed placeholders to DuckDB parameters. Returns the SQL and the names it binds."""
    names: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in names:
            names.append(name)
        return f"CAST(${name} AS {duckdb_type(match.group(2))})"

    return _PLACEHOLDER.sub(replace, query), tuple(names)


@dataclass(slots=True)
class DuckDbResult:
    column_names: Sequence[str]
    result_rows: Sequence[Sequence[Any]]
    query_id: str | None
    summary: Mapping[str, Any] = field(default_factory=dict)

    @property
    def row_count(self) -> int:
        return len(self.result_rows)


@dataclass(slots=True)
class DuckDbStreamSource:
    column_names: Sequence[str]
    query_id: str | None
    summary: dict[str, Any] = field(default_factory=dict)
    result_rows: Sequence[Sequence[Any]] = ()

    @property
    def row_count(self) -> int:
        return 0


class DuckDbBlockStream:
    """Row blocks of one executed query. `source.summary` is filled once the blocks are read."""

    def __init__(
        self, client: DuckDbSourceClient, source: DuckDbStreamSource, timer: _Timer
    ) -> None:
        self._client = client
        self.source = source
        self._timer = timer

    def __enter__(self) -> Iterator[Sequence[Sequence[Any]]]:
        return self._blocks()

    def __exit__(self, *_args: object) -> None:
        self._timer.cancel()

    def _blocks(self) -> Iterator[Sequence[Sequence[Any]]]:
        connection = self._client.connection
        try:
            while block := connection.fetchmany(BLOCK_ROWS):
                yield block
        finally:
            self._timer.cancel()
        self.source.summary.update(self._client.profile())


class DuckDbSourceClient:
    def __init__(self, path: Path) -> None:
        if not path.is_file():
            raise DuckDbSourceError("source database not found; load Zeek logs first")
        try:
            self.connection = duckdb.connect(str(path), read_only=True)
        except duckdb.Error as exc:
            raise DuckDbSourceError("cannot open the source database read-only") from exc
        for statement in (
            "SET TimeZone = 'UTC'",
            "PRAGMA enable_profiling = 'no_output'",
            """SET custom_profiling_settings = '{"CUMULATIVE_ROWS_SCANNED": "true"}'""",
            "SET enable_external_access = false",
            "SET lock_configuration = true",
        ):
            self.connection.execute(statement)

    def query(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
    ) -> DuckDbResult:
        query_id, timer = self._execute(query, parameters, settings)
        try:
            columns = self._columns()
            rows = self.connection.fetchall()
        finally:
            timer.cancel()
        return DuckDbResult(columns, rows, query_id, self.profile())

    def query_row_block_stream(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
    ) -> DuckDbBlockStream:
        query_id, timer = self._execute(query, parameters, settings)
        return DuckDbBlockStream(self, DuckDbStreamSource(self._columns(), query_id), timer)

    def close(self) -> None:
        self.connection.close()

    def profile(self) -> dict[str, int]:
        try:
            info = json.loads(self.connection.get_profiling_information(format="json"))
        except (duckdb.Error, ValueError):
            return {}
        return {"read_rows": int(info.get("cumulative_rows_scanned", 0) or 0), "read_bytes": 0}

    def _execute(
        self,
        query: str,
        parameters: Mapping[str, Any] | None,
        settings: Mapping[str, Any] | None,
    ) -> tuple[str, _Timer]:
        text, names = translate(query)
        given = dict(parameters or {})
        missing = [name for name in names if name not in given]
        if missing:
            raise DuckDbSourceError(f"query parameter {missing[0]} was not supplied")
        timeout = float((settings or {}).get("max_execution_time", 0) or 0)
        timer: _Timer = (
            threading.Timer(timeout, self.connection.interrupt) if timeout > 0 else _NoTimer()
        )
        timer.start()
        try:
            self.connection.execute(text, {name: given[name] for name in names})
        except BaseException:
            timer.cancel()
            raise
        return f"duckdb-{next(_QUERY_IDS)}", timer

    def _columns(self) -> tuple[str, ...]:
        description = self.connection.description or ()
        return tuple(str(column[0]) for column in description)


class _NoTimer:
    def start(self) -> None:
        return None

    def cancel(self) -> None:
        return None
