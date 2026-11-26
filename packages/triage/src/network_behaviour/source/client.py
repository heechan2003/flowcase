"""Privacy-safe, read-only source query execution."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from time import monotonic
from types import TracebackType
from typing import Any, Literal, Protocol, cast

from network_behaviour.config import ConfigurationError, SourceConfig
from network_behaviour.source.duckdb_client import DuckDbSourceClient, DuckDbSourceError
from network_behaviour.source.sql import SqlKind, SqlQuery
from network_behaviour.time import UtcBounds


class SourceQueryError(RuntimeError):
    """Raised without SQL, parameters, credentials, or source identifiers."""


class QueryResultLike(Protocol):
    @property
    def column_names(self) -> Sequence[str]: ...

    @property
    def result_rows(self) -> Sequence[Sequence[Any]]: ...

    @property
    def query_id(self) -> str | None: ...

    @property
    def summary(self) -> Mapping[str, Any]: ...

    @property
    def row_count(self) -> int: ...


class RowBlockStream(Protocol):
    """An executed query's row blocks. `source` names its columns, and its `summary` holds the
    footprint once the blocks are read."""

    @property
    def source(self) -> Any: ...

    def __enter__(self) -> Iterator[Sequence[Sequence[Any]]]: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...


class ClientLike(Protocol):
    def query(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
    ) -> QueryResultLike: ...

    def query_row_block_stream(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
    ) -> RowBlockStream: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class QueryAudit:
    query_name: str
    query_version: int
    query_id: str
    elapsed_seconds: float
    returned_rows: int
    read_rows: int
    read_bytes: int
    aggregate_only: bool
    status: str


def bytes_read(read_bytes: int, *, unit: Literal["bytes", "GB"] = "bytes") -> str:
    """`, N bytes read` (or `, N.NN GB read`) for a footprint line, or nothing when the source did
    not measure bytes.

    DuckDB reports rows scanned but no bytes, so its `read_bytes` is always 0; a source that
    measures bytes and read anything reports more than 0.
    """
    if not read_bytes:
        return ""
    size = f"{read_bytes / 1e9:.2f} GB" if unit == "GB" else f"{read_bytes:,} bytes"
    return f", {size} read"


class AuditSink(Protocol):
    def record(self, audit: QueryAudit) -> None: ...


class LoggingAuditSink:
    """Emit only query metadata, never SQL, parameters, or source identifiers."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("network_behaviour.source")

    def record(self, audit: QueryAudit) -> None:
        self._logger.info(
            "source query completed",
            extra={
                "query_name": audit.query_name,
                "query_version": audit.query_version,
                "query_id": audit.query_id,
                "elapsed_seconds": audit.elapsed_seconds,
                "returned_rows": audit.returned_rows,
                "read_rows": audit.read_rows,
                "read_bytes": audit.read_bytes,
                "aggregate_only": audit.aggregate_only,
                "status": audit.status,
            },
        )


@dataclass(frozen=True, slots=True)
class QueryOutcome:
    column_names: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]
    audit: QueryAudit

    def dictionaries(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(zip(self.column_names, row, strict=True)) for row in self.rows)


def create_source_client(config: SourceConfig) -> ClientLike:
    """Open the source tables read-only."""
    try:
        return cast(ClientLike, DuckDbSourceClient(config.path))
    except DuckDbSourceError as exc:
        raise ConfigurationError(f"source unavailable: {exc}") from exc


class ReadOnlyQueryRunner:
    def __init__(self, client: ClientLike, audit_sink: AuditSink | None = None) -> None:
        self._client = client
        self._audit_sink = audit_sink or LoggingAuditSink()

    def __enter__(self) -> ReadOnlyQueryRunner:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def run(
        self,
        query: SqlQuery,
        *,
        bounds: UtcBounds | None = None,
        parameters: Mapping[str, Any] | None = None,
    ) -> QueryOutcome:
        if query.kind is SqlKind.DATA and bounds is None:
            raise ValueError("data queries require typed UTC bounds")
        if query.kind is SqlKind.METADATA and bounds is not None:
            raise ValueError("metadata queries do not accept data bounds")

        bound_parameters: dict[str, Any] = dict(parameters or {})
        if "start" in bound_parameters or "end" in bound_parameters:
            raise ValueError("start and end parameters must come from UtcBounds")
        if bounds is not None:
            bound_parameters.update(start=bounds.start, end=bounds.end)

        started = monotonic()
        returned_rows = 0
        query_id = "unavailable"
        try:
            result = self._client.query(
                query.text,
                parameters=bound_parameters,
                settings={"readonly": 1, "max_execution_time": query.timeout_seconds},
            )
            query_id = result.query_id or "unavailable"
            column_names = tuple(result.column_names)
            rows = tuple(tuple(row) for row in result.result_rows)
            returned_rows = len(rows)
            summary = result.summary
        except Exception as exc:
            self._audit_sink.record(
                QueryAudit(
                    query_name=query.name,
                    query_version=query.version,
                    query_id=query_id,
                    elapsed_seconds=monotonic() - started,
                    returned_rows=returned_rows,
                    read_rows=0,
                    read_bytes=0,
                    aggregate_only=query.aggregate_only,
                    status="failed",
                )
            )
            raise SourceQueryError(f"query {query.name} v{query.version} failed") from exc
        elapsed = monotonic() - started
        audit = QueryAudit(
            query_name=query.name,
            query_version=query.version,
            query_id=query_id,
            elapsed_seconds=elapsed,
            returned_rows=returned_rows,
            read_rows=_summary_int(summary, "read_rows"),
            read_bytes=_summary_int(summary, "read_bytes"),
            aggregate_only=query.aggregate_only,
            status="passed",
        )
        self._audit_sink.record(audit)
        return QueryOutcome(
            column_names=column_names,
            rows=rows,
            audit=audit,
        )

    def run_blocks(
        self,
        query: SqlQuery,
        consume: Callable[[tuple[str, ...], Sequence[Sequence[Any]]], None],
        *,
        bounds: UtcBounds,
    ) -> QueryAudit:
        """Stream bounded row blocks through a consumer without materializing a full result."""
        if query.kind is not SqlKind.DATA:
            raise ValueError("row-block streaming is restricted to bounded data queries")
        parameters = {"start": bounds.start, "end": bounds.end}
        started = monotonic()
        returned_rows = 0
        query_id = "unavailable"
        try:
            context = self._client.query_row_block_stream(
                query.text,
                parameters=parameters,
                settings={"readonly": 1, "max_execution_time": query.timeout_seconds},
            )
            source = cast(QueryResultLike, context.source)
            query_id = source.query_id or "unavailable"
            column_names = tuple(source.column_names)
            with context as blocks:
                for block in blocks:
                    returned_rows += len(block)
                    consume(column_names, block)
            summary = source.summary
        except Exception as exc:
            audit = QueryAudit(
                query_name=query.name,
                query_version=query.version,
                query_id=query_id,
                elapsed_seconds=monotonic() - started,
                returned_rows=returned_rows,
                read_rows=0,
                read_bytes=0,
                aggregate_only=query.aggregate_only,
                status="failed",
            )
            self._audit_sink.record(audit)
            raise SourceQueryError(f"query {query.name} v{query.version} failed") from exc
        audit = QueryAudit(
            query_name=query.name,
            query_version=query.version,
            query_id=query_id,
            elapsed_seconds=monotonic() - started,
            returned_rows=returned_rows,
            read_rows=_summary_int(summary, "read_rows"),
            read_bytes=_summary_int(summary, "read_bytes"),
            aggregate_only=query.aggregate_only,
            status="passed",
        )
        self._audit_sink.record(audit)
        return audit


def _summary_int(summary: Mapping[str, Any], key: str) -> int:
    value = summary.get(key, 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
