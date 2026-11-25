"""Privacy-safe, read-only ClickHouse query execution."""

from __future__ import annotations

import logging
from collections.abc import Callable, Generator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from threading import get_ident
from time import monotonic
from typing import Any, Protocol, cast

import clickhouse_connect
from clickhouse_connect.driver.common import StreamContext
from clickhouse_connect.driver.external import ExternalData

from network_behaviour.config import ClickHouseConfig
from network_behaviour.source.sql import SqlKind, SqlQuery
from network_behaviour.time import UtcBounds


class SourceQueryError(RuntimeError):
    """Raised without SQL, parameters, credentials, or source identifiers."""


_DRIVER_HTTP_LOGGER = "clickhouse_connect.driver.httputil"
_TRUNCATED_STREAM_MESSAGE = "unexpected failure to read next chunk"


class _DriverStreamFailureMonitor(logging.Handler):
    """Detect clickhouse-connect 0.x swallowing a mid-response HTTP failure."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self._thread_id = get_ident()
        self.detected = False

    def emit(self, record: logging.LogRecord) -> None:
        if record.thread == self._thread_id and record.getMessage().startswith(
            _TRUNCATED_STREAM_MESSAGE
        ):
            self.detected = True


@contextmanager
def _monitor_driver_stream() -> Generator[_DriverStreamFailureMonitor, None, None]:
    """Install a query-local detector until the upstream stream fix is released."""

    logger = logging.getLogger(_DRIVER_HTTP_LOGGER)
    monitor = _DriverStreamFailureMonitor()
    previous_disabled = logger.disabled
    previous_level = logger.level
    logger.disabled = False
    if not logger.isEnabledFor(logging.WARNING):
        logger.setLevel(logging.WARNING)
    logger.addHandler(monitor)
    try:
        yield monitor
    finally:
        logger.removeHandler(monitor)
        logger.setLevel(previous_level)
        logger.disabled = previous_disabled
        monitor.close()


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


class ClientLike(Protocol):
    def query(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
        external_data: ExternalData | None = None,
    ) -> QueryResultLike: ...

    def query_row_block_stream(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
        external_data: ExternalData | None = None,
    ) -> StreamContext: ...

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


class AuditSink(Protocol):
    def record(self, audit: QueryAudit) -> None: ...


class LoggingAuditSink:
    """Emit only query metadata, never SQL, parameters, or source identifiers."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("network_behaviour.source")

    def record(self, audit: QueryAudit) -> None:
        self._logger.info(
            "clickhouse query completed",
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


def create_clickhouse_client(config: ClickHouseConfig) -> ClientLike:
    """Create a client whose server session is forced into read-only mode."""
    return cast(
        ClientLike,
        clickhouse_connect.get_client(
            host=config.host,
            port=config.port,
            username=config.username,
            password=config.password,
            secure=config.secure,
            connect_timeout=config.connect_timeout_seconds,
            send_receive_timeout=config.send_receive_timeout_seconds,
            settings={"readonly": 1},
        ),
    )


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
        external_data: ExternalData | None = None,
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
            with _monitor_driver_stream() as stream_monitor:
                result = self._client.query(
                    query.text,
                    parameters=bound_parameters,
                    settings={"readonly": 1, "max_execution_time": query.timeout_seconds},
                    external_data=external_data,
                )
                query_id = result.query_id or "unavailable"
                column_names = tuple(result.column_names)
                rows = tuple(tuple(row) for row in result.result_rows)
                returned_rows = len(rows)
                if stream_monitor.detected:
                    raise RuntimeError("ClickHouse response stream was interrupted")
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
        external_data: ExternalData | None = None,
    ) -> QueryAudit:
        """Stream bounded row blocks through a consumer without materializing a full result."""
        if query.kind is not SqlKind.DATA:
            raise ValueError("row-block streaming is restricted to bounded data queries")
        parameters = {"start": bounds.start, "end": bounds.end}
        started = monotonic()
        returned_rows = 0
        query_id = "unavailable"
        try:
            with _monitor_driver_stream() as stream_monitor:
                context = self._client.query_row_block_stream(
                    query.text,
                    parameters=parameters,
                    settings={"readonly": 1, "max_execution_time": query.timeout_seconds},
                    external_data=external_data,
                )
                source = cast(QueryResultLike, context.source)
                query_id = source.query_id or "unavailable"
                column_names = tuple(source.column_names)
                with context as blocks:
                    for block in blocks:
                        returned_rows += len(block)
                        consume(column_names, block)
                if stream_monitor.detected:
                    raise RuntimeError("ClickHouse response stream was interrupted")
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
