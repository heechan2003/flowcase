import logging
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

import pytest
from clickhouse_connect.driver.common import StreamContext
from clickhouse_connect.driver.external import ExternalData

from network_behaviour.source.client import (
    QueryAudit,
    QueryResultLike,
    ReadOnlyQueryRunner,
    SourceQueryError,
)
from network_behaviour.source.sql import SqlKind, SqlQuery
from network_behaviour.time import UtcDay


class FakeResult:
    column_names = ("total",)
    result_rows = ((7,),)
    query_id = "query-123"
    summary: ClassVar[dict[str, str]] = {"read_rows": "100", "read_bytes": "2048"}

    @property
    def row_count(self) -> int:
        return 1


class FakeClient:
    def __init__(self) -> None:
        self.parameters: Mapping[str, Any] | None = None
        self.settings: Mapping[str, Any] | None = None
        self.closed = False
        self.calls = 0

    def query(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
        external_data: ExternalData | None = None,
    ) -> QueryResultLike:
        del query, external_data
        self.parameters = parameters
        self.settings = settings
        self.calls += 1
        return FakeResult()

    def close(self) -> None:
        self.closed = True

    def query_row_block_stream(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
        external_data: ExternalData | None = None,
    ) -> StreamContext:
        del query, external_data
        self.parameters = parameters
        self.settings = settings
        self.calls += 1
        return FakeStreamResult().row_block_stream


class FakeStreamResult:
    column_names = ("total",)
    query_id = "stream-query-123"
    summary: ClassVar[dict[str, str]] = {"read_rows": "200", "read_bytes": "4096"}

    @property
    def row_block_stream(self) -> StreamContext:
        return StreamContext(self, iter(([(7,), (8,)],)))

    def close(self) -> None:
        pass


class TruncatedStreamClient(FakeClient):
    def query_row_block_stream(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
        external_data: ExternalData | None = None,
    ) -> StreamContext:
        del query, external_data
        self.parameters = parameters
        self.settings = settings
        self.calls += 1
        return TruncatedStreamResult().row_block_stream


class TruncatedStreamResult(FakeStreamResult):
    query_id = "truncated-query-123"

    @property
    def row_block_stream(self) -> StreamContext:
        def blocks() -> Any:
            yield [(7,), (8,)]
            logging.getLogger("clickhouse_connect.driver.httputil").warning(
                "unexpected failure to read next chunk"
            )

        return StreamContext(self, blocks())


class CollectingSink:
    def __init__(self) -> None:
        self.audits: list[QueryAudit] = []

    def record(self, audit: QueryAudit) -> None:
        self.audits.append(audit)


class FailingClient(FakeClient):
    def query(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
        external_data: ExternalData | None = None,
    ) -> QueryResultLike:
        del query, parameters, settings, external_data
        raise RuntimeError("not-a-real-secret")


class TruncatedQueryClient(FakeClient):
    def query(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
        external_data: ExternalData | None = None,
    ) -> QueryResultLike:
        del query, external_data
        self.parameters = parameters
        self.settings = settings
        self.calls += 1
        return TruncatedQueryResult()


class TruncatedQueryResult:
    column_names = ("total",)
    query_id = "truncated-query-456"
    summary: ClassVar[dict[str, str]] = {"read_rows": "200", "read_bytes": "4096"}

    @property
    def result_rows(self) -> Sequence[Sequence[Any]]:
        logging.getLogger("clickhouse_connect.driver.httputil").warning(
            "unexpected failure to read next chunk"
        )
        return ((7,), (8,))

    @property
    def row_count(self) -> int:
        return len(self.result_rows)


def test_runner_injects_bounds_readonly_timeout_and_safe_audit() -> None:
    client = FakeClient()
    sink = CollectingSink()
    query = SqlQuery(
        "bounded_count",
        3,
        "SELECT count() FROM flow.activity_1m "
        "WHERE time >= {start:DateTime} AND time < {end:DateTime}",
        45,
        SqlKind.DATA,
        True,
    )

    with ReadOnlyQueryRunner(client, sink) as runner:
        outcome = runner.run(query, bounds=UtcDay.parse("2026-07-10").bounds)

    assert client.calls == 1
    assert client.closed
    assert client.settings == {"readonly": 1, "max_execution_time": 45}
    assert client.parameters == {
        "start": UtcDay.parse("2026-07-10").bounds.start,
        "end": UtcDay.parse("2026-07-10").bounds.end,
    }
    assert outcome.rows == ((7,),)
    assert sink.audits[0].query_id == "query-123"
    assert sink.audits[0].read_rows == 100
    assert sink.audits[0].read_bytes == 2048
    assert not hasattr(sink.audits[0], "sql")
    assert not hasattr(sink.audits[0], "parameters")


def test_runner_rejects_untyped_or_overridden_bounds() -> None:
    runner = ReadOnlyQueryRunner(FakeClient(), CollectingSink())
    query = SqlQuery("data", 1, "SELECT count()", 30, SqlKind.DATA, True)

    with pytest.raises(ValueError, match="typed UTC bounds"):
        runner.run(query)
    with pytest.raises(ValueError, match="must come from UtcBounds"):
        runner.run(
            query,
            bounds=UtcDay.parse("2026-07-10").bounds,
            parameters={"start": "unsafe"},
        )


def test_runner_audits_failure_without_exposing_underlying_error() -> None:
    sink = CollectingSink()
    runner = ReadOnlyQueryRunner(FailingClient(), sink)
    query = SqlQuery("safe_name", 2, "SELECT count()", 30, SqlKind.METADATA, True)

    with pytest.raises(SourceQueryError, match="query safe_name v2 failed") as error:
        runner.run(query)

    assert "not-a-real-secret" not in str(error.value)
    assert sink.audits[0].status == "failed"
    assert sink.audits[0].query_id == "unavailable"


def test_runner_fails_closed_when_materialized_result_was_truncated() -> None:
    sink = CollectingSink()
    query = SqlQuery("safe_name", 2, "SELECT count()", 30, SqlKind.METADATA, True)

    with pytest.raises(SourceQueryError, match="query safe_name v2 failed"):
        ReadOnlyQueryRunner(TruncatedQueryClient(), sink).run(query)

    assert sink.audits[0].status == "failed"
    assert sink.audits[0].query_id == "truncated-query-456"
    assert sink.audits[0].returned_rows == 2


def test_runner_streams_bounded_blocks_without_materializing_result() -> None:
    client = FakeClient()
    sink = CollectingSink()
    consumed: list[tuple[object, ...]] = []
    query = SqlQuery("streamed", 1, "SELECT count()", 30, SqlKind.DATA, True)

    def consume(columns: tuple[str, ...], rows: Sequence[Sequence[Any]]) -> None:
        consumed.append(columns)
        consumed.extend(tuple(row) for row in rows)

    audit = ReadOnlyQueryRunner(client, sink).run_blocks(
        query,
        consume,
        bounds=UtcDay.parse("2026-07-10").bounds,
    )

    assert consumed == [("total",), (7,), (8,)]
    assert audit.returned_rows == 2
    assert audit.read_rows == 200
    assert audit.read_bytes == 4096


def test_runner_fails_closed_when_driver_swallows_midstream_read_failure() -> None:
    sink = CollectingSink()
    query = SqlQuery("streamed", 1, "SELECT count()", 30, SqlKind.DATA, True)

    with pytest.raises(SourceQueryError, match="query streamed v1 failed"):
        ReadOnlyQueryRunner(TruncatedStreamClient(), sink).run_blocks(
            query,
            lambda _columns, _rows: None,
            bounds=UtcDay.parse("2026-07-10").bounds,
        )

    assert sink.audits == [
        QueryAudit(
            "streamed",
            1,
            "truncated-query-123",
            sink.audits[0].elapsed_seconds,
            2,
            0,
            0,
            True,
            "failed",
        )
    ]
