from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, ClassVar

import duckdb
import pytest

from network_behaviour.config import ConfigurationError, SourceConfig
from network_behaviour.source.client import (
    QueryAudit,
    QueryResultLike,
    ReadOnlyQueryRunner,
    SourceQueryError,
    create_source_client,
)
from network_behaviour.source.duckdb_client import DuckDbSourceError, duckdb_type, translate
from network_behaviour.source.sql import SqlKind, SqlQuery
from network_behaviour.time import UtcDay

DAY = UtcDay.parse("2026-07-10")


class FakeResult:
    column_names = ("total",)
    result_rows = ((7,),)
    query_id = "query-123"
    summary: ClassVar[dict[str, str]] = {"read_rows": "100", "read_bytes": "2048"}

    @property
    def row_count(self) -> int:
        return 1


class FakeStream:
    def __init__(self) -> None:
        self.source = FakeResult()

    def __enter__(self) -> Iterator[Sequence[Sequence[Any]]]:
        return iter(([(7,), (8,)],))

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


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
    ) -> QueryResultLike:
        del query
        self.parameters = parameters
        self.settings = settings
        self.calls += 1
        return FakeResult()

    def query_row_block_stream(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
    ) -> FakeStream:
        del query, parameters, settings
        return FakeStream()

    def close(self) -> None:
        self.closed = True


class FailingClient(FakeClient):
    def query(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
    ) -> QueryResultLike:
        raise RuntimeError("password=not-a-real-secret")


class CollectingSink:
    def __init__(self) -> None:
        self.audits: list[QueryAudit] = []

    def record(self, audit: QueryAudit) -> None:
        self.audits.append(audit)


def _bounded(text: str = "SELECT count(*) FROM flow.activity_1m") -> SqlQuery:
    return SqlQuery(
        "bounded_count",
        3,
        f"{text} WHERE time >= {{start:DateTime('UTC')}} AND time < {{end:DateTime('UTC')}}",
        45,
        SqlKind.DATA,
        True,
    )


def test_runner_injects_bounds_readonly_timeout_and_safe_audit() -> None:
    client = FakeClient()
    sink = CollectingSink()

    with ReadOnlyQueryRunner(client, sink) as runner:
        outcome = runner.run(_bounded(), bounds=DAY.bounds)

    assert client.calls == 1 and client.closed
    assert client.settings == {"readonly": 1, "max_execution_time": 45}
    assert client.parameters == {"start": DAY.bounds.start, "end": DAY.bounds.end}
    assert outcome.rows == ((7,),)
    assert sink.audits[0].query_id == "query-123"
    assert (sink.audits[0].read_rows, sink.audits[0].read_bytes) == (100, 2048)
    assert not hasattr(sink.audits[0], "sql")
    assert not hasattr(sink.audits[0], "parameters")


def test_runner_rejects_untyped_or_overridden_bounds() -> None:
    runner = ReadOnlyQueryRunner(FakeClient(), CollectingSink())
    query = SqlQuery("data", 1, "SELECT count(*)", 30, SqlKind.DATA, True)

    with pytest.raises(ValueError, match="typed UTC bounds"):
        runner.run(query)
    with pytest.raises(ValueError, match="must come from UtcBounds"):
        runner.run(query, bounds=DAY.bounds, parameters={"start": "unsafe"})


def test_runner_audits_failure_without_exposing_underlying_error() -> None:
    sink = CollectingSink()
    query = SqlQuery("safe_name", 2, "SELECT count(*)", 30, SqlKind.METADATA, True)

    with pytest.raises(SourceQueryError, match="query safe_name v2 failed") as error:
        ReadOnlyQueryRunner(FailingClient(), sink).run(query)

    assert "not-a-real-secret" not in str(error.value)
    assert sink.audits[0].status == "failed" and sink.audits[0].query_id == "unavailable"


def test_runner_streams_bounded_blocks_without_materializing_result() -> None:
    consumed: list[tuple[object, ...]] = []

    def consume(columns: tuple[str, ...], rows: Sequence[Sequence[Any]]) -> None:
        consumed.append(columns)
        consumed.extend(tuple(row) for row in rows)

    audit = ReadOnlyQueryRunner(FakeClient(), CollectingSink()).run_blocks(
        _bounded(), consume, bounds=DAY.bounds
    )

    assert consumed == [("total",), (7,), (8,)]
    assert audit.returned_rows == 2 and audit.read_rows == 100


# --- the DuckDB client ----------------------------------------------------------------------------


def test_placeholders_become_typed_duckdb_parameters() -> None:
    text, names = translate(
        "SELECT 1 WHERE t >= {start:DateTime64(6, 'UTC')} AND h IN {hosts:Array(String)} "
        "AND t < {end:DateTime('UTC')} AND t >= {start:DateTime64(6, 'UTC')}"
    )

    assert names == ("start", "hosts", "end")
    assert "CAST($start AS TIMESTAMPTZ)" in text and "CAST($hosts AS VARCHAR[])" in text
    assert "{" not in text
    assert duckdb_type("UInt16") == "BIGINT" and duckdb_type("Nullable(Float64)") == "DOUBLE"
    with pytest.raises(DuckDbSourceError):
        duckdb_type("Map(String, String)")


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "source.duckdb"
    with duckdb.connect(str(path)) as connection:
        connection.execute("SET TimeZone = 'UTC'")
        connection.execute("CREATE SCHEMA flow")
        connection.execute(
            "CREATE TABLE flow.activity_1m AS SELECT range AS up_bytes, "
            "TIMESTAMPTZ '2026-07-10 00:00:00+00' + to_minutes(range) AS time FROM range(2880)"
        )
    return path


def test_the_client_runs_bounded_queries_and_reports_rows_read(source: Path) -> None:
    runner = ReadOnlyQueryRunner(create_source_client(SourceConfig(source)), CollectingSink())

    outcome = runner.run(_bounded("SELECT count(*) AS n, sum(up_bytes) AS b FROM flow.activity_1m"),
                         bounds=DAY.bounds)  # fmt: skip
    blocks: list[Sequence[Any]] = []
    audit = runner.run_blocks(
        _bounded("SELECT up_bytes, time FROM flow.activity_1m"),
        lambda _columns, rows: blocks.extend(rows),
        bounds=DAY.bounds,
    )
    runner.close()

    assert outcome.dictionaries() == ({"n": 1440, "b": sum(range(1440))},)
    assert outcome.audit.read_rows >= 1440
    assert len(blocks) == 1440 and audit.returned_rows == 1440
    assert blocks[0][1] == datetime(2026, 7, 10, tzinfo=UTC)


def test_the_client_is_read_only_and_cannot_reach_other_files(source: Path, tmp_path: Path) -> None:
    other = tmp_path / "other.csv"
    other.write_text("a\n1\n", encoding="utf-8")
    client = create_source_client(SourceConfig(source))
    try:
        with pytest.raises(duckdb.Error):
            client.query("DELETE FROM flow.activity_1m")
        with pytest.raises(duckdb.Error):
            client.query(f"SELECT count(*) FROM read_csv('{other}')")
        with pytest.raises(duckdb.Error):
            client.query("SET enable_external_access = true")
    finally:
        client.close()


def test_a_missing_source_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="load Zeek logs first"):
        create_source_client(SourceConfig(tmp_path / "absent.duckdb"))


def test_a_query_past_its_timeout_is_interrupted(source: Path) -> None:
    client = create_source_client(SourceConfig(source))
    try:
        with pytest.raises(duckdb.Error):
            client.query(
                "SELECT count(*) FROM range(100000000) AS a, range(100000) AS b "
                "WHERE a.range > b.range",
                settings={"max_execution_time": 0.2},
            )
    finally:
        client.close()
