from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import duckdb
import pytest

from network_behaviour.aggregation import ActivityObservation, DayAggregator, StagedDay
from network_behaviour.publication import DayPublisher, PublicationError, StorageGuard
from network_behaviour.source.day import ReconciliationTotals, SourceDayInputs
from network_behaviour.storage.migrations import MigrationRunner
from network_behaviour.time import UtcDay

MIGRATIONS = Path(__file__).parents[3] / "sql" / "migrations"
DAY = UtcDay.parse("2026-07-10")
NOW = datetime(2026, 7, 11, 8, tzinfo=UTC)


def _staged() -> tuple[SourceDayInputs, StagedDay]:
    observation = ActivityObservation(
        datetime(2026, 7, 10, tzinfo=UTC),
        "10.20.1.2",
        "8.8.8.8",
        443,
        6,
        "example.com",
        None,
        None,
        "web",
        "browsing",
        "AS15169",
        100,
        50,
        10,
        5,
        2,
        (0,),
    )
    staged = DayAggregator().aggregate(DAY, (observation,), (), ())
    source = SourceDayInputs(
        day=DAY,
        reconciliation=ReconciliationTotals(100, 50, 100, 50),
        query_versions_json='{"day_activity_observations":1}',
        query_count=5,
        returned_rows=100,
        read_rows=1_000,
        read_bytes=20_000,
        elapsed_seconds=1.0,
        aggregation_seconds=0.5,
    )
    return source, staged


@pytest.fixture
def connection() -> duckdb.DuckDBPyConnection:
    value = duckdb.connect(":memory:")
    MigrationRunner(MIGRATIONS).apply(value)
    return value


def test_publication_hides_day_until_scoring_then_publishes_both_grains(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    source, staged = _staged()
    callback_run_ids: list[UUID] = []

    def score(conn: duckdb.DuckDBPyConnection, day: UtcDay, run_id: UUID) -> None:
        assert conn.execute(
            "SELECT count(*) FROM history.client_day WHERE day = ?", [day.value]
        ).fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM staging_client_day").fetchone() == (1,)
        callback_run_ids.append(run_id)

    result = DayPublisher(connection).publish(source, staged, score, now=NOW)

    assert callback_run_ids == [result.run_id]
    assert connection.execute("SELECT count(*) FROM history.client_day").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM history.client_service_day").fetchone() == (1,)
    assert connection.execute(
        "SELECT status, schema_version, staged_client_rows, staged_service_rows "
        "FROM ops.pipeline_run"
    ).fetchone() == ("published", 10, 1, 1)
    assert connection.execute(
        """
        SELECT source_sql_version, query_versions_json, aggregation_version,
               reconciliation_version, source_duplicate_fraction,
               query_count, source_read_rows, source_read_bytes
        FROM ops.pipeline_run
        """
    ).fetchone() == (
        "phase3-source-bundle-v3",
        '{"day_activity_observations":1}',
        "day-aggregation-v2",
        "activity-rate-relative-v1",
        0.0,
        5,
        1_000,
        20_000,
    )
    with pytest.raises(duckdb.CatalogException):
        connection.execute("SELECT count(*) FROM staging_client_day")


def test_failed_scoring_rolls_back_all_publication_and_cleans_transient_tables(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    source, staged = _staged()

    def fail(*_args: object) -> None:
        raise RuntimeError("synthetic scoring failure")

    with pytest.raises(PublicationError, match="publication failed"):
        DayPublisher(connection).publish(source, staged, fail, now=NOW)

    assert connection.execute("SELECT count(*) FROM history.client_day").fetchone() == (0,)
    assert connection.execute("SELECT status, failure_code FROM ops.pipeline_run").fetchone() == (
        "failed",
        "RuntimeError",
    )
    with pytest.raises(duckdb.CatalogException):
        connection.execute("SELECT count(*) FROM staging_client_service_day")


def test_repeated_success_is_idempotent_and_does_not_score_again(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    source, staged = _staged()
    calls = 0

    def score(*_args: object) -> None:
        nonlocal calls
        calls += 1

    publisher = DayPublisher(connection)
    first = publisher.publish(source, staged, score, now=NOW)
    second = publisher.publish(source, staged, score, now=NOW)

    assert not first.idempotent
    assert second.idempotent
    assert first.run_id == second.run_id
    assert calls == 1
    assert connection.execute("SELECT count(*) FROM history.client_day").fetchone() == (1,)


def test_previous_equivalent_transfer_bundle_is_idempotently_compatible(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    source, staged = _staged()
    publisher = DayPublisher(connection)
    first = publisher.publish(source, staged, lambda *_args: None, now=NOW)
    connection.execute("UPDATE ops.pipeline_run SET source_sql_version = 'phase3-source-bundle-v2'")

    second = publisher.publish(source, staged, lambda *_args: None, now=NOW)

    assert second.idempotent
    assert second.run_id == first.run_id


def test_reconciliation_and_storage_guards_fail_closed(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    source, staged = _staged()
    bad_source = SourceDayInputs(
        day=source.day,
        reconciliation=ReconciliationTotals(100, 50, 10, 5),
        query_versions_json=source.query_versions_json,
        query_count=source.query_count,
        returned_rows=source.returned_rows,
        read_rows=source.read_rows,
        read_bytes=source.read_bytes,
        elapsed_seconds=source.elapsed_seconds,
        aggregation_seconds=source.aggregation_seconds,
    )
    with pytest.raises(PublicationError, match="reconciliation exceeds"):
        DayPublisher(connection).publish(bad_source, staged, lambda *_args: None, now=NOW)

    duplicate_source = SourceDayInputs(
        day=source.day,
        reconciliation=ReconciliationTotals(100, 50, 100, 50, 100, 90),
        query_versions_json=source.query_versions_json,
        query_count=source.query_count,
        returned_rows=source.returned_rows,
        read_rows=source.read_rows,
        read_bytes=source.read_bytes,
        elapsed_seconds=source.elapsed_seconds,
        aggregation_seconds=source.aggregation_seconds,
    )
    with pytest.raises(PublicationError, match="duplicate fraction exceeds"):
        DayPublisher(connection).publish(duplicate_source, staged, lambda *_args: None, now=NOW)

    tiny_guard = StorageGuard(alert_bytes=1, stop_bytes=2)
    with pytest.raises(PublicationError, match="storage reaches"):
        DayPublisher(connection, storage_guard=tiny_guard).publish(
            source, staged, lambda *_args: None, now=NOW
        )

    assert connection.execute(
        "SELECT count(*) FROM ops.pipeline_run WHERE status = 'failed'"
    ).fetchone() == (3,)


def test_arrow_staging_preserves_full_width_unsigned_identifiers(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    source, staged = _staged()
    category = 2**63 + 17
    service = replace(staged.service_rows[0], application_category_id=category)
    staged = StagedDay(staged.day, staged.client_rows, (service,))

    DayPublisher(connection).publish(source, staged, lambda *_args: None, now=NOW)

    assert connection.execute(
        "SELECT application_category_id FROM history.client_service_day"
    ).fetchone() == (category,)
