from pathlib import Path

import pytest

from network_behaviour.source.sql import SqlKind, SqlLoader, SqlQuery, SqlSafetyError, validate_sql

SQL_ROOT = Path(__file__).parents[3] / "sql" / "source"


def test_repository_contract_queries_pass_static_safety() -> None:
    loader = SqlLoader(SQL_ROOT)

    metadata = loader.load(
        "source_metadata", 1, timeout_seconds=30, kind=SqlKind.METADATA, aggregate_only=False
    )
    coverage = loader.load("source_coverage", 2, timeout_seconds=30, kind=SqlKind.DATA)

    assert metadata.version == 1
    assert coverage.bounded
    assert "up_bytes + down_bytes >= 1000000" in coverage.text


def test_day_aggregation_queries_are_bounded_aggregates() -> None:
    loader = SqlLoader(SQL_ROOT)

    queries = tuple(
        loader.load(name, 1, timeout_seconds=300, kind=SqlKind.DATA)
        for name in (
            "day_activity_observations",
            "day_rate_observations",
            "day_long_flow_observations",
        )
    )

    assert all(query.bounded and query.aggregate_only for query in queries)
    assert "up_bytes + down_bytes >= 1000000" in queries[2].text
    assert "finish" in queries[2].text


def test_dns_query_is_direct_bounded_and_aggregate_only() -> None:
    query = SqlLoader(SQL_ROOT).load(
        "dns_daily_observations", 1, timeout_seconds=300, kind=SqlKind.DATA
    )

    assert query.bounded and query.aggregate_only
    assert "FROM flow.dns_pairs" in query.text
    assert "md5(server_ip)" in query.text
    assert "client_tag" not in query.text


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM flow.activity_1m",
        "SELECT * FROM flow.activity_1m",
        "SELECT count() FROM unapproved.table WHERE time >= {start:DateTime}",
        "SELECT count() FROM flow.activity_1m",
        "SELECT {start:DateTime} AS start, {end:DateTime} AS end, count() FROM flow.activity_1m",
        "SELECT subscriber_id, count() FROM flow.activity_1m "
        "WHERE time >= {start:DateTime} AND time < {end:DateTime}",
    ],
)
def test_unsafe_source_sql_is_rejected(sql: str) -> None:
    query = SqlQuery("unsafe", 1, sql, 30, SqlKind.DATA, True)

    with pytest.raises(SqlSafetyError):
        validate_sql(query)
