from collections.abc import Callable, Sequence
from datetime import timedelta
from itertools import pairwise
from pathlib import Path
from typing import cast

import pytest

from network_behaviour.detectors.dns import DnsSourceError, DnsSourceReader
from network_behaviour.source.client import QueryAudit, ReadOnlyQueryRunner
from network_behaviour.source.sql import SqlQuery
from network_behaviour.time import UtcBounds, UtcDay

SQL_ROOT = Path(__file__).parents[3] / "sql" / "source"
DAY = UtcDay.parse("2026-07-10")
DNS_COLUMNS = (
    "day",
    "client_ip",
    "resolver_id",
    "complete_sessions",
    "unanswered_sessions",
    "unsolicited_sessions",
    "query_packets",
    "response_packets",
    "unanswered_query_packets",
    "unsolicited_response_packets",
    "weighted_service_nanos",
    "weighted_service_sessions",
)


class _FakeRunner:
    def __init__(self, columns: tuple[str, ...] = DNS_COLUMNS) -> None:
        self.columns = columns
        self.calls: list[tuple[SqlQuery, UtcBounds]] = []

    def run_blocks(
        self,
        query: SqlQuery,
        consume: Callable[[tuple[str, ...], Sequence[Sequence[object]]], None],
        *,
        bounds: UtcBounds,
    ) -> QueryAudit:
        self.calls.append((query, bounds))
        audit = QueryAudit(
            query.name, query.version, "dns-query", 1.0, 1, 100, 1_000, True, "passed"
        )
        row = (
            bounds.start.date(),
            "10.20.1.1",
            "opaque-resolver-id",
            50,
            2,
            1,
            100,
            95,
            2,
            1,
            50_000.0,
            50,
        )
        consume(self.columns, (row[: len(self.columns)],))
        return audit


def test_dns_reader_uses_weekly_bounded_aggregates_and_returns_no_raw_resolver() -> None:
    runner = _FakeRunner()

    result = DnsSourceReader(cast(ReadOnlyQueryRunner, runner), SQL_ROOT, timeout_seconds=300).read(
        DAY
    )

    assert len(runner.calls) == len(result.audits) == 13
    query = runner.calls[0][0]
    assert query.name == "dns_daily_observations"
    assert query.aggregate_only and query.bounded
    assert "AS resolver_id" in query.text
    assert "GROUP BY day, client_ip, resolver_id" in query.text
    assert runner.calls[0][1].start.date() == DAY.value - timedelta(days=90)
    assert runner.calls[-1][1].end == DAY.bounds.end
    assert all(left[1].end == right[1].start for left, right in pairwise(runner.calls))
    assert all(bounds.end - bounds.start == timedelta(days=7) for _, bounds in runner.calls)
    assert len(result.observations) == 13
    assert result.observations[0].resolver_id == "opaque-resolver-id"
    assert not hasattr(result.observations[0], "server_ip")


def test_dns_reader_fails_closed_on_missing_aggregate_column() -> None:
    runner = _FakeRunner(DNS_COLUMNS[:-1])

    with pytest.raises(DnsSourceError, match="omitted column"):
        DnsSourceReader(cast(ReadOnlyQueryRunner, runner), SQL_ROOT, timeout_seconds=300).read(DAY)
