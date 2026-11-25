from collections.abc import Callable, Sequence
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

import pytest

from network_behaviour.source.client import (
    QueryAudit,
    QueryOutcome,
    ReadOnlyQueryRunner,
    SourceQueryError,
)
from network_behaviour.source.contracts import CoverageReconciliation, SourceContractReport
from network_behaviour.source.day import SourceDayReader
from network_behaviour.source.sql import SqlQuery
from network_behaviour.time import UtcBounds, UtcDay

SQL_ROOT = Path(__file__).parents[3] / "sql" / "source"
DAY = UtcDay.parse("2026-07-10")


def _outcome(name: str, columns: tuple[str, ...], row: tuple[object, ...]) -> QueryOutcome:
    return QueryOutcome(
        columns,
        (row,),
        QueryAudit(name, 1, "query", 0.1, 1, 10, 100, True, "passed"),
    )


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, UtcBounds]] = []

    def run_blocks(
        self,
        query: SqlQuery,
        consume: Callable[[tuple[str, ...], Sequence[Sequence[Any]]], None],
        *,
        bounds: UtcBounds,
    ) -> QueryAudit:
        self.calls.append((query.name, bounds))
        bucket_epoch = int(bounds.start.timestamp())
        outcomes = {
            "day_activity_observations": _outcome(
                query.name,
                (
                    "bucket_epoch",
                    "client_ip",
                    "server_ip",
                    "server_port",
                    "transport_protocol",
                    "root_domain",
                    "sni",
                    "dns",
                    "application",
                    "application_category",
                    "asn",
                    "up_bytes",
                    "down_bytes",
                    "up_packets",
                    "down_packets",
                    "flow_count",
                    "minute_offsets",
                ),
                (
                    bucket_epoch,
                    "10.20.1.2",
                    "8.8.8.8",
                    443,
                    6,
                    "example.com",
                    "",
                    "",
                    "web",
                    "browsing",
                    "AS15169",
                    100,
                    50,
                    10,
                    5,
                    2,
                    [0, 1],
                ),
            ),
            "day_rate_observations": _outcome(
                query.name,
                ("bucket_epoch", "client_ip", "up_rate_p95_bps"),
                (bucket_epoch, "10.20.1.2", 800.0),
            ),
            "day_long_flow_observations": _outcome(
                query.name,
                (
                    "start_epoch_us",
                    "finish_epoch_us",
                    "client_ip",
                    "server_ip",
                    "protocol",
                    "server_port",
                    "large_flow_count",
                    "large_flow_up_bytes",
                    "max_large_flow_bytes",
                    "max_large_flow_duration_sec",
                ),
                (
                    1_783_641_660_000_000,
                    1_783_641_720_000_000,
                    "10.20.1.2",
                    "8.8.8.8",
                    6,
                    443,
                    1,
                    1_000_000,
                    1_100_000,
                    60.0,
                ),
            ),
        }
        outcome = outcomes[query.name]
        consume(outcome.column_names, outcome.rows)
        return outcome.audit


class FailingSliceRunner(FakeRunner):
    def run_blocks(
        self,
        query: SqlQuery,
        consume: Callable[[tuple[str, ...], Sequence[Sequence[Any]]], None],
        *,
        bounds: UtcBounds,
    ) -> QueryAudit:
        if query.name == "day_activity_observations" and len(self.calls) == 2:
            self.calls.append((query.name, bounds))
            raise SourceQueryError("synthetic interrupted slice")
        return super().run_blocks(query, consume, bounds=bounds)


def test_source_day_reader_requires_contract_and_maps_transient_results() -> None:
    contract = SourceContractReport(
        DAY,
        True,
        True,
        2,
        20,
        200,
        (),
        CoverageReconciliation(100, 50, 100, 50, 10, 10),
        0.2,
        4,
    )
    runner = FakeRunner()
    reader = SourceDayReader(cast(ReadOnlyQueryRunner, runner), SQL_ROOT, timeout_seconds=300)

    inputs, staged = reader.read_and_aggregate(DAY, contract)

    assert inputs.reconciliation.activity_rows == 10
    assert inputs.query_count == 28
    assert inputs.returned_rows == 30
    assert inputs.read_rows == 280
    assert inputs.read_bytes == 2_800
    assert len(staged.client_rows) == len(staged.service_rows) == 1
    assert staged.client_rows[0].active_minutes == 48
    activity_bounds = tuple(
        bounds for name, bounds in runner.calls if name == "day_activity_observations"
    )
    assert len(activity_bounds) == 24
    assert activity_bounds[0].start == DAY.bounds.start
    assert activity_bounds[-1].end == DAY.bounds.end
    assert all(left.end == right.start for left, right in pairwise(activity_bounds))
    assert all((item.end - item.start).total_seconds() == 3_600 for item in activity_bounds)


def test_source_day_reader_stops_before_later_sources_when_an_activity_slice_fails() -> None:
    contract = SourceContractReport(
        DAY,
        True,
        True,
        2,
        20,
        200,
        (),
        CoverageReconciliation(100, 50, 100, 50, 10, 10),
        0.2,
        4,
    )
    runner = FailingSliceRunner()

    with pytest.raises(SourceQueryError, match="synthetic interrupted slice"):
        SourceDayReader(
            cast(ReadOnlyQueryRunner, runner), SQL_ROOT, timeout_seconds=300
        ).read_and_aggregate(DAY, contract)

    assert tuple(name for name, _bounds in runner.calls) == (
        "day_activity_observations",
        "day_activity_observations",
        "day_activity_observations",
    )
