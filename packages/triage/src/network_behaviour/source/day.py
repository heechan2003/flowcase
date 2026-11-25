"""Stream approved source aggregates into deterministic daily retained grains."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from time import monotonic
from typing import Any

from network_behaviour.aggregation import (
    ActivityObservation,
    DayAccumulator,
    LongFlowObservation,
    RateObservation,
    StagedDay,
    utc_from_epoch,
    utc_from_epoch_microseconds,
)
from network_behaviour.source.client import QueryAudit, ReadOnlyQueryRunner
from network_behaviour.source.contracts import SourceContractReport
from network_behaviour.source.sql import SqlKind, SqlLoader
from network_behaviour.time import UtcDay, partition_utc_bounds

SOURCE_QUERY_VERSIONS: Mapping[str, int] = {
    "day_activity_observations": 1,
    "day_rate_observations": 1,
    "day_long_flow_observations": 1,
}
SOURCE_QUERY_BUNDLE_VERSION = "phase3-source-bundle-v3"
COMPATIBLE_SOURCE_QUERY_BUNDLE_VERSIONS = (
    "phase3-source-bundle-v2",
    SOURCE_QUERY_BUNDLE_VERSION,
)
# The per-query version sets a published day may have recorded in `query_versions_json` and still
# stream back, in the canonical form the pipeline writes (DNS included). An allow-list, not the
# current value: comparing it strictly would strand every published day the first time any one
# query moved to a new version.
COMPATIBLE_QUERY_VERSIONS_JSON = frozenset(
    {
        '{"day_activity_observations":1,"day_long_flow_observations":1,'
        '"day_rate_observations":1,"dns_daily_observations":1}',
    }
)
ACTIVITY_QUERY_SLICE = timedelta(hours=1)


class SourceDayError(ValueError):
    """Raised when a day source result is incomplete or malformed."""


@dataclass(frozen=True, slots=True)
class ReconciliationTotals:
    activity_up_bytes: int
    activity_down_bytes: int
    rate_up_bytes: int
    rate_down_bytes: int
    activity_rows: int = 0
    unique_activity_grain_rows: int = 0


@dataclass(frozen=True, slots=True)
class SourceDayInputs:
    day: UtcDay
    reconciliation: ReconciliationTotals
    query_versions_json: str
    query_count: int
    returned_rows: int
    read_rows: int
    read_bytes: int
    elapsed_seconds: float
    aggregation_seconds: float
    long_flow_context_available: bool = True
    """Whether `long_flows` carried any qualifying row for the day.

    Optional context (Tier 1): its absence never fails the day and never lowers strength, but an
    episode should say it was scored without it rather than imply the context was there.
    """


class SourceDayReader:
    def __init__(
        self,
        runner: ReadOnlyQueryRunner,
        sql_root: Path,
        *,
        timeout_seconds: int,
    ) -> None:
        self._runner = runner
        self._loader = SqlLoader(sql_root)
        self._timeout_seconds = timeout_seconds

    def read_and_aggregate(
        self, day: UtcDay, contract_report: SourceContractReport
    ) -> tuple[SourceDayInputs, StagedDay]:
        if (
            not contract_report.passed
            or not contract_report.metadata_checked
            or not contract_report.coverage_checked
            or contract_report.day != day
            or contract_report.reconciliation is None
        ):
            raise SourceDayError(
                "a passing metadata, coverage, and reconciliation contract is required"
            )

        accumulator = DayAccumulator(day)
        aggregation_seconds = 0.0

        def activity_consumer(columns: tuple[str, ...], rows: Sequence[Sequence[Any]]) -> None:
            nonlocal aggregation_seconds
            started = monotonic()
            indexes = _indexes(
                columns,
                {
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
                },
            )
            for row in rows:
                accumulator.consume_activity(_activity_row(row, indexes))
            aggregation_seconds += monotonic() - started

        def rate_consumer(columns: tuple[str, ...], rows: Sequence[Sequence[Any]]) -> None:
            nonlocal aggregation_seconds
            started = monotonic()
            indexes = _indexes(columns, {"bucket_epoch", "client_ip", "up_rate_p95_bps"})
            for row in rows:
                accumulator.consume_rate(_rate_row(row, indexes))
            aggregation_seconds += monotonic() - started

        def long_flow_consumer(columns: tuple[str, ...], rows: Sequence[Sequence[Any]]) -> None:
            nonlocal aggregation_seconds
            started = monotonic()
            indexes = _indexes(
                columns,
                {
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
                },
            )
            for row in rows:
                accumulator.consume_long_flow(_long_flow_row(row, indexes))
            aggregation_seconds += monotonic() - started

        consumers = {
            "day_activity_observations": activity_consumer,
            "day_rate_observations": rate_consumer,
            "day_long_flow_observations": long_flow_consumer,
        }
        audits: list[QueryAudit] = []
        for name, version in SOURCE_QUERY_VERSIONS.items():
            query = self._loader.load(
                name,
                version,
                timeout_seconds=self._timeout_seconds,
                kind=SqlKind.DATA,
            )
            bounds = (
                partition_utc_bounds(day.bounds, ACTIVITY_QUERY_SLICE)
                if name == "day_activity_observations"
                else (day.bounds,)
            )
            audits.extend(
                self._runner.run_blocks(query, consumers[name], bounds=query_bounds)
                for query_bounds in bounds
            )

        started = monotonic()
        staged = accumulator.finish()
        aggregation_seconds += monotonic() - started
        source_reconciliation = contract_report.reconciliation
        source = SourceDayInputs(
            day=day,
            reconciliation=ReconciliationTotals(
                source_reconciliation.activity_up_bytes,
                source_reconciliation.activity_down_bytes,
                source_reconciliation.rate_up_bytes,
                source_reconciliation.rate_down_bytes,
                source_reconciliation.activity_rows,
                source_reconciliation.unique_activity_grain_rows,
            ),
            query_versions_json=json.dumps(
                SOURCE_QUERY_VERSIONS, sort_keys=True, separators=(",", ":")
            ),
            query_count=len(audits) + contract_report.query_count,
            returned_rows=sum(audit.returned_rows for audit in audits)
            + contract_report.returned_rows,
            read_rows=sum(audit.read_rows for audit in audits) + contract_report.read_rows,
            read_bytes=sum(audit.read_bytes for audit in audits) + contract_report.read_bytes,
            elapsed_seconds=sum(audit.elapsed_seconds for audit in audits)
            + contract_report.elapsed_seconds,
            aggregation_seconds=aggregation_seconds,
            long_flow_context_available=contract_report.long_flow_rows != 0,
        )
        return source, staged


def _indexes(columns: tuple[str, ...], expected: set[str]) -> dict[str, int]:
    missing = expected - set(columns)
    if missing:
        raise SourceDayError(f"source result omitted column {sorted(missing)[0]}")
    return {name: columns.index(name) for name in expected}


def _activity_row(row: Sequence[Any], indexes: Mapping[str, int]) -> ActivityObservation:
    offsets = _field(row, indexes, "minute_offsets")
    if not isinstance(offsets, Sequence) or isinstance(offsets, (str, bytes)):
        raise SourceDayError("activity minute offsets are malformed")
    return ActivityObservation(
        bucket_start=utc_from_epoch(_integer(row, indexes, "bucket_epoch")),
        client_ip=str(_field(row, indexes, "client_ip")),
        server_ip=str(_field(row, indexes, "server_ip")),
        server_port=_field(row, indexes, "server_port"),
        transport_protocol=_field(row, indexes, "transport_protocol"),
        root_domain=_optional_string(_field(row, indexes, "root_domain")),
        sni=_optional_string(_field(row, indexes, "sni")),
        dns=_optional_string(_field(row, indexes, "dns")),
        application=_optional_string(_field(row, indexes, "application")),
        application_category=_optional_string(_field(row, indexes, "application_category")),
        asn=_field(row, indexes, "asn"),
        up_bytes=_integer(row, indexes, "up_bytes"),
        down_bytes=_integer(row, indexes, "down_bytes"),
        up_packets=_integer(row, indexes, "up_packets"),
        down_packets=_integer(row, indexes, "down_packets"),
        flow_count=_integer(row, indexes, "flow_count"),
        minute_offsets=tuple(_integer_value(value, "minute_offset") for value in offsets),
    )


def _rate_row(row: Sequence[Any], indexes: Mapping[str, int]) -> RateObservation:
    return RateObservation(
        utc_from_epoch(_integer(row, indexes, "bucket_epoch")),
        str(_field(row, indexes, "client_ip")),
        _floating(row, indexes, "up_rate_p95_bps"),
    )


def _long_flow_row(row: Sequence[Any], indexes: Mapping[str, int]) -> LongFlowObservation:
    return LongFlowObservation(
        utc_from_epoch_microseconds(_integer(row, indexes, "start_epoch_us")),
        utc_from_epoch_microseconds(_integer(row, indexes, "finish_epoch_us")),
        str(_field(row, indexes, "client_ip")),
        str(_field(row, indexes, "server_ip")),
        _field(row, indexes, "protocol"),
        _field(row, indexes, "server_port"),
        _integer(row, indexes, "large_flow_count"),
        _integer(row, indexes, "large_flow_up_bytes"),
        _integer(row, indexes, "max_large_flow_bytes"),
        _floating(row, indexes, "max_large_flow_duration_sec"),
    )


def _field(row: Sequence[Any], indexes: Mapping[str, int], field: str) -> Any:
    return row[indexes[field]]


def _integer(row: Sequence[Any], indexes: Mapping[str, int], field: str) -> int:
    return _integer_value(_field(row, indexes, field), field)


def _integer_value(value: Any, field: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise SourceDayError(f"{field} is not an integer") from exc
    if parsed < 0:
        raise SourceDayError(f"{field} cannot be negative")
    return parsed


def _floating(row: Sequence[Any], indexes: Mapping[str, int], field: str) -> float:
    try:
        return float(_field(row, indexes, field))
    except (TypeError, ValueError) as exc:
        raise SourceDayError(f"{field} is not numeric") from exc


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
