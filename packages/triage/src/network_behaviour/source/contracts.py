"""Approved source contracts and fail-closed validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from network_behaviour.source.client import QueryOutcome, ReadOnlyQueryRunner
from network_behaviour.source.sql import SqlKind, SqlLoader
from network_behaviour.time import UtcDay


class SourceContractError(ValueError):
    """Raised when source-contract output is malformed or cannot be validated."""


@dataclass(frozen=True, slots=True)
class ColumnContract:
    name: str
    type_name: str


@dataclass(frozen=True, slots=True)
class SourceContract:
    key: str
    database: str
    table: str
    columns: tuple[ColumnContract, ...]
    required_buckets_per_day: int | None
    absence_is_failure: bool


def _columns(**columns: str) -> tuple[ColumnContract, ...]:
    return tuple(ColumnContract(name, type_name) for name, type_name in columns.items())


TABLE_TYPE = "BASE TABLE"
"""A source is a stored table, never a view over something else."""

SOURCE_CONTRACTS = (
    SourceContract(
        key="activity_1m",
        database="flow",
        table="activity_1m",
        columns=_columns(
            time="TIMESTAMP WITH TIME ZONE",
            client_ip="VARCHAR",
            server_ip="VARCHAR",
            server_port="USMALLINT",
            transport_protocol="UTINYINT",
            application="VARCHAR",
            application_category="VARCHAR",
            root_domain="VARCHAR",
            sni="VARCHAR",
            dns="VARCHAR",
            asn="VARCHAR",
            up_bytes="BIGINT",
            down_bytes="BIGINT",
            up_packets="BIGINT",
            down_packets="BIGINT",
            flow_count="UBIGINT",
        ),
        required_buckets_per_day=1_440,
        absence_is_failure=True,
    ),
    SourceContract(
        key="host_load_5m",
        database="flow",
        table="host_load_5m",
        columns=_columns(
            time="TIMESTAMP WITH TIME ZONE",
            client_ip="VARCHAR",
            active_minutes="UBIGINT",
            up_rate_p95_bps="DOUBLE",
            up_bytes="BIGINT",
            down_bytes="BIGINT",
        ),
        required_buckets_per_day=288,
        absence_is_failure=True,
    ),
    SourceContract(
        key="dns_pairs",
        database="flow",
        table="dns_pairs",
        columns=_columns(
            time="TIMESTAMP WITH TIME ZONE",
            client_ip="VARCHAR",
            server_ip="VARCHAR",
            complete_sessions="UBIGINT",
            unanswered_sessions="UBIGINT",
            unsolicited_sessions="UBIGINT",
            query_packets="UBIGINT",
            response_packets="UBIGINT",
            unanswered_query_packets="UBIGINT",
            unsolicited_response_packets="UBIGINT",
            mean_service_nanos="UBIGINT",
        ),
        required_buckets_per_day=None,
        absence_is_failure=False,
    ),
    SourceContract(
        key="long_flows",
        database="flow",
        table="long_flows",
        columns=_columns(
            flow_id="VARCHAR",
            start="TIMESTAMP WITH TIME ZONE",
            finish="TIMESTAMP WITH TIME ZONE",
            duration_sec="DOUBLE",
            client_ip="VARCHAR",
            server_ip="VARCHAR",
            client_port="UINTEGER",
            server_port="UINTEGER",
            protocol="USMALLINT",
            up_bytes="UBIGINT",
            down_bytes="UBIGINT",
            initiator="VARCHAR",
        ),
        required_buckets_per_day=None,
        absence_is_failure=False,
    ),
)
_CONTRACT_BY_KEY = {contract.key: contract for contract in SOURCE_CONTRACTS}


@dataclass(frozen=True, slots=True)
class ContractIssue:
    source: str
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class CoverageReconciliation:
    activity_up_bytes: int
    activity_down_bytes: int
    rate_up_bytes: int
    rate_down_bytes: int
    activity_rows: int
    unique_activity_grain_rows: int


@dataclass(frozen=True, slots=True)
class SourceContractReport:
    day: UtcDay | None
    metadata_checked: bool
    coverage_checked: bool
    query_count: int
    read_rows: int
    read_bytes: int
    issues: tuple[ContractIssue, ...]
    reconciliation: CoverageReconciliation | None = None
    elapsed_seconds: float = 0.0
    returned_rows: int = 0
    long_flow_rows: int | None = None
    """Qualifying `long_flows` rows for the day; `None` when coverage was not checked."""

    @property
    def passed(self) -> bool:
        return not self.issues

    def render(self) -> str:
        status = "pass" if self.passed else "drift"
        day = str(self.day) if self.day is not None else "metadata-only"
        lines = [
            f"status: {status}",
            "sources: activity_1m, host_load_5m, dns_pairs, long_flows",
            f"day: {day}",
            f"query footprint: {self.query_count} aggregate/metadata queries, "
            f"{self.returned_rows} rows returned, {self.read_rows} rows read, "
            f"{self.read_bytes} bytes read, {self.elapsed_seconds:.3f} seconds",
        ]
        lines.extend(
            f"issue: {issue.source} {issue.code} - {issue.detail}" for issue in self.issues
        )
        return "\n".join(lines)


def validate_metadata(outcome: QueryOutcome) -> tuple[ContractIssue, ...]:
    _require_columns(outcome, {"database", "table", "column_name", "column_type", "engine"})
    observed: dict[tuple[str, str], tuple[str, str]] = {}
    engines: dict[tuple[str, str], str] = {}
    for row in outcome.dictionaries():
        key = (str(row["database"]), str(row["table"]))
        observed[(f"{key[0]}.{key[1]}", str(row["column_name"]))] = (
            str(row["column_type"]),
            str(row["engine"]),
        )
        engines[key] = str(row["engine"])

    issues: list[ContractIssue] = []
    for contract in SOURCE_CONTRACTS:
        table_key = (contract.database, contract.table)
        source = f"{contract.database}.{contract.table}"
        if table_key not in engines:
            issues.append(ContractIssue(source, "missing_table", "required table is absent"))
            continue
        if engines[table_key] != TABLE_TYPE:
            issues.append(
                ContractIssue(
                    source, "wrong_engine", f"expected {TABLE_TYPE}, got {engines[table_key]}"
                )
            )
        for column in contract.columns:
            value = observed.get((source, column.name))
            if value is None:
                issues.append(
                    ContractIssue(
                        source, "missing_column", f"required column {column.name} is absent"
                    )
                )
            elif value[0] != column.type_name:
                issues.append(
                    ContractIssue(
                        source,
                        "wrong_type",
                        f"{column.name} expected {column.type_name}, got {value[0]}",
                    )
                )
    return tuple(issues)


def validate_coverage(outcome: QueryOutcome) -> tuple[ContractIssue, ...]:
    _require_columns(
        outcome,
        {"source_key", "row_count", "bucket_count", "invalid_grain_rows"},
    )
    observed = {str(row["source_key"]): row for row in outcome.dictionaries()}
    issues: list[ContractIssue] = []
    for contract in SOURCE_CONTRACTS:
        row = observed.get(contract.key)
        if row is None:
            issues.append(ContractIssue(contract.key, "missing_coverage", "coverage row is absent"))
            continue
        row_count = _as_non_negative_int(row["row_count"], "row_count")
        bucket_count = _as_non_negative_int(row["bucket_count"], "bucket_count")
        invalid_grain = _as_non_negative_int(row["invalid_grain_rows"], "invalid_grain_rows")
        if contract.absence_is_failure and row_count == 0:
            issues.append(
                ContractIssue(contract.key, "incomplete_day", "required source has no rows")
            )
        if invalid_grain:
            issues.append(
                ContractIssue(
                    contract.key,
                    "wrong_grain",
                    f"{invalid_grain} rows violate the documented temporal grain",
                )
            )
        if (
            row_count > 0
            and contract.required_buckets_per_day is not None
            and bucket_count != contract.required_buckets_per_day
        ):
            issues.append(
                ContractIssue(
                    contract.key,
                    "incomplete_day",
                    f"expected {contract.required_buckets_per_day} UTC buckets, got {bucket_count}",
                )
            )
    unexpected = set(observed) - set(_CONTRACT_BY_KEY)
    if unexpected:
        issues.append(ContractIssue("source_check", "unexpected_source", sorted(unexpected)[0]))
    return tuple(issues)


def coverage_reconciliation(outcome: QueryOutcome) -> CoverageReconciliation:
    _require_columns(outcome, {"source_key", "up_bytes", "down_bytes", "unique_grain_rows"})
    observed = {str(row["source_key"]): row for row in outcome.dictionaries()}
    try:
        activity = observed["activity_1m"]
        rate = observed["host_load_5m"]
    except KeyError as exc:
        raise SourceContractError("principal reconciliation source is absent") from exc
    return CoverageReconciliation(
        activity_up_bytes=_as_non_negative_int(activity["up_bytes"], "activity up_bytes"),
        activity_down_bytes=_as_non_negative_int(activity["down_bytes"], "activity down_bytes"),
        rate_up_bytes=_as_non_negative_int(rate["up_bytes"], "rate up_bytes"),
        rate_down_bytes=_as_non_negative_int(rate["down_bytes"], "rate down_bytes"),
        activity_rows=_as_non_negative_int(activity["row_count"], "activity row_count"),
        unique_activity_grain_rows=_as_non_negative_int(
            activity["unique_grain_rows"], "activity unique_grain_rows"
        ),
    )


def run_source_contract_check(
    runner: ReadOnlyQueryRunner,
    loader: SqlLoader,
    day: UtcDay,
    *,
    timeout_seconds: int,
    metadata_only: bool,
) -> SourceContractReport:
    metadata_query = loader.load(
        "source_metadata",
        1,
        timeout_seconds=timeout_seconds,
        kind=SqlKind.METADATA,
        aggregate_only=False,
    )
    metadata = runner.run(metadata_query)
    issues = list(validate_metadata(metadata))
    outcomes = [metadata]
    reconciliation = None
    long_flow_rows = None
    if not metadata_only:
        coverage_query = loader.load(
            "source_coverage",
            2,
            timeout_seconds=timeout_seconds,
            kind=SqlKind.DATA,
        )
        coverage = runner.run(coverage_query, bounds=day.bounds)
        issues.extend(validate_coverage(coverage))
        reconciliation = coverage_reconciliation(coverage)
        long_flow_rows = optional_source_rows(coverage).get("long_flows", 0)
        outcomes.append(coverage)

    return SourceContractReport(
        day=None if metadata_only else day,
        metadata_checked=True,
        coverage_checked=not metadata_only,
        query_count=len(outcomes),
        read_rows=sum(outcome.audit.read_rows for outcome in outcomes),
        read_bytes=sum(outcome.audit.read_bytes for outcome in outcomes),
        issues=tuple(issues),
        reconciliation=reconciliation,
        elapsed_seconds=sum(outcome.audit.elapsed_seconds for outcome in outcomes),
        returned_rows=sum(outcome.audit.returned_rows for outcome in outcomes),
        long_flow_rows=long_flow_rows,
    )


def optional_source_rows(outcome: QueryOutcome) -> dict[str, int]:
    """Row counts of the optional sources, whose absence is context lost rather than a failure."""

    _require_columns(outcome, {"source_key", "row_count"})
    optional = {contract.key for contract in SOURCE_CONTRACTS if not contract.absence_is_failure}
    return {
        str(row["source_key"]): _as_non_negative_int(row["row_count"], "row_count")
        for row in outcome.dictionaries()
        if str(row["source_key"]) in optional
    }


def _require_columns(outcome: QueryOutcome, expected: set[str]) -> None:
    missing = expected - set(outcome.column_names)
    if missing:
        raise SourceContractError(f"contract query omitted result column {sorted(missing)[0]}")


def _as_non_negative_int(value: Any, field: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise SourceContractError(f"{field} is not an integer") from exc
    if parsed < 0:
        raise SourceContractError(f"{field} cannot be negative")
    return parsed
