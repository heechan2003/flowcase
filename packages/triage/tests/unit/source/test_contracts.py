from typing import Any

from network_behaviour.source.client import QueryAudit, QueryOutcome, bytes_read
from network_behaviour.source.contracts import (
    SOURCE_CONTRACTS,
    SourceContractReport,
    coverage_reconciliation,
    optional_source_rows,
    validate_coverage,
    validate_metadata,
)
from network_behaviour.time import UtcDay

DAY = UtcDay.parse("2026-07-10")


def _outcome(columns: tuple[str, ...], rows: list[tuple[Any, ...]]) -> QueryOutcome:
    return QueryOutcome(
        columns,
        tuple(rows),
        QueryAudit("test", 1, "query", 0.1, len(rows), 0, 0, True, "passed"),
    )


def _valid_metadata_rows() -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = []
    for contract in SOURCE_CONTRACTS:
        rows.extend(
            (contract.database, contract.table, column.name, column.type_name, "BASE TABLE")
            for column in contract.columns
        )
    return rows


def test_metadata_contract_accepts_exact_documented_schema() -> None:
    outcome = _outcome(
        ("database", "table", "column_name", "column_type", "engine"),
        _valid_metadata_rows(),
    )

    assert validate_metadata(outcome) == ()


def test_metadata_contract_fails_closed_on_missing_column_and_type_drift() -> None:
    rows = _valid_metadata_rows()
    rows.pop(0)
    database, table, column, _type_name, engine = rows[0]
    rows[0] = (database, table, column, "HUGEINT", engine)
    outcome = _outcome(("database", "table", "column_name", "column_type", "engine"), rows)

    issues = validate_metadata(outcome)

    assert {issue.code for issue in issues} >= {"missing_column", "wrong_type"}


def test_coverage_requires_complete_principal_buckets_but_allows_optional_absence() -> None:
    outcome = _outcome(
        ("source_key", "row_count", "bucket_count", "invalid_grain_rows"),
        [
            ("activity_1m", 1_000, 1_440, 0),
            ("host_load_5m", 500, 288, 0),
            ("dns_pairs", 0, 0, 0),
            ("long_flows", 0, 0, 0),
        ],
    )

    assert validate_coverage(outcome) == ()
    # Absence is not a failure, but it is reported: the run scores without that context.
    assert optional_source_rows(outcome) == {"dns_pairs": 0, "long_flows": 0}


def test_coverage_fails_on_incomplete_day_or_wrong_grain() -> None:
    outcome = _outcome(
        ("source_key", "row_count", "bucket_count", "invalid_grain_rows"),
        [
            ("activity_1m", 1_000, 1_439, 0),
            ("host_load_5m", 500, 288, 1),
            ("dns_pairs", 0, 0, 0),
            ("long_flows", 0, 0, 0),
        ],
    )

    issues = validate_coverage(outcome)

    assert {issue.code for issue in issues} == {"incomplete_day", "wrong_grain"}


def test_coverage_exposes_activity_rate_reconciliation() -> None:
    outcome = _outcome(
        (
            "source_key",
            "row_count",
            "bucket_count",
            "invalid_grain_rows",
            "up_bytes",
            "down_bytes",
            "unique_grain_rows",
        ),
        [
            ("activity_1m", 1_000, 1_440, 0, 100, 50, 999),
            ("host_load_5m", 500, 288, 0, 99, 51, 0),
            ("dns_pairs", 0, 0, 0, 0, 0, 0),
            ("long_flows", 0, 0, 0, 0, 0, 0),
        ],
    )

    result = coverage_reconciliation(outcome)

    assert result.activity_up_bytes == 100
    assert result.rate_down_bytes == 51
    assert result.activity_rows == 1_000
    assert result.unique_activity_grain_rows == 999


def test_the_footprint_states_bytes_only_when_the_source_measured_them() -> None:
    """DuckDB counts rows scanned and no bytes, so its 0 is not a measurement to print."""
    unmeasured = SourceContractReport(DAY, True, True, 2, 1_500, 0, ()).render()
    measured = SourceContractReport(DAY, True, True, 2, 1_500, 2_048, ()).render()

    assert "1500 rows read, 0.000 seconds" in unmeasured
    assert "bytes read" not in unmeasured
    assert "1500 rows read, 2,048 bytes read, 0.000 seconds" in measured


def test_bytes_read_gives_bytes_or_gigabytes_and_nothing_unmeasured() -> None:
    assert bytes_read(0) == bytes_read(0, unit="GB") == ""
    assert bytes_read(2_048) == ", 2,048 bytes read"
    assert bytes_read(1_234_000_000, unit="GB") == ", 1.23 GB read"
