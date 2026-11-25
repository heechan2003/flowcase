"""Validated, idempotent, atomic publication of one staged UTC day."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any, Final
from uuid import UUID, uuid4

import duckdb
import pyarrow as pa

from network_behaviour.aggregation import (
    AGGREGATION_VERSION,
    COMPATIBLE_AGGREGATION_VERSIONS,
    ClientDayRow,
    ClientServiceDayRow,
    StagedDay,
)
from network_behaviour.source.day import (
    COMPATIBLE_QUERY_VERSIONS_JSON,
    COMPATIBLE_SOURCE_QUERY_BUNDLE_VERSIONS,
    SOURCE_QUERY_BUNDLE_VERSION,
    ReconciliationTotals,
    SourceDayInputs,
)
from network_behaviour.time import UtcDay

RECONCILIATION_VERSION = "activity-rate-relative-v1"
RECONCILIATION_RELATIVE_TOLERANCE = 0.05
SOURCE_DUPLICATE_FRACTION_TOLERANCE = 0.01
NORMALIZATION_BUNDLE_VERSION = (
    "service-id-v1/category-id-v1/port-groups-v1/bitmap-288-lsb-v1/tldextract-5.3.1"
)
# Generations a published day may carry and still stream back; see
# `aggregation.COMPATIBLE_AGGREGATION_VERSIONS` for why these are allow-lists.
COMPATIBLE_RECONCILIATION_VERSIONS = frozenset({RECONCILIATION_VERSION})
COMPATIBLE_NORMALIZATION_BUNDLE_VERSIONS = frozenset({NORMALIZATION_BUNDLE_VERSION})
RETENTION_DAYS = 365
GIB: Final = 1024**3
DEFAULT_ALERT_BYTES = 40 * GIB
DEFAULT_STOP_BYTES = 45 * GIB

_CLIENT_COLUMNS = (
    "day, client_ip, up_bytes, down_bytes, up_packets, down_packets, flow_count, "
    "active_minutes, active_5m_buckets, unique_servers, unique_services, unique_routes, "
    "unique_asns, unique_port_groups, top_service_up_bytes, top_service_total_bytes, "
    "opaque_bytes, p95_5m_up_bytes, max_5m_up_bytes, p95_5m_unique_servers, "
    "max_5m_unique_servers, p95_5m_unique_services, max_5m_unique_services, "
    "p95_5m_unique_port_groups, max_5m_unique_port_groups, "
    "p95_bucket_up_rate_p95_bps, max_bucket_up_rate_p95_bps, large_flow_count, "
    "large_flow_up_bytes, max_large_flow_bytes, max_large_flow_duration_sec"
)
_SERVICE_COLUMNS = (
    "day, client_ip, service_id, service_basis, asn_id, application_category_id, "
    "transport_protocol, port_group, active_5m_bitmap, up_bytes, down_bytes, flow_count, "
    "unique_servers, large_flow_count, large_flow_up_bytes, max_large_flow_bytes, "
    "max_large_flow_duration_sec"
)
_CLIENT_NAMES = tuple(_CLIENT_COLUMNS.split(", "))
_SERVICE_NAMES = tuple(_SERVICE_COLUMNS.split(", "))
_CLIENT_ARROW_TYPES: tuple[pa.DataType, ...] = (
    pa.date32(),
    pa.string(),
    *(pa.uint64() for _ in range(5)),
    pa.uint16(),
    pa.uint16(),
    *(pa.uint64() for _ in range(8)),
    pa.float64(),
    pa.uint64(),
    pa.float64(),
    pa.uint64(),
    pa.float64(),
    pa.uint64(),
    pa.float64(),
    pa.uint64(),
    pa.float64(),
    pa.float64(),
    pa.uint64(),
    pa.uint64(),
    pa.uint64(),
    pa.float64(),
)
_SERVICE_ARROW_TYPES: tuple[pa.DataType, ...] = (
    pa.date32(),
    pa.string(),
    pa.binary(16),
    pa.string(),
    pa.uint64(),
    pa.uint64(),
    pa.uint8(),
    pa.uint32(),
    pa.binary(36),
    *(pa.uint64() for _ in range(7)),
    pa.float64(),
)
_SIZE = re.compile(r"^(?P<value>[0-9]+(?:\.[0-9]+)?)\s+(?P<unit>bytes|KiB|MiB|GiB|TiB)$")

ScorePublisher = Callable[[duckdb.DuckDBPyConnection, UtcDay, UUID], int | None]


class PublicationError(RuntimeError):
    """Raised when a staged day cannot be safely published."""


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    relative_delta: float
    duplicate_fraction: float
    version: str = RECONCILIATION_VERSION


@dataclass(frozen=True, slots=True)
class StorageAssessment:
    current_bytes: int
    projected_bytes: int
    alert: bool


@dataclass(frozen=True, slots=True)
class PublicationResult:
    run_id: UUID
    day: UtcDay
    client_rows: int
    service_rows: int
    reconciliation_relative_delta: float
    storage: StorageAssessment
    idempotent: bool
    timings: PublicationTimings


@dataclass(frozen=True, slots=True)
class PublicationTimings:
    staging_seconds: float = 0.0
    validation_seconds: float = 0.0
    publication_seconds: float = 0.0
    cleanup_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class ReconciliationPolicy:
    relative_tolerance: float = RECONCILIATION_RELATIVE_TOLERANCE
    duplicate_fraction_tolerance: float = SOURCE_DUPLICATE_FRACTION_TOLERANCE
    version: str = RECONCILIATION_VERSION

    def __post_init__(self) -> None:
        if not 0 <= self.relative_tolerance < 1:
            raise ValueError("reconciliation tolerance must be between zero and one")
        if not 0 <= self.duplicate_fraction_tolerance < 1:
            raise ValueError("duplicate tolerance must be between zero and one")

    def validate(
        self,
        staged: StagedDay,
        source: ReconciliationTotals,
    ) -> ReconciliationResult:
        staged_up = sum(row.up_bytes for row in staged.client_rows)
        staged_down = sum(row.down_bytes for row in staged.client_rows)
        if (staged_up, staged_down) != (
            source.activity_up_bytes,
            source.activity_down_bytes,
        ):
            raise PublicationError("staged client totals do not reconcile to activity source")
        up_delta = _relative_delta(source.activity_up_bytes, source.rate_up_bytes)
        down_delta = _relative_delta(source.activity_down_bytes, source.rate_down_bytes)
        delta = max(up_delta, down_delta)
        if delta > self.relative_tolerance:
            raise PublicationError(f"activity/rate reconciliation exceeds {self.version} tolerance")
        if source.unique_activity_grain_rows > source.activity_rows:
            raise PublicationError("source duplicate counts are inconsistent")
        duplicate_fraction = (
            (source.activity_rows - source.unique_activity_grain_rows) / source.activity_rows
            if source.activity_rows
            else 0.0
        )
        if duplicate_fraction > self.duplicate_fraction_tolerance:
            raise PublicationError(f"source duplicate fraction exceeds {self.version} tolerance")
        return ReconciliationResult(delta, duplicate_fraction, self.version)


@dataclass(frozen=True, slots=True)
class StorageGuard:
    alert_bytes: int = DEFAULT_ALERT_BYTES
    stop_bytes: int = DEFAULT_STOP_BYTES
    estimated_client_row_bytes: int = 512
    estimated_service_row_bytes: int = 256

    def __post_init__(self) -> None:
        if not 0 < self.alert_bytes < self.stop_bytes:
            raise ValueError("storage alert must be positive and below the stop threshold")

    def assess(
        self, connection: duckdb.DuckDBPyConnection, *, client_rows: int, service_rows: int
    ) -> StorageAssessment:
        row = connection.execute(
            "SELECT database_size, wal_size FROM pragma_database_size()"
        ).fetchone()
        if row is None:
            raise PublicationError("cannot measure DuckDB storage")
        current = _size_bytes(str(row[0])) + _size_bytes(str(row[1]))
        projected = (
            current
            + client_rows * self.estimated_client_row_bytes
            + service_rows * self.estimated_service_row_bytes
        )
        if projected >= self.stop_bytes:
            raise PublicationError(
                "projected retained storage reaches the configured stop threshold"
            )
        return StorageAssessment(current, projected, projected >= self.alert_bytes)


class DayPublisher:
    """Stage in temporary tables, score, and publish inside one transaction."""

    def __init__(
        self,
        connection: duckdb.DuckDBPyConnection,
        *,
        reconciliation_policy: ReconciliationPolicy | None = None,
        storage_guard: StorageGuard | None = None,
    ) -> None:
        self._connection = connection
        self._reconciliation = reconciliation_policy or ReconciliationPolicy()
        self._storage_guard = storage_guard or StorageGuard()

    def publish(
        self,
        source: SourceDayInputs,
        staged: StagedDay,
        score_and_publish_candidates: ScorePublisher,
        *,
        now: datetime | None = None,
        existing_run_id: UUID | None = None,
    ) -> PublicationResult:
        current = datetime.now(UTC) if now is None else now
        staged.day.ensure_completed(current)
        if source.day != staged.day:
            raise PublicationError("source and staged UTC days differ")
        if staged.aggregation_version != AGGREGATION_VERSION:
            raise PublicationError("unsupported day aggregation version")

        existing = self._existing_publication(staged.day, source)
        if existing is not None:
            return existing
        self._require_no_orphan_history(staged.day)

        run_id = existing_run_id or uuid4()
        schema_version = self._schema_version()
        manifest_values = [
            SOURCE_QUERY_BUNDLE_VERSION,
            schema_version,
            NORMALIZATION_BUNDLE_VERSION,
            source.query_versions_json,
            staged.aggregation_version,
            self._reconciliation.version,
            source.query_count,
            source.read_rows,
            source.read_bytes,
        ]
        if existing_run_id is None:
            self._connection.execute(
                """
                INSERT INTO ops.pipeline_run (
                    run_id, day, status, started_at, source_sql_version, schema_version,
                    normalization_version, query_versions_json, aggregation_version,
                    reconciliation_version, query_count, source_read_rows, source_read_bytes
                ) VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [run_id, staged.day.value, current, *manifest_values],
            )
        else:
            existing_manifest = self._connection.execute(
                "SELECT day, status FROM ops.pipeline_run WHERE run_id = ?", [run_id]
            ).fetchone()
            if (
                existing_manifest is None
                or str(existing_manifest[0]) != str(staged.day)
                or str(existing_manifest[1]) != "running"
            ):
                raise PublicationError("existing run manifest is unavailable or incompatible")
            self._connection.execute(
                """
                UPDATE ops.pipeline_run
                SET source_sql_version = ?, schema_version = ?, normalization_version = ?,
                    query_versions_json = ?, aggregation_version = ?,
                    reconciliation_version = ?, query_count = ?, source_read_rows = ?,
                    source_read_bytes = ?
                WHERE run_id = ?
                """,
                [*manifest_values, run_id],
            )

        staging_seconds = 0.0
        validation_seconds = 0.0
        publication_seconds = 0.0
        cleanup_seconds = 0.0
        try:
            stage_started = monotonic()
            self._create_staging(staged)
            staging_seconds = monotonic() - stage_started
            validation_started = monotonic()
            reconciliation = self._reconciliation.validate(staged, source.reconciliation)
            storage = self._storage_guard.assess(
                self._connection,
                client_rows=len(staged.client_rows),
                service_rows=len(staged.service_rows),
            )
            self._validate_staging(staged.day)
            validation_seconds = monotonic() - validation_started
            publication_started = monotonic()
            self._connection.execute("BEGIN TRANSACTION")
            try:
                # The callback sees day D in temp staging but never in published history.
                candidate_projected_storage = score_and_publish_candidates(
                    self._connection, staged.day, run_id
                )
                if candidate_projected_storage is not None:
                    if candidate_projected_storage < storage.current_bytes:
                        raise PublicationError(
                            "candidate publication returned an invalid storage projection"
                        )
                    storage = StorageAssessment(
                        storage.current_bytes,
                        max(storage.projected_bytes, candidate_projected_storage),
                        storage.alert
                        or candidate_projected_storage >= self._storage_guard.alert_bytes,
                    )
                self._connection.execute(
                    f"INSERT INTO history.client_day ({_CLIENT_COLUMNS}) "
                    f"SELECT {_CLIENT_COLUMNS} FROM staging_client_day"
                )
                self._connection.execute(
                    f"INSERT INTO history.client_service_day ({_SERVICE_COLUMNS}) "
                    f"SELECT {_SERVICE_COLUMNS} FROM staging_client_service_day"
                )
                cutoff = staged.day.value - timedelta(days=RETENTION_DAYS - 1)
                self._connection.execute("DELETE FROM history.client_day WHERE day < ?", [cutoff])
                self._connection.execute(
                    "DELETE FROM history.client_service_day WHERE day < ?", [cutoff]
                )
                self._connection.execute(
                    """
                    UPDATE ops.pipeline_run
                    SET status = 'published', completed_at = ?,
                        reconciliation_relative_delta = ?, staged_client_rows = ?,
                        source_duplicate_fraction = ?, staged_service_rows = ?,
                        storage_bytes_before = ?,
                        projected_storage_bytes = ?
                    WHERE run_id = ?
                    """,
                    [
                        datetime.now(UTC),
                        reconciliation.relative_delta,
                        len(staged.client_rows),
                        reconciliation.duplicate_fraction,
                        len(staged.service_rows),
                        storage.current_bytes,
                        storage.projected_bytes,
                        run_id,
                    ],
                )
                self._connection.execute("COMMIT")
                publication_seconds = monotonic() - publication_started
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        except Exception as exc:
            self._mark_failed(run_id, datetime.now(UTC), type(exc).__name__)
            if isinstance(exc, PublicationError):
                raise
            raise PublicationError("day publication failed") from exc
        finally:
            cleanup_started = monotonic()
            self._drop_staging()
            cleanup_seconds = monotonic() - cleanup_started

        return PublicationResult(
            run_id,
            staged.day,
            len(staged.client_rows),
            len(staged.service_rows),
            reconciliation.relative_delta,
            storage,
            False,
            PublicationTimings(
                staging_seconds,
                validation_seconds,
                publication_seconds,
                cleanup_seconds,
            ),
        )

    def _create_staging(self, staged: StagedDay) -> None:
        self._drop_staging()
        self._connection.execute(
            "CREATE TEMP TABLE staging_client_day AS SELECT * FROM history.client_day WHERE false"
        )
        self._connection.execute(
            "CREATE TEMP TABLE staging_client_service_day AS "
            "SELECT * FROM history.client_service_day WHERE false"
        )
        if staged.client_rows:
            self._insert_arrow(
                "staging_client_day",
                _CLIENT_COLUMNS,
                _arrow_table(
                    staged.client_rows,
                    _CLIENT_NAMES,
                    _CLIENT_ARROW_TYPES,
                ),
            )
        if staged.service_rows:
            self._insert_arrow(
                "staging_client_service_day",
                _SERVICE_COLUMNS,
                _arrow_table(
                    staged.service_rows,
                    _SERVICE_NAMES,
                    _SERVICE_ARROW_TYPES,
                ),
            )

    def _insert_arrow(self, table: str, columns: str, arrow: pa.Table) -> None:
        registration = f"_{table}_arrow"
        self._connection.register(registration, arrow)
        try:
            self._connection.execute(
                f"INSERT INTO {table} ({columns}) SELECT {columns} FROM {registration}"
            )
        finally:
            self._connection.unregister(registration)

    def _validate_staging(self, day: UtcDay) -> None:
        client_count = int(
            _required_row(
                self._connection.execute("SELECT count(*) FROM staging_client_day").fetchone()
            )[0]
        )
        if client_count == 0:
            raise PublicationError("staged day contains no client rows")
        invalid_days = int(
            _required_row(
                self._connection.execute(
                    """
                    SELECT
                        count(*) FILTER (WHERE day <> ?) +
                        (SELECT count(*) FILTER (WHERE day <> ?)
                         FROM staging_client_service_day)
                    FROM staging_client_day
                    """,
                    [day.value, day.value],
                ).fetchone()
            )[0]
        )
        if invalid_days:
            raise PublicationError("staging contains rows outside day D")
        orphan_services = int(
            _required_row(
                self._connection.execute(
                    """
                    SELECT count(*)
                    FROM staging_client_service_day service
                    ANTI JOIN staging_client_day client
                      ON client.day = service.day AND client.client_ip = service.client_ip
                    """
                ).fetchone()
            )[0]
        )
        if orphan_services:
            raise PublicationError("staging contains service rows without a client row")
        duplicate_clients = int(
            _required_row(
                self._connection.execute(
                    """
                    SELECT count(*) FROM (
                        SELECT day, client_ip FROM staging_client_day
                        GROUP BY day, client_ip HAVING count(*) > 1
                    )
                    """
                ).fetchone()
            )[0]
        )
        duplicate_services = int(
            _required_row(
                self._connection.execute(
                    """
                    SELECT count(*) FROM (
                        SELECT day, client_ip, service_id, asn_id, application_category_id,
                               transport_protocol, port_group
                        FROM staging_client_service_day
                        GROUP BY ALL HAVING count(*) > 1
                    )
                    """
                ).fetchone()
            )[0]
        )
        if duplicate_clients or duplicate_services:
            raise PublicationError("staging violates retained-grain uniqueness")

    def _existing_publication(
        self, day: UtcDay, source: SourceDayInputs
    ) -> PublicationResult | None:
        # The generations this run would write, plus the allow-lists `DayRunService._published`
        # applies: a day published under an earlier compatible generation is already published,
        # never a candidate for a second run.
        allowed = (
            ("source_sql_version", sorted(COMPATIBLE_SOURCE_QUERY_BUNDLE_VERSIONS)),
            (
                "query_versions_json",
                sorted(COMPATIBLE_QUERY_VERSIONS_JSON | {source.query_versions_json}),
            ),
            ("aggregation_version", sorted(COMPATIBLE_AGGREGATION_VERSIONS)),
            (
                "reconciliation_version",
                sorted(COMPATIBLE_RECONCILIATION_VERSIONS | {self._reconciliation.version}),
            ),
            ("normalization_version", sorted(COMPATIBLE_NORMALIZATION_BUNDLE_VERSIONS)),
        )
        predicates = " ".join(
            f"AND {column} IN ({', '.join('?' for _ in values)})" for column, values in allowed
        )
        row = self._connection.execute(
            f"""
            SELECT run_id, staged_client_rows, staged_service_rows,
                   reconciliation_relative_delta, storage_bytes_before,
                   projected_storage_bytes
            FROM ops.pipeline_run
            WHERE day = ? AND status = 'published' {predicates}
            ORDER BY completed_at DESC LIMIT 1
            """,
            [day.value, *(value for _, values in allowed for value in values)],
        ).fetchone()
        if row is None:
            return None
        return PublicationResult(
            UUID(str(row[0])),
            day,
            int(row[1]),
            int(row[2]),
            float(row[3]),
            StorageAssessment(
                int(row[4]), int(row[5]), int(row[5]) >= self._storage_guard.alert_bytes
            ),
            True,
            PublicationTimings(),
        )

    def _require_no_orphan_history(self, day: UtcDay) -> None:
        count = int(
            _required_row(
                self._connection.execute(
                    """
                    SELECT
                        (SELECT count(*) FROM history.client_day WHERE day = ?) +
                        (SELECT count(*) FROM history.client_service_day WHERE day = ?)
                    """,
                    [day.value, day.value],
                ).fetchone()
            )[0]
        )
        if count:
            raise PublicationError("day D history exists without a matching published manifest")

    def _schema_version(self) -> int:
        row = self._connection.execute("SELECT max(version) FROM _schema_migrations").fetchone()
        if row is None or row[0] is None:
            raise PublicationError("database schema version is unavailable")
        return int(row[0])

    def _mark_failed(self, run_id: UUID, completed_at: datetime, failure_code: str) -> None:
        self._connection.execute(
            """
            UPDATE ops.pipeline_run
            SET status = 'failed', completed_at = ?, failure_code = ?
            WHERE run_id = ? AND status = 'running'
            """,
            [completed_at, failure_code[:80], run_id],
        )

    def _drop_staging(self) -> None:
        self._connection.execute("DROP TABLE IF EXISTS staging_client_service_day")
        self._connection.execute("DROP TABLE IF EXISTS staging_client_day")


def _relative_delta(left: int, right: int) -> float:
    return abs(left - right) / max(left, right, 1)


def _required_row(row: tuple[Any, ...] | None) -> tuple[Any, ...]:
    if row is None:
        raise PublicationError("publication validation query returned no row")
    return row


def _arrow_table(
    rows: tuple[ClientDayRow, ...] | tuple[ClientServiceDayRow, ...],
    names: tuple[str, ...],
    types: tuple[pa.DataType, ...],
) -> pa.Table:
    if len(names) != len(types):
        raise AssertionError("Arrow staging schema is inconsistent")
    arrays = [
        pa.array([getattr(row, name) for row in rows], type=type_name)
        for name, type_name in zip(names, types, strict=True)
    ]
    return pa.Table.from_arrays(arrays, names=names)


def _size_bytes(raw: str) -> int:
    match = _SIZE.fullmatch(raw)
    if match is None:
        raise PublicationError("DuckDB returned an unsupported storage-size value")
    scale = {"bytes": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    return int(float(match.group("value")) * scale[match.group("unit")])
