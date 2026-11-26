"""§4 volume and cost projection: what an operator receives, and what it costs.

Read-only against the product database. Published output has ranged 1,510 to 19,676 episodes a day
and tracks the academic week (`CASE_STUDY` §11), so a single weekday measurement is not a
projection and `WeekCoverage` refuses to call one a week.

Growth is projected against the retained grains only. The published stream is not retained for 365
days; `history.client_day` and `history.client_service_day` are, and they are what the 60 GiB
volume has to hold.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

import duckdb

from network_behaviour.publication import StorageGuard
from network_behaviour.source.client import bytes_read
from network_behaviour.time import UtcDay

RETENTION_DAYS = 365
_WEEKEND = (5, 6)


class VolumeUnavailableError(RuntimeError):
    """Raised when a database cannot answer §4, rather than answering it wrongly."""


@dataclass(frozen=True, slots=True)
class DayVolume:
    """One published day, as it was published. Never re-derived here."""

    day: date
    episodes: int
    hosts: int
    tie_groups: int
    largest_tie_group: int
    e1: int
    e2: int
    e3: int
    client_rows: int
    service_rows: int
    query_count: int
    read_rows: int
    read_bytes: int
    projected_storage_bytes: int | None
    runtime_seconds: float | None

    @property
    def weekday(self) -> str:
        return self.day.strftime("%a")

    @property
    def is_weekend(self) -> bool:
        return self.day.weekday() in _WEEKEND

    def render(self) -> str:
        runtime = "n/a" if self.runtime_seconds is None else f"{self.runtime_seconds:8.1f}s"
        return (
            f"  {self.day} {self.weekday}  episodes {self.episodes:>7,}  hosts {self.hosts:>6,}  "
            f"tie groups {self.tie_groups:>6,}  E1/E2/E3 {self.e1:>6,}/{self.e2:>6,}/{self.e3:>6,}"
            f"  queries {self.query_count:>3}  {self.read_rows:>13,} rows read"
            f"{bytes_read(self.read_bytes, unit='GB')}  {runtime}"
        )


@dataclass(frozen=True, slots=True)
class WeekCoverage:
    """Whether the measured range is a week including a weekend, as §4 requires."""

    days: int
    distinct_weekdays: int
    weekend_days: int

    @property
    def sufficient(self) -> bool:
        return self.days >= 7 and self.weekend_days >= 1

    def render(self) -> str:
        if self.sufficient:
            return (
                f"coverage: {self.days} days, {self.distinct_weekdays} distinct weekdays, "
                f"{self.weekend_days} weekend day(s) — sufficient for a projection"
            )
        return (
            f"coverage: {self.days} days, {self.weekend_days} weekend day(s) — "
            "NOT a week including a weekend; this is a measurement, not a projection"
        )


@dataclass(frozen=True, slots=True)
class GrowthProjection:
    retained_client_rows: int
    retained_service_rows: int
    measured_days: int
    database_bytes: int
    alert_bytes: int
    stop_bytes: int
    projected_bytes_at_retention: int

    @property
    def headroom_fraction(self) -> float:
        return self.projected_bytes_at_retention / self.stop_bytes if self.stop_bytes else 0.0

    @property
    def crosses_stop(self) -> bool:
        return self.projected_bytes_at_retention >= self.stop_bytes

    def render(self) -> str:
        verdict = "EXCEEDS" if self.crosses_stop else "within"
        return "\n".join(
            (
                f"retained rows measured over {self.measured_days} day(s): "
                f"{self.retained_client_rows:,} client-day, "
                f"{self.retained_service_rows:,} client-service-day",
                f"database today: {self.database_bytes / 2**30:.2f} GiB",
                f"projected at {RETENTION_DAYS}-day retention: "
                f"{self.projected_bytes_at_retention / 2**30:.2f} GiB "
                f"({self.headroom_fraction:.0%} of the stop threshold) — {verdict} the ceiling",
            )
        )


@dataclass(frozen=True, slots=True)
class VolumeReport:
    days: tuple[DayVolume, ...]
    coverage: WeekCoverage
    growth: GrowthProjection | None

    def render(self) -> str:
        lines = [self.coverage.render(), ""]
        lines.extend(day.render() for day in self.days)
        if self.days:
            episodes = [day.episodes for day in self.days]
            hosts = [day.hosts for day in self.days]
            lines += [
                "",
                f"episodes per day: {min(episodes):,} to {max(episodes):,}",
                f"queued hosts per day: {min(hosts):,} to {max(hosts):,}",
                f"query footprint: {sum(day.query_count for day in self.days):,} queries, "
                f"{sum(day.read_rows for day in self.days):,} rows read"
                f"{bytes_read(sum(day.read_bytes for day in self.days), unit='GB')}",
            ]
        if self.growth is not None:
            lines += ["", self.growth.render()]
        return "\n".join(lines)


def measure_volume(
    connection: duckdb.DuckDBPyConnection,
    start: UtcDay,
    end: UtcDay,
    *,
    guard: StorageGuard | None = None,
) -> VolumeReport:
    """Report every published day in the inclusive range, plus the retained-growth projection."""

    if end < start:
        raise ValueError("end day cannot precede start day")
    _require_stream_schema(connection)
    rows = connection.execute(
        """
        SELECT
            episode.day,
            count(*),
            count(DISTINCT episode.client_ip),
            count(DISTINCT episode.tie_group),
            max(episode.tie_group_size),
            sum(CASE WHEN episode.evidence_tier = 'E1' THEN 1 ELSE 0 END),
            sum(CASE WHEN episode.evidence_tier = 'E2' THEN 1 ELSE 0 END),
            sum(CASE WHEN episode.evidence_tier = 'E3' THEN 1 ELSE 0 END)
        FROM (
            SELECT day, client_ip, tie_group, evidence_tier,
                   count(*) OVER (PARTITION BY day, tie_group) AS tie_group_size
            FROM feed.episode
            WHERE day BETWEEN ? AND ?
        ) AS episode
        GROUP BY episode.day
        ORDER BY episode.day
        """,
        [start.value, end.value],
    ).fetchall()
    runs = {
        row[0]: row[1:]
        for row in connection.execute(
            """
            SELECT day, staged_client_rows, staged_service_rows, query_count,
                   source_read_rows, source_read_bytes, projected_storage_bytes,
                   epoch(completed_at) - epoch(started_at)
            FROM ops.pipeline_run
            WHERE status = 'published' AND day BETWEEN ? AND ?
            """,
            [start.value, end.value],
        ).fetchall()
    }
    days = tuple(_day_volume(row, runs.get(row[0])) for row in rows)
    return VolumeReport(days, _coverage(days), project_growth(connection, guard or StorageGuard()))


def _day_volume(row: tuple[object, ...], run: tuple[object, ...] | None) -> DayVolume:
    day = row[0]
    if not isinstance(day, date):
        raise ValueError("feed.episode returned a non-date day")
    values = run or (None,) * 7
    return DayVolume(
        day,
        _int(row[1]),
        _int(row[2]),
        _int(row[3]),
        _int(row[4]),
        _int(row[5]),
        _int(row[6]),
        _int(row[7]),
        _int(values[0]),
        _int(values[1]),
        _int(values[2]),
        _int(values[3]),
        _int(values[4]),
        _optional_int(values[5]),
        _optional_float(values[6]),
    )


def _int(value: object) -> int:
    return 0 if value is None else int(str(value))


def _optional_int(value: object) -> int | None:
    return None if value is None else int(str(value))


def _optional_float(value: object) -> float | None:
    return None if value is None else float(str(value))


def _require_stream_schema(connection: duckdb.DuckDBPyConnection) -> None:
    """`feed.episode` arrives with migration 0008. Older stores hold pre-cutover output only."""
    row = connection.execute(
        """
        SELECT count(*) FROM information_schema.tables
        WHERE table_schema = 'feed' AND table_name = 'episode'
        """
    ).fetchone()
    if row is None or not row[0]:
        raise VolumeUnavailableError(
            "this database has no feed.episode, so it predates migration 0008 and holds only "
            "pre-cutover selected output; migrate it, or point at one that carries a v2 stream"
        )


def project_growth(
    connection: duckdb.DuckDBPyConnection,
    guard: StorageGuard,
) -> GrowthProjection | None:
    """Extrapolate the retained grains to the full 365-day window at the measured daily rate."""

    row = connection.execute(
        """
        SELECT (SELECT count(*) FROM history.client_day),
               (SELECT count(*) FROM history.client_service_day),
               (SELECT count(DISTINCT day) FROM history.client_day)
        """
    ).fetchone()
    size = connection.execute(
        "SELECT database_size, wal_size FROM pragma_database_size()"
    ).fetchone()
    if row is None or size is None or not row[2]:
        return None
    client_rows, service_rows, measured_days = int(row[0]), int(row[1]), int(row[2])
    per_day_bytes = (
        client_rows * guard.estimated_client_row_bytes
        + service_rows * guard.estimated_service_row_bytes
    ) / measured_days
    return GrowthProjection(
        client_rows,
        service_rows,
        measured_days,
        _bytes(size[0]) + _bytes(size[1]),
        guard.alert_bytes,
        guard.stop_bytes,
        int(per_day_bytes * RETENTION_DAYS),
    )


def _coverage(days: Sequence[DayVolume]) -> WeekCoverage:
    return WeekCoverage(
        len(days),
        len({day.day.weekday() for day in days}),
        sum(1 for day in days if day.is_weekend),
    )


def _bytes(raw: object) -> int:
    """DuckDB reports sizes as human strings; parse the same way the storage guard does."""
    from network_behaviour.publication import _size_bytes

    return _size_bytes(str(raw))
