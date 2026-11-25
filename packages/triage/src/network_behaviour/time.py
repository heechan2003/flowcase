"""UTC day and bounded-time domain types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta


@dataclass(frozen=True, slots=True)
class UtcBounds:
    """A non-empty half-open UTC interval."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("query bounds must be timezone-aware")
        if self.start.utcoffset() != timedelta(0) or self.end.utcoffset() != timedelta(0):
            raise ValueError("query bounds must be UTC")
        if self.start >= self.end:
            raise ValueError("query bounds must be a non-empty half-open interval")


def partition_utc_bounds(bounds: UtcBounds, maximum: timedelta) -> tuple[UtcBounds, ...]:
    """Partition one half-open UTC interval into adjacent bounded slices."""

    if maximum <= timedelta(0):
        raise ValueError("maximum query slice duration must be positive")
    result: list[UtcBounds] = []
    start = bounds.start
    while start < bounds.end:
        end = min(start + maximum, bounds.end)
        result.append(UtcBounds(start, end))
        start = end
    return tuple(result)


@dataclass(frozen=True, order=True, slots=True)
class UtcDay:
    """A completed UTC calendar day eligible for T+1 processing."""

    value: date

    @classmethod
    def parse(cls, raw: str) -> UtcDay:
        try:
            return cls(date.fromisoformat(raw))
        except ValueError as exc:
            raise ValueError("day must use YYYY-MM-DD") from exc

    @classmethod
    def latest_completed(cls, now: datetime | None = None) -> UtcDay:
        current = datetime.now(UTC) if now is None else _require_utc(now)
        today = current.date()
        candidate = today - timedelta(days=1 if current.time() >= time(8) else 2)
        return cls(candidate)

    @property
    def bounds(self) -> UtcBounds:
        start = datetime.combine(self.value, time.min, tzinfo=UTC)
        return UtcBounds(start=start, end=start + timedelta(days=1))

    @property
    def eligible_at(self) -> datetime:
        return self.bounds.end + timedelta(hours=8)

    def ensure_completed(self, now: datetime | None = None) -> None:
        current = datetime.now(UTC) if now is None else _require_utc(now)
        if current < self.eligible_at:
            raise ValueError(
                f"UTC day {self.value.isoformat()} is not eligible until "
                f"{self.eligible_at.isoformat()}"
            )

    def __str__(self) -> str:
        return self.value.isoformat()


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("current time must be timezone-aware UTC")
    return value
