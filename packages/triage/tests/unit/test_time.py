from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest

from network_behaviour.time import UtcBounds, UtcDay, partition_utc_bounds


def test_day_is_not_eligible_before_t_plus_one_0800() -> None:
    day = UtcDay.parse("2026-07-10")

    with pytest.raises(ValueError, match="not eligible"):
        day.ensure_completed(datetime(2026, 7, 11, 7, 59, tzinfo=UTC))


def test_day_is_eligible_at_t_plus_one_0800() -> None:
    day = UtcDay.parse("2026-07-10")

    day.ensure_completed(datetime(2026, 7, 11, 8, 0, tzinfo=UTC))
    assert day.bounds.start.isoformat() == "2026-07-10T00:00:00+00:00"
    assert day.bounds.end.isoformat() == "2026-07-11T00:00:00+00:00"


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (datetime(2026, 7, 12, 7, 59, tzinfo=UTC), "2026-07-10"),
        (datetime(2026, 7, 12, 8, 0, tzinfo=UTC), "2026-07-11"),
    ],
)
def test_latest_completed_day(now: datetime, expected: str) -> None:
    assert str(UtcDay.latest_completed(now)) == expected


def test_utc_bounds_are_partitioned_into_adjacent_bounded_slices() -> None:
    bounds = UtcBounds(
        datetime(2026, 7, 10, tzinfo=UTC),
        datetime(2026, 7, 10, 5, 30, tzinfo=UTC),
    )

    slices = partition_utc_bounds(bounds, timedelta(hours=2))

    assert tuple(item.end - item.start for item in slices) == (
        timedelta(hours=2),
        timedelta(hours=2),
        timedelta(hours=1, minutes=30),
    )
    assert slices[0].start == bounds.start
    assert slices[-1].end == bounds.end
    assert all(left.end == right.start for left, right in pairwise(slices))


def test_utc_bounds_reject_non_positive_slice_duration() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        partition_utc_bounds(UtcDay.parse("2026-07-10").bounds, timedelta(0))
