from datetime import UTC, datetime
from itertools import permutations

import pytest

from network_behaviour.normalization.bitmap import BITMAP_BYTES, ActivityBitmap
from network_behaviour.time import UtcDay


def test_bitmap_has_fixed_width_and_documented_bit_order() -> None:
    bitmap = ActivityBitmap.from_buckets([0, 7, 8, 287])

    assert len(bitmap.value) == BITMAP_BYTES
    assert bitmap.value[0] == 0b10000001
    assert bitmap.value[1] == 0b00000001
    assert bitmap.value[-1] == 0b10000000


def test_bitmap_derives_counts_runs_and_gaps() -> None:
    bitmap = ActivityBitmap.from_buckets([1, 2, 5, 7, 8])

    assert bitmap.active_buckets() == (1, 2, 5, 7, 8)
    assert bitmap.count == 5
    assert bitmap.first_bucket == 1
    assert bitmap.last_bucket == 8
    assert bitmap.run_count == 3
    assert bitmap.internal_gap_count == 3


def test_bitmap_union_and_source_reordering_are_deterministic() -> None:
    buckets = [1, 2, 5, 287]
    expected = ActivityBitmap.from_buckets(buckets)

    for ordering in permutations(buckets):
        assert ActivityBitmap.from_buckets(ordering) == expected
    assert ActivityBitmap.from_buckets([1, 5]) | ActivityBitmap.from_buckets([2, 287]) == expected


def test_timestamp_bucket_mapping_is_utc_and_day_bounded() -> None:
    day = UtcDay.parse("2026-07-10")
    bitmap = ActivityBitmap.from_timestamps(
        day,
        [
            datetime(2026, 7, 10, 0, 0, tzinfo=UTC),
            datetime(2026, 7, 10, 23, 59, 59, tzinfo=UTC),
        ],
    )

    assert bitmap.active_buckets() == (0, 287)
    with pytest.raises(ValueError):
        ActivityBitmap.from_timestamps(day, [datetime(2026, 7, 11, 0, 0, tzinfo=UTC)])


@pytest.mark.parametrize("size", [0, 35, 37])
def test_bitmap_rejects_wrong_width(size: int) -> None:
    with pytest.raises(ValueError):
        ActivityBitmap(bytes(size))
