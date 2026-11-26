from datetime import UTC, datetime
from itertools import pairwise, permutations
from random import Random

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


def _old_buckets(bitmap: ActivityBitmap) -> tuple[int, ...]:
    """The byte-loop implementation the integer one replaced, kept as an oracle."""
    return tuple(b for b in range(288) if bitmap.value[b // 8] & (1 << (b % 8)))


def _old_derived(bitmap: ActivityBitmap) -> tuple[object, ...]:
    buckets = _old_buckets(bitmap)
    return (
        buckets,
        sum(byte.bit_count() for byte in bitmap.value),
        buckets[0] if buckets else None,
        buckets[-1] if buckets else None,
        sum(i == 0 or b != buckets[i - 1] + 1 for i, b in enumerate(buckets)),
        sum(max(0, right - left - 1) for left, right in pairwise(buckets)),
    )


def _bitmap_cases() -> list[ActivityBitmap]:
    rng = Random(20261126)
    edges = [
        ActivityBitmap(),
        ActivityBitmap(bytes([0xFF] * BITMAP_BYTES)),
        ActivityBitmap.from_buckets([0]),
        ActivityBitmap.from_buckets([287]),
        ActivityBitmap.from_buckets([0, 287]),
        ActivityBitmap(bytes([0x55] * BITMAP_BYTES)),
        ActivityBitmap(bytes([0xAA] * BITMAP_BYTES)),
    ]
    randoms = [
        ActivityBitmap.from_buckets(rng.sample(range(288), rng.randint(1, 288))) for _ in range(500)
    ]
    sparse = [
        ActivityBitmap.from_buckets(rng.sample(range(288), rng.randint(1, 6))) for _ in range(200)
    ]
    return edges + randoms + sparse


def test_bitmap_derivations_match_the_byte_loop_oracle() -> None:
    cases = _bitmap_cases()
    for bitmap in cases:
        assert (
            bitmap.active_buckets(),
            bitmap.count,
            bitmap.first_bucket,
            bitmap.last_bucket,
            bitmap.run_count,
            bitmap.internal_gap_count,
        ) == _old_derived(bitmap)
    for left, right in zip(cases, reversed(cases), strict=True):
        expected = bytes(a | b for a, b in zip(left.value, right.value, strict=True))
        assert (left | right).value == expected
