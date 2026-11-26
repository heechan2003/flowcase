from random import Random

from network_behaviour.detectors.engine import _comparable_time_shape
from network_behaviour.normalization.bitmap import BITMAP_BYTES, ActivityBitmap


def _old_comparable_time_shape(current: ActivityBitmap, prior: ActivityBitmap) -> bool:
    """The set-based implementation the bit test replaced, kept as an oracle."""
    prior_buckets = set(prior.active_buckets())
    timing_overlap = any(
        candidate in prior_buckets
        for bucket in current.active_buckets()
        for candidate in (bucket - 1, bucket, bucket + 1)
        if 0 <= candidate < 288
    )
    run_tolerance = max(1, current.run_count // 2)
    gap_tolerance = max(1, current.internal_gap_count // 4)
    return (
        timing_overlap
        and abs(current.run_count - prior.run_count) <= run_tolerance
        and abs(current.internal_gap_count - prior.internal_gap_count) <= gap_tolerance
    )


def test_comparable_time_shape_matches_the_set_based_oracle() -> None:
    rng = Random(20261126)
    edges = [
        ActivityBitmap(),
        ActivityBitmap(bytes([0xFF] * BITMAP_BYTES)),
        ActivityBitmap.from_buckets([0]),
        ActivityBitmap.from_buckets([1]),
        ActivityBitmap.from_buckets([286]),
        ActivityBitmap.from_buckets([287]),
        ActivityBitmap.from_buckets([0, 287]),
        ActivityBitmap(bytes([0x55] * BITMAP_BYTES)),
        ActivityBitmap(bytes([0xAA] * BITMAP_BYTES)),
    ]
    randoms = [
        ActivityBitmap.from_buckets(rng.sample(range(288), rng.choice([1, 2, 3, 8, 40, 200])))
        for _ in range(300)
    ]
    pairs = [(a, b) for a in edges for b in edges]
    pairs += [(rng.choice(randoms), rng.choice(randoms)) for _ in range(3000)]
    # Near misses: a prior shifted by up to two buckets from the current one.
    for bitmap in randoms[:200]:
        shift = rng.choice([-2, -1, 1, 2])
        moved = [b + shift for b in bitmap.active_buckets() if 0 <= b + shift < 288]
        pairs.append((bitmap, ActivityBitmap.from_buckets(moved)))
    outcomes = set()
    for current, prior in pairs:
        expected = _old_comparable_time_shape(current, prior)
        assert _comparable_time_shape(current, prior) is expected
        outcomes.add(expected)
    assert outcomes == {True, False}
