"""Fixed-width 288-bit UTC five-minute activity bitmap."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import pairwise

from network_behaviour.time import UtcDay

BUCKET_COUNT = 288
BITMAP_BYTES = 36


@dataclass(frozen=True, slots=True)
class ActivityBitmap:
    """Bucket zero is the least-significant bit of byte zero."""

    value: bytes = bytes(BITMAP_BYTES)

    def __post_init__(self) -> None:
        if len(self.value) != BITMAP_BYTES:
            raise ValueError("activity bitmap must contain exactly 288 bits")

    @classmethod
    def from_buckets(cls, buckets: list[int] | tuple[int, ...]) -> ActivityBitmap:
        mutable = bytearray(BITMAP_BYTES)
        for bucket in buckets:
            if not 0 <= bucket < BUCKET_COUNT:
                raise ValueError("five-minute bucket must be between 0 and 287")
            mutable[bucket // 8] |= 1 << (bucket % 8)
        return cls(bytes(mutable))

    @classmethod
    def from_timestamps(
        cls, day: UtcDay, timestamps: list[datetime] | tuple[datetime, ...]
    ) -> ActivityBitmap:
        buckets: list[int] = []
        bounds = day.bounds
        for timestamp in timestamps:
            if (
                timestamp.tzinfo is None
                or timestamp.utcoffset() != timedelta(0)
                or not bounds.start <= timestamp < bounds.end
            ):
                raise ValueError("activity timestamp must be timezone-aware and inside the UTC day")
            seconds = int((timestamp - bounds.start).total_seconds())
            buckets.append(seconds // 300)
        return cls.from_buckets(buckets)

    def __or__(self, other: ActivityBitmap) -> ActivityBitmap:
        return ActivityBitmap(
            bytes(left | right for left, right in zip(self.value, other.value, strict=True))
        )

    def active_buckets(self) -> tuple[int, ...]:
        return tuple(
            bucket
            for bucket in range(BUCKET_COUNT)
            if self.value[bucket // 8] & (1 << (bucket % 8))
        )

    @property
    def count(self) -> int:
        return sum(byte.bit_count() for byte in self.value)

    @property
    def first_bucket(self) -> int | None:
        buckets = self.active_buckets()
        return buckets[0] if buckets else None

    @property
    def last_bucket(self) -> int | None:
        buckets = self.active_buckets()
        return buckets[-1] if buckets else None

    @property
    def run_count(self) -> int:
        buckets = self.active_buckets()
        return sum(
            index == 0 or bucket != buckets[index - 1] + 1 for index, bucket in enumerate(buckets)
        )

    @property
    def internal_gap_count(self) -> int:
        buckets = self.active_buckets()
        return sum(max(0, right - left - 1) for left, right in pairwise(buckets))
