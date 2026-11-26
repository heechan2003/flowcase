"""Fixed-width 288-bit UTC five-minute activity bitmap."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

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

    @property
    def bits(self) -> int:
        """The bitmap as an integer whose bit i is bucket i (little-endian bytes)."""
        return int.from_bytes(self.value, "little")

    def __or__(self, other: ActivityBitmap) -> ActivityBitmap:
        return ActivityBitmap((self.bits | other.bits).to_bytes(BITMAP_BYTES, "little"))

    def active_buckets(self) -> tuple[int, ...]:
        buckets: list[int] = []
        bits = self.bits
        while bits:
            low = bits & -bits
            buckets.append(low.bit_length() - 1)
            bits ^= low
        return tuple(buckets)

    @property
    def count(self) -> int:
        return self.bits.bit_count()

    @property
    def first_bucket(self) -> int | None:
        bits = self.bits
        return (bits & -bits).bit_length() - 1 if bits else None

    @property
    def last_bucket(self) -> int | None:
        bits = self.bits
        return bits.bit_length() - 1 if bits else None

    @property
    def run_count(self) -> int:
        """Active buckets whose previous bucket is idle: one per run."""
        bits = self.bits
        return (bits & ~(bits << 1)).bit_count()

    @property
    def internal_gap_count(self) -> int:
        """Idle buckets between the first and last active ones."""
        bits = self.bits
        if not bits:
            return 0
        first = (bits & -bits).bit_length() - 1
        return bits.bit_length() - first - bits.bit_count()
