"""Conservative adapters from available transient timing to episode signals."""

from __future__ import annotations

from datetime import timedelta

from network_behaviour.detectors.models import DetectorSignal
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.ranking.models import (
    DataQualityConfidence,
    EpisodeSignal,
    SignalStatus,
    TemporalPrecision,
)
from network_behaviour.time import UtcDay


def day_level_signal(
    day: UtcDay,
    signal: DetectorSignal,
    *,
    status: SignalStatus = SignalStatus.ELIGIBLE,
    data_quality_confidence: DataQualityConfidence = DataQualityConfidence.NORMAL,
) -> EpisodeSignal:
    """Keep a signal separate when only day-level timing is available."""
    return EpisodeSignal(
        signal,
        day.bounds.start,
        day.bounds.end,
        TemporalPrecision.DAY,
        status,
        data_quality_confidence,
    )


def bitmap_signal_windows(
    day: UtcDay,
    signal: DetectorSignal,
    bitmap: ActivityBitmap,
    *,
    status: SignalStatus = SignalStatus.ELIGIBLE,
    data_quality_confidence: DataQualityConfidence = DataQualityConfidence.NORMAL,
) -> tuple[EpisodeSignal, ...]:
    """Split a retained relationship bitmap into exact contiguous five-minute windows."""
    buckets = bitmap.active_buckets()
    if not buckets:
        raise ValueError("episode bitmap cannot be empty")
    runs: list[tuple[int, int]] = []
    first = buckets[0]
    previous = first
    for bucket in buckets[1:]:
        if bucket != previous + 1:
            runs.append((first, previous))
            first = bucket
        previous = bucket
    runs.append((first, previous))
    return tuple(
        EpisodeSignal(
            signal,
            day.bounds.start + timedelta(minutes=first_bucket * 5),
            day.bounds.start + timedelta(minutes=(last_bucket + 1) * 5),
            TemporalPrecision.FIVE_MINUTE,
            status,
            data_quality_confidence,
        )
        for first_bucket, last_bucket in runs
    )
