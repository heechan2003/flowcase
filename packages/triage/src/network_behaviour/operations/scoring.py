"""The day-D scoring path: staged rows plus history in, a ranked population out.

Extracted from `operations/pipeline.py` so publication and `network_behaviour.evaluation` run the
same code. The alternative — a harness with its own copy of baselines, detection and ranking —
would measure the copy, which is the failure this repository is recovering from.

Scoring is pure with respect to the connection: it reads `history.*` and writes nothing.
Publication is what writes, and it stays in `pipeline.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import duckdb

from network_behaviour.aggregation import ClientServiceDayRow, StagedDay
from network_behaviour.baselines import BaselineEngine, SourceQualityInput
from network_behaviour.baselines.models import BaselineBatch, BaselinePolicy
from network_behaviour.detectors import (
    DetectorEngine,
    DnsDailyObservation,
    PersistenceHistoryRepository,
)
from network_behaviour.detectors.models import (
    DetectionBatch,
    DetectorFamily,
    DetectorPolicy,
    DetectorSignal,
)
from network_behaviour.instrumentation import ConditionRecorder
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.population import PopulationCensus, take_census
from network_behaviour.ranking import (
    EpisodeSignal,
    RankingEngine,
    RankingPolicy,
    bitmap_signal_windows,
    day_level_signal,
)
from network_behaviour.ranking.models import RankingBatch
from network_behaviour.time import UtcDay


@dataclass(frozen=True, slots=True)
class ScoringPolicies:
    """Every tuned input to one scored day, so a harness can perturb one and hold the rest."""

    ranking: RankingPolicy = field(default_factory=RankingPolicy)
    detector: DetectorPolicy = field(default_factory=DetectorPolicy)
    baseline: BaselinePolicy = field(default_factory=BaselinePolicy)
    source_quality: SourceQualityInput = field(default_factory=SourceQualityInput)


@dataclass(frozen=True, slots=True)
class ScoredDay:
    """Everything one scoring pass produced, before anything is published."""

    day: UtcDay
    baselines: BaselineBatch
    detections: DetectionBatch
    ranking: RankingBatch
    census: PopulationCensus
    """Who was in scope and who was not. Reported by every run, never silently dropped."""


def score_day(
    connection: duckdb.DuckDBPyConnection,
    day: UtcDay,
    staged: StagedDay,
    dns: tuple[DnsDailyObservation, ...] = (),
    *,
    policies: ScoringPolicies | None = None,
    recorder: ConditionRecorder | None = None,
) -> ScoredDay:
    """Score one staged day against whatever history the connection holds for `day < D`."""

    active = policies or ScoringPolicies()
    baselines = BaselineEngine(connection, active.baseline).build(
        day,
        staged.client_rows,
        staged.service_rows,
        active.source_quality,
        active.detector.support,
    )
    persistence = PersistenceHistoryRepository(connection, active.detector).load(
        day, staged.service_rows
    )
    detections = DetectorEngine(active.detector).detect(
        day,
        staged.client_rows,
        staged.service_rows,
        baselines,
        dns_observations=dns,
        persistence_history=persistence,
        recorder=recorder,
    )
    ranking = RankingEngine(active.ranking).rank(
        day,
        detections,
        build_ranking_inputs(day, detections.signals, staged.service_rows),
        recorder=recorder,
    )
    return ScoredDay(
        day,
        baselines,
        detections,
        ranking,
        take_census(day.value.isoformat(), staged.client_rows, active.detector.support),
    )


def build_ranking_inputs(
    day: UtcDay,
    signals: tuple[DetectorSignal, ...],
    services: tuple[ClientServiceDayRow, ...],
    *,
    use_bitmap_timing: bool = True,
) -> tuple[EpisodeSignal, ...]:
    """Build transient episode windows without publishing or retaining five-minute detail."""

    if not use_bitmap_timing:
        return tuple(day_level_signal(day, signal) for signal in signals)
    bitmaps: dict[tuple[str, str, int], ActivityBitmap] = {}
    for row in services:
        key = (row.client_ip, row.service_id.hex(), row.asn_id)
        bitmap = ActivityBitmap(row.active_5m_bitmap)
        bitmaps[key] = bitmaps.get(key, ActivityBitmap()) | bitmap
    result: list[EpisodeSignal] = []
    for signal in signals:
        if signal.service_id_hex is None:
            result.append(day_level_signal(day, signal))
            continue
        if signal.family is DetectorFamily.PERSISTENCE:
            result.append(day_level_signal(day, signal))
            continue
        relationship_bitmap = bitmaps.get(
            (signal.client_ip, signal.service_id_hex, signal.asn_id or 0)
        )
        if relationship_bitmap is None:
            result.append(day_level_signal(day, signal))
        else:
            result.extend(bitmap_signal_windows(day, signal, relationship_bitmap))
    return tuple(result)
