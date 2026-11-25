"""Typed episode-fusion and canonical-ranking envelopes."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from math import isfinite
from uuid import UUID

from network_behaviour.baselines.models import HistoryConfidence
from network_behaviour.detectors.models import (
    CORROBORATION_STRENGTH,
    DetectorEvidence,
    DetectorFamily,
    DetectorSignal,
)

ORDERING_VERSION = "episode-ordering-v4"

# Historical pairs remain readable so published days stream back unchanged. Days built under a
# ranking-v1 or ranking-v2 pair are returned from storage verbatim and are never re-ordered, and
# the same applies to every day built under detectors-v2 before the support gate was removed in
# behavioural-support-v2. Read-back compatibility is not replay compatibility: a detectors-v2 day
# re-derived under v3 will differ, because v3 admits addresses v2 excluded. Reruns are forward-only.
COMPATIBLE_BEHAVIOUR_VERSION_PAIRS = frozenset(
    {
        ("primary-detectors-v2", "episode-ranking-v1"),
        ("primary-detectors-v2", "episode-ranking-v2"),
        ("primary-detectors-v2", "episode-ordering-v3"),
        ("primary-detectors-v3", "episode-ordering-v3"),
        ("primary-detectors-v4", "episode-ordering-v3"),
        ("primary-detectors-v5", "episode-ordering-v3"),
        ("primary-detectors-v6", "episode-ordering-v4"),
        ("primary-detectors-v7", "episode-ordering-v4"),
        ("primary-detectors-v8", "episode-ordering-v4"),
        ("primary-detectors-v9", ORDERING_VERSION),
    }
)


class EvidenceTier(StrEnum):
    """Coarse evidence bucket. Not a priority: E1 has historically held ~30% of the stream."""

    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    DIAGNOSTIC = "diagnostic"


class DataQualityConfidence(StrEnum):
    DEGRADED = "degraded"
    LIMITED = "limited"
    NORMAL = "normal"


class TemporalPrecision(StrEnum):
    FIVE_MINUTE = "five_minute"
    HOURLY = "hourly"
    DAY = "day"


class SignalStatus(StrEnum):
    ELIGIBLE = "eligible"
    BELOW_THRESHOLD = "below_threshold"
    DIAGNOSTIC = "diagnostic"


@dataclass(frozen=True, slots=True)
class RankingPolicy:
    """Versioned fusion and classification controls with no workload policy."""

    moderate_strength: float = 97.5
    strong_strength: float = 99.0
    # Large-flow context promotes an episode a full tier only above this. Presence alone did
    # until episode-ordering-v4, which is what R2 exists to correct: it passed 26.01% of eligible
    # relationship units on 2026-08-09 and 80% of active addresses, so the top tier was separated
    # by a condition that separated almost nothing (CASE_STUDY §8).
    corroboration_strength: float = CORROBORATION_STRENGTH
    default_gap_minutes: int = 15
    extended_gap_minutes: int = 30
    version: str = ORDERING_VERSION

    def __post_init__(self) -> None:
        if not 0 <= self.moderate_strength <= self.strong_strength <= 100:
            raise ValueError("ranking strength thresholds are inconsistent")
        if not 0 <= self.corroboration_strength <= 100:
            raise ValueError("corroboration strength must be a tail probability in [0, 100]")
        if not 0 < self.default_gap_minutes <= self.extended_gap_minutes:
            raise ValueError("episode gap controls are inconsistent")
        if not self.version.strip():
            raise ValueError("ordering version cannot be empty")


@dataclass(frozen=True, slots=True)
class EpisodeSignal:
    """A detector signal with the transient time precision needed for safe fusion."""

    signal: DetectorSignal
    episode_start: datetime
    episode_end: datetime
    temporal_precision: TemporalPrecision
    status: SignalStatus = SignalStatus.ELIGIBLE
    data_quality_confidence: DataQualityConfidence = DataQualityConfidence.NORMAL

    def __post_init__(self) -> None:
        for value in (self.episode_start, self.episode_end):
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError("episode timestamps must be timezone-aware UTC")
        if self.episode_end < self.episode_start:
            raise ValueError("episode end cannot precede its start")
        if not isfinite(self.signal.family_strength) or not 0 <= self.signal.family_strength <= 100:
            raise ValueError("signal family strength must be between zero and 100")


@dataclass(frozen=True, slots=True)
class RankedEpisode:
    episode_id: UUID
    day: str
    client_ip: str
    family: DetectorFamily
    label: str
    episode_start: datetime
    episode_end: datetime
    service_id_hex: str | None
    asn_id: int | None
    family_strength: float
    independent_primary_family_count: int
    corroboration_present: bool
    evidence_tier: EvidenceTier
    tie_group: int
    evidence: tuple[DetectorEvidence, ...]
    evidence_group_mask: int
    history_confidence: HistoryConfidence
    data_quality_confidence: DataQualityConfidence
    reason_code_mask: int
    detector_version: str
    status: SignalStatus


@dataclass(frozen=True, slots=True)
class ClientHostProjection:
    """Best episode per observed host. Not carried on the stream itself."""

    client_ip: str
    best_episode: RankedEpisode


@dataclass(frozen=True, slots=True)
class RankingBatch:
    """Canonical complete ranked population, independent of analyst capacity."""

    day: str
    detector_version: str
    ordering_version: str
    ranked_eligible: tuple[RankedEpisode, ...]
    diagnostics: tuple[RankedEpisode, ...]
    client_view: tuple[ClientHostProjection, ...]

    def to_bytes(self) -> bytes:
        """Return a byte-stable envelope for replay and operational-field isolation tests."""
        return json.dumps(
            asdict(self),
            allow_nan=False,
            default=str,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
