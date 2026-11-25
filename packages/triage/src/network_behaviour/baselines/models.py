"""Typed, versioned baseline outputs."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from math import isfinite

BASELINE_VERSION = "baseline-calibration-v7"

# Baseline generations a published day may carry and still stream back unchanged. Baselines are
# behaviour — they set every denominator a strength is measured against — so they belong in an
# allow-list, not in the strict-equality group of the compatibility check: strict equality would
# make all thirty-seven published days unreadable the moment this constant moved, and the
# forward-only rerun policy requires the opposite. `None` is a day published before migration
# 0009 added the column, and is accepted for the same reason.
#
# v2 -> v3: the prevalence denominator was counted from `history.client_day` while every
# numerator was counted from `history.client_service_day`, so it included addresses that could
# never appear in a numerator. Days published under v2 keep the numbers they were published
# with; forward-only, and they cannot be re-derived in any case.
#
# v3 -> v4: relationship novelty and rarity became empirical tail probabilities over the day's
# own relationship population, and the pair is combined into one calibrated strength. Under v3
# novelty was a four-rung lookup ladder returning 100.0, 99.0, 98.0 or 97.5, which sat on the
# same 0-100 scale as a prevalence and won a `min` against it on 18.2% of eligible units. A day
# published under v3 keeps the ladder values it was published with.
#
# v4 -> v5: large-flow corroboration became a calibrated quantity. Each host's own prior large
# flows are the reference pool, and a day's large flow carries the tail probability of its size
# and duration against that pool. Under v4 the only figure attached to a large flow was its
# count, and presence alone promoted an episode a full tier — measured passing 26.01% of eligible
# relationship units and 80% of active addresses, which is not a discriminator. A day published
# under v4 keeps the unqualified corroboration it was published with.
# v5 -> v6: the peer band drops `active_minutes` and gains a reachability floor. Measured over
# the 7-day median every band is built from (2026-08-03..09, matching `recent_active_days`),
# 98.98% of addresses sit at 1,440 active minutes — the daily maximum — so the dimension split
# nothing and only fragmented cohorts that the byte and destination axes already separated
# (`CASE_STUDY` §3, §4). Dropping it took occupied bands from 23 of 125 to 18 of 25 and halved
# the addresses sitting below any usable cohort size. `min_cohort` (40, the same value and the
# same "two units of resolution above the exact threshold" reasoning as
# `large_flow_reference_min_units`) then refuses a peer percentile a cohort below it cannot
# support, rather than silently emitting one an address could never clear regardless of
# behaviour.
# v6 -> v7: peer and self-calibration pools hold only client-days the support definition admits —
# under `behavioural-support-v3`, addresses with at least one service row. Under v6 the pools of the
# lowest destination band were made of addresses carrying nothing but unaddressed rows (6,801 of
# 6,967 members on 2026-10-14, `CASE_STUDY` §3), so a quiet addressed host was ranked against
# traffic whose meaning is not established, and against a population the drift gate does not watch.
COMPATIBLE_BASELINE_VERSIONS = frozenset(
    {
        BASELINE_VERSION,
        "baseline-calibration-v6",
        "baseline-calibration-v5",
        "baseline-calibration-v4",
        "baseline-calibration-v3",
        "baseline-calibration-v2",
    }
)

# Positive retained measures needed by the retained-history detector families. Ratios and
# shares remain derived at scoring time and are deliberately absent.
CLIENT_METRICS = (
    "up_bytes",
    "down_bytes",
    "up_packets",
    "down_packets",
    "flow_count",
    "active_minutes",
    "active_5m_buckets",
    "unique_servers",
    "unique_services",
    "unique_routes",
    "unique_asns",
    "unique_port_groups",
    "top_service_up_bytes",
    "top_service_total_bytes",
    "opaque_bytes",
    "p95_5m_up_bytes",
    "max_5m_up_bytes",
    "p95_5m_unique_servers",
    "max_5m_unique_servers",
    "p95_5m_unique_services",
    "max_5m_unique_services",
    "p95_5m_unique_port_groups",
    "max_5m_unique_port_groups",
    "p95_bucket_up_rate_p95_bps",
    "max_bucket_up_rate_p95_bps",
    "large_flow_count",
    "large_flow_up_bytes",
    "max_large_flow_bytes",
    "max_large_flow_duration_sec",
)


class HistoryConfidence(StrEnum):
    COLD = "cold"
    LIMITED = "limited"
    NORMAL = "normal"
    MATURE = "mature"

    @classmethod
    def from_active_days(cls, active_days: int) -> HistoryConfidence:
        if active_days < 0:
            raise ValueError("active-day count cannot be negative")
        if active_days <= 7:
            return cls.COLD
        if active_days <= 14:
            return cls.LIMITED
        if active_days <= 30:
            return cls.NORMAL
        return cls.MATURE


class ResidualMethod(StrEnum):
    MAD = "mad"
    IQR = "iqr"
    RATIO_TO_MEDIAN = "ratio_to_median"


class ServiceConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class BaselinePolicy:
    recent_active_days: int = 7
    long_min_active_days: int = 30
    long_max_active_days: int = 90
    same_weekday_min_occurrences: int = 4
    calibration_min_prior_days: int = 8
    retained_lookback_days: int = 365
    calibration_lookback_days: int = 120
    population_lookback_days: int = 90
    # The reference pool a large flow is qualified against: this host's own large flows over this
    # window, at the service-day grain they are recorded on. `min_units` is a reachability floor,
    # not a taste — `empirical_percentile_sorted` is a midpoint rank, so the most extreme value in
    # a pool of n scores (n - 0.5)/n and a pool of fewer than 20 cannot place anything in a 2.5%
    # tail at all. 40 leaves the tail two units of resolution.
    large_flow_reference_days: int = 90
    large_flow_reference_min_units: int = 40
    # Fixed raw-value edges make bands stable across replays and population drift.
    total_byte_edges: tuple[float, ...] = (1_048_576, 10_485_760, 104_857_600, 1_073_741_824)
    destination_edges: tuple[float, ...] = (5, 20, 100, 500)
    # A midpoint-rank percentile over n peers tops out at (n - 0.5)/n: below this a cohort cannot
    # place any address in the `moderate_strength` (97.5) tail regardless of behaviour. Held equal
    # to `large_flow_reference_min_units` — same arithmetic, same margin — rather than the exact
    # boundary (20), which passes only the single most extreme peer with no room to spare.
    min_cohort: int = 40
    version: str = BASELINE_VERSION

    def __post_init__(self) -> None:
        if (
            not 0
            < self.recent_active_days
            <= self.long_min_active_days
            <= self.long_max_active_days
        ):
            raise ValueError("baseline active-day windows are inconsistent")
        if self.same_weekday_min_occurrences < 1 or self.calibration_min_prior_days < 1:
            raise ValueError("baseline eligibility counts must be positive")
        if self.calibration_lookback_days < self.long_max_active_days:
            raise ValueError("calibration lookback cannot be shorter than the long baseline")
        if self.retained_lookback_days < self.calibration_lookback_days:
            raise ValueError("retained lookback cannot be shorter than calibration lookback")
        if not 0 < self.large_flow_reference_days <= self.retained_lookback_days:
            raise ValueError("large-flow reference window must fit inside retained history")
        if self.large_flow_reference_min_units < 20:
            raise ValueError("a midpoint-rank tail below 2.5% needs at least 20 reference units")
        for edges in (self.total_byte_edges, self.destination_edges):
            if tuple(sorted(edges)) != edges or any(value < 0 for value in edges):
                raise ValueError("activity-band edges must be sorted and non-negative")
        if self.min_cohort < 20:
            raise ValueError("a midpoint-rank tail below 2.5% needs a cohort of at least 20")


@dataclass(frozen=True, slots=True)
class RobustSummary:
    count: int
    median_log1p: float
    mad_log1p: float
    q25_log1p: float
    q75_log1p: float
    median_raw: float
    method: ResidualMethod


@dataclass(frozen=True, slots=True)
class MetricCalibration:
    name: str
    current_value: float
    recent: RobustSummary | None
    long: RobustSummary | None
    same_weekday: RobustSummary | None
    current_residual: float | None
    self_percentile: float | None
    peer_percentile: float | None
    metric_strength: float | None


@dataclass(frozen=True, slots=True)
class SourceQualityInput:
    principal_activity_complete: bool = True
    reconciliation_passed: bool = True
    rate_context_available: bool = True
    dns_context_available: bool = True
    long_flow_context_available: bool = True
    classifier_context_degraded: bool = False


@dataclass(frozen=True, slots=True)
class SourceQualityContext:
    principal_activity_complete: bool
    reconciliation_passed: bool
    rate_context_available: bool
    dns_context_available: bool
    long_flow_context_available: bool
    classifier_context_degraded: bool
    opaque_byte_fraction: float


@dataclass(frozen=True, slots=True)
class ClientBaselineContext:
    client_ip: str
    prior_active_days: int
    history_confidence: HistoryConfidence
    activity_band: str
    same_weekday_eligible: bool
    metrics: tuple[MetricCalibration, ...]
    source_quality: SourceQualityContext
    # The day's largest flow, qualified against this host's own prior large flows. Same scale and
    # same pool as `RelationshipBaselineContext.large_flow_strength`; see `_large_flow_strengths`.
    large_flow_size_strength: float = 0.0
    large_flow_duration_strength: float = 0.0
    large_flow_strength: float = 0.0

    def __post_init__(self) -> None:
        validate_strengths(
            self.large_flow_size_strength,
            self.large_flow_duration_strength,
            self.large_flow_strength,
        )


@dataclass(frozen=True, slots=True)
class RelationshipBaselineContext:
    client_ip: str
    service_id_hex: str
    asn_id: int
    service_confidence: ServiceConfidence
    prior_service_active_days: int
    service_days_since_seen: int | None
    new_service: bool
    prior_route_active_days: int | None
    route_days_since_seen: int | None
    new_route: bool | None
    historical_service_prevalence: float
    historical_route_prevalence: float | None
    current_service_prevalence: float
    current_route_prevalence: float | None
    # Calibrated over the day's own relationship population by `BaselineEngine`, so all three are
    # tail probabilities on one scale: "more extreme than this share of today's relationships".
    # A threshold compared against them means the same thing here as it does for a client metric,
    # which was not true of the ladder these replace. See `_calibrate_relationships`.
    novelty_strength: float = 0.0
    rarity_strength: float = 0.0
    joint_strength: float = 0.0
    # How unusual this unit's largest flow is for this host, against the host's own prior large
    # flows rather than against a fixed byte count. Zero where the day carried no large flow on
    # this relationship, or where the host has too few prior large flows to place a tail.
    large_flow_size_strength: float = 0.0
    large_flow_duration_strength: float = 0.0
    large_flow_strength: float = 0.0

    def __post_init__(self) -> None:
        validate_strengths(
            self.novelty_strength,
            self.rarity_strength,
            self.joint_strength,
            self.large_flow_size_strength,
            self.large_flow_duration_strength,
            self.large_flow_strength,
        )


@dataclass(frozen=True, slots=True)
class BaselineBatch:
    day: str
    version: str
    clients: tuple[ClientBaselineContext, ...]
    relationships: tuple[RelationshipBaselineContext, ...]

    def to_bytes(self) -> bytes:
        """Return the canonical score-input envelope used by replay stability tests."""
        return json.dumps(
            asdict(self),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")


def validate_strengths(*strengths: float) -> None:
    for strength in strengths:
        if not isfinite(strength) or not 0 <= strength <= 100:
            raise ValueError("baseline strengths must be tail probabilities in [0, 100]")


def validate_measure(value: float) -> float:
    if not isfinite(value) or value < 0:
        raise ValueError("baseline measures must be finite and non-negative")
    return value
