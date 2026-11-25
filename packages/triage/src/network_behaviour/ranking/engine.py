"""Deterministic episode fusion, tiering, and canonical ranking."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime
from uuid import UUID, uuid5

from network_behaviour.baselines.models import HistoryConfidence, ServiceConfidence
from network_behaviour.detectors.models import (
    FAMILY_ORDER,
    DetectionBatch,
    DetectorEvidence,
    DetectorFamily,
)
from network_behaviour.domain import EvidenceGroup, code_mask
from network_behaviour.instrumentation import Combinator, ConditionRecorder
from network_behaviour.ranking.models import (
    ClientHostProjection,
    DataQualityConfidence,
    EpisodeSignal,
    EvidenceTier,
    RankedEpisode,
    RankingBatch,
    RankingPolicy,
    SignalStatus,
    TemporalPrecision,
)
from network_behaviour.time import UtcDay

_CANDIDATE_NAMESPACE = UUID("637e3e2d-b266-5320-a614-53dc8d840ee8")
# Composition and synchronization context were listed here until domain-codes-v3 but were never
# emitted by any detector, so a matching filtered large flow has always been the only route from
# one strong primary family to P1. See docs/generated/detectors.md and docs/CASE_STUDY.md §8.
# Membership alone is no longer enough: since episode-ordering-v4 the evidence must also carry a
# `metric_strength` at or above `RankingPolicy.corroboration_strength`, which is how unusual the
# flow is for the host that made it. Unqualified large-flow context still reaches the stream and
# still widens the fusion gap; what it no longer does is promote a tier.
_INDEPENDENT_CORROBORATION_GROUPS = {
    EvidenceGroup.LARGE_FLOW_CONTEXT,
}
_HISTORY_ORDER = {
    HistoryConfidence.COLD: 0,
    HistoryConfidence.LIMITED: 1,
    HistoryConfidence.NORMAL: 2,
    HistoryConfidence.MATURE: 3,
}
_QUALITY_ORDER = {
    DataQualityConfidence.DEGRADED: 0,
    DataQualityConfidence.LIMITED: 1,
    DataQualityConfidence.NORMAL: 2,
}
_TIER_ORDER = {
    EvidenceTier.E1: 0,
    EvidenceTier.E2: 1,
    EvidenceTier.E3: 2,
    EvidenceTier.DIAGNOSTIC: 3,
}


@dataclass(slots=True)
class _EpisodeCluster:
    signals: list[EpisodeSignal]

    @property
    def start(self) -> datetime:
        return min(item.episode_start for item in self.signals)

    @property
    def end(self) -> datetime:
        return max(item.episode_end for item in self.signals)


@dataclass(frozen=True, slots=True)
class _RankingPopulations:
    ranking: RankingBatch
    below_threshold: tuple[RankedEpisode, ...]


class RankingEngine:
    """Fuse proven-overlapping signals into a canonical capacity-free ranking."""

    def __init__(self, policy: RankingPolicy) -> None:
        self._policy = policy

    def rank(
        self,
        day: UtcDay,
        detections: DetectionBatch,
        signals: tuple[EpisodeSignal, ...],
        *,
        recorder: ConditionRecorder | None = None,
    ) -> RankingBatch:
        return self._rank_populations(day, detections, signals, recorder).ranking

    def _rank_populations(
        self,
        day: UtcDay,
        detections: DetectionBatch,
        signals: tuple[EpisodeSignal, ...],
        recorder: ConditionRecorder | None = None,
    ) -> _RankingPopulations:
        if detections.day != day.value.isoformat():
            raise ValueError("detection batch must belong to day D")
        eligible_signals = set(detections.signals)
        below_threshold_signals = {
            item.near_threshold_signal
            for item in detections.diagnostics
            if item.near_threshold_signal is not None
        }
        supplied_below = {
            item.signal for item in signals if item.status is SignalStatus.BELOW_THRESHOLD
        }
        expanded_signals = (
            *signals,
            *(
                EpisodeSignal(
                    signal,
                    day.bounds.start,
                    day.bounds.end,
                    TemporalPrecision.DAY,
                    SignalStatus.BELOW_THRESHOLD,
                )
                for signal in sorted(
                    below_threshold_signals - supplied_below,
                    key=lambda value: (
                        value.client_ip,
                        FAMILY_ORDER[value.family],
                        value.service_id_hex or "",
                        value.asn_id if value.asn_id is not None else -1,
                    ),
                )
            ),
        )
        for item in expanded_signals:
            if not day.bounds.start <= item.episode_start <= day.bounds.end:
                raise ValueError("episode start is outside day D")
            if not day.bounds.start <= item.episode_end <= day.bounds.end:
                raise ValueError("episode end is outside day D")
            if item.status is SignalStatus.ELIGIBLE and item.signal not in eligible_signals:
                raise ValueError("eligible ranking input is absent from the detection batch")
            if (
                item.status is SignalStatus.BELOW_THRESHOLD
                and item.signal not in below_threshold_signals
            ):
                raise ValueError("below-threshold input is absent from detector diagnostics")

        fused = tuple(
            self._fuse(day, detections.version, cluster, recorder)
            for cluster in self._clusters(_deduplicate(expanded_signals))
        )
        eligible = tuple(
            item
            for item in fused
            if item.status is SignalStatus.ELIGIBLE
            and item.evidence_tier is not EvidenceTier.DIAGNOSTIC
        )
        below = tuple(item for item in fused if item.status is SignalStatus.BELOW_THRESHOLD)
        diagnostic = tuple(
            item
            for item in fused
            if item.status is SignalStatus.DIAGNOSTIC
            or (
                item.status is SignalStatus.ELIGIBLE
                and item.evidence_tier is EvidenceTier.DIAGNOSTIC
            )
        )

        ranked_eligible = _assign_tie_groups(tuple(sorted(eligible, key=_rank_key)))
        ranked_below = _assign_tie_groups(tuple(sorted(below, key=_rank_key)))
        diagnostics = tuple(sorted(diagnostic, key=_rank_key))
        client_view = _client_view(ranked_eligible)
        return _RankingPopulations(
            RankingBatch(
                day.value.isoformat(),
                detections.version,
                self._policy.version,
                ranked_eligible,
                diagnostics,
                client_view,
            ),
            ranked_below,
        )

    def _clusters(self, signals: tuple[EpisodeSignal, ...]) -> tuple[_EpisodeCluster, ...]:
        clusters: list[_EpisodeCluster] = []
        clusters_by_client_status: dict[tuple[str, SignalStatus], list[_EpisodeCluster]] = (
            defaultdict(list)
        )
        for item in sorted(signals, key=_signal_sort_key):
            key = (item.signal.client_ip, item.status)
            # Day-level timing is explicitly non-fusible. Keep it out of the
            # per-client merge search so large diagnostic populations remain linear.
            if item.temporal_precision is TemporalPrecision.DAY:
                clusters.append(_EpisodeCluster([item]))
                continue
            compatible = [
                cluster
                for cluster in clusters_by_client_status[key]
                if self._can_merge(cluster, item)
            ]
            if not compatible:
                cluster = _EpisodeCluster([item])
                clusters.append(cluster)
                clusters_by_client_status[key].append(cluster)
                continue
            target = min(
                compatible,
                key=lambda cluster: (
                    _interval_gap_seconds(cluster.start, cluster.end, item),
                    cluster.start,
                    _signal_sort_key(cluster.signals[0]),
                ),
            )
            target.signals.append(item)
        return tuple(clusters)

    def _can_merge(self, cluster: _EpisodeCluster, item: EpisodeSignal) -> bool:
        if item.temporal_precision is TemporalPrecision.DAY or any(
            existing.temporal_precision is TemporalPrecision.DAY for existing in cluster.signals
        ):
            return False
        if any(not _compatible_context(existing, item) for existing in cluster.signals):
            return False
        gap_seconds = _interval_gap_seconds(cluster.start, cluster.end, item)
        extended = _uses_extended_gap((*cluster.signals, item))
        limit = self._policy.extended_gap_minutes if extended else self._policy.default_gap_minutes
        return gap_seconds <= limit * 60

    def _fuse(
        self,
        day: UtcDay,
        detector_version: str,
        cluster: _EpisodeCluster,
        recorder: ConditionRecorder | None = None,
    ) -> RankedEpisode:
        signals = tuple(sorted(cluster.signals, key=_signal_sort_key))
        by_family: dict[DetectorFamily, EpisodeSignal] = {}
        for item in signals:
            existing = by_family.get(item.signal.family)
            if existing is None or _family_signal_key(item) < _family_signal_key(existing):
                by_family[item.signal.family] = item
        families = tuple(by_family.values())
        dominant = min(families, key=_family_signal_key)
        family_strength = max(item.signal.family_strength for item in families)
        history = min(
            (item.signal.history_confidence for item in families), key=_HISTORY_ORDER.__getitem__
        )
        quality = min(
            (item.data_quality_confidence for item in signals), key=_QUALITY_ORDER.__getitem__
        )
        corroboration = any(
            evidence.group in _INDEPENDENT_CORROBORATION_GROUPS
            and (evidence.metric_strength or 0.0) >= self._policy.corroboration_strength
            for item in signals
            for evidence in item.signal.evidence
        )
        evidence = _collapse_evidence(signals)
        status = signals[0].status
        tier = self._tier(families, history, quality, corroboration, status, recorder)
        service_ids = {item.signal.service_id_hex for item in signals if item.signal.service_id_hex}
        asn_ids = {item.signal.asn_id for item in signals if item.signal.asn_id is not None}
        service_id = next(iter(service_ids)) if len(service_ids) == 1 else None
        asn_id = next(iter(asn_ids)) if len(asn_ids) == 1 else None
        episode_id = _episode_id(
            day,
            detector_version,
            self._policy.version,
            signals,
            cluster.start,
            cluster.end,
            service_id,
            asn_id,
        )
        behaviour_version = f"{detector_version}/{self._policy.version}"
        reason_codes = {reason for item in signals for reason in item.signal.reason_codes}
        return RankedEpisode(
            episode_id,
            day.value.isoformat(),
            dominant.signal.client_ip,
            dominant.signal.family,
            dominant.signal.label,
            cluster.start,
            cluster.end,
            service_id,
            asn_id,
            family_strength,
            min(2, len(families)),
            corroboration,
            tier,
            0,  # tie_group assigned once the whole population is ordered
            evidence,
            code_mask(*(item.group for item in evidence)),
            history,
            quality,
            code_mask(*reason_codes),
            behaviour_version,
            status,
        )

    def _tier(
        self,
        families: tuple[EpisodeSignal, ...],
        history: HistoryConfidence,
        quality: DataQualityConfidence,
        corroboration: bool,
        status: SignalStatus,
        recorder: ConditionRecorder | None = None,
    ) -> EvidenceTier:
        if status is SignalStatus.DIAGNOSTIC or quality is DataQualityConfidence.DEGRADED:
            _exclude(recorder, "diagnostic_or_degraded")
            return EvidenceTier.DIAGNOSTIC
        strengths = [item.signal.family_strength for item in families]
        strong_count = sum(value >= self._policy.strong_strength for value in strengths)
        moderate_count = sum(value >= self._policy.moderate_strength for value in strengths)
        if not moderate_count:
            _exclude(recorder, "below_moderate_strength")
            return EvidenceTier.DIAGNOSTIC
        low_service = any(
            item.signal.service_confidence is ServiceConfidence.LOW for item in families
        )
        confidence_cap = (
            history in {HistoryConfidence.COLD, HistoryConfidence.LIMITED}
            or quality is DataQualityConfidence.LIMITED
            or low_service
        )
        if recorder is not None:
            recorder.record(
                "tier_confidence_cap",
                Combinator.ANY,
                history_cold_or_limited=history
                in {HistoryConfidence.COLD, HistoryConfidence.LIMITED},
                quality_limited=quality is DataQualityConfidence.LIMITED,
                low_service_confidence=low_service,
            )
            recorder.record(
                "tier_e1",
                Combinator.ANY,
                two_strong_families=strong_count >= 2,
                strong_with_corroboration=strong_count >= 1 and corroboration,
            )
            recorder.record(
                "tier_e2",
                Combinator.ANY,
                one_strong_family=strong_count >= 1,
                two_moderate_families=moderate_count >= 2,
            )
        if confidence_cap:
            return EvidenceTier.E3
        if strong_count >= 2 or (strong_count >= 1 and corroboration):
            return EvidenceTier.E1
        if strong_count >= 1 or moderate_count >= 2:
            return EvidenceTier.E2
        return EvidenceTier.E3


_TIER_RULES = ("tier_confidence_cap", "tier_e1", "tier_e2")


def _exclude(recorder: ConditionRecorder | None, reason: str) -> None:
    """An episode that never reaches the tier ladder belongs in none of its marginals."""
    if recorder is None:
        return
    for rule in _TIER_RULES:
        recorder.exclude(rule, reason)


def _deduplicate(signals: tuple[EpisodeSignal, ...]) -> tuple[EpisodeSignal, ...]:
    return tuple(dict.fromkeys(signals))


def _signal_sort_key(item: EpisodeSignal) -> tuple[object, ...]:
    signal = item.signal
    return (
        signal.client_ip,
        item.status.value,
        item.episode_start,
        item.episode_end,
        FAMILY_ORDER[signal.family],
        signal.service_id_hex or "",
        signal.asn_id if signal.asn_id is not None else -1,
        item.temporal_precision.value,
        signal.label,
    )


def _family_signal_key(item: EpisodeSignal) -> tuple[object, ...]:
    return (-item.signal.family_strength, FAMILY_ORDER[item.signal.family], _signal_sort_key(item))


def _compatible_context(left: EpisodeSignal, right: EpisodeSignal) -> bool:
    left_signal = left.signal
    right_signal = right.signal
    if (
        left_signal.service_id_hex
        and right_signal.service_id_hex
        and left_signal.service_id_hex != right_signal.service_id_hex
    ):
        return False
    return not (
        left_signal.asn_id is not None
        and right_signal.asn_id is not None
        and left_signal.asn_id != right_signal.asn_id
    )


def _interval_gap_seconds(start: datetime, end: datetime, item: EpisodeSignal) -> float:
    if item.episode_start > end:
        return (item.episode_start - end).total_seconds()
    if start > item.episode_end:
        return (start - item.episode_end).total_seconds()
    return 0.0


def _uses_extended_gap(signals: tuple[EpisodeSignal, ...]) -> bool:
    return any(
        (
            item.signal.family is DetectorFamily.DNS
            and item.temporal_precision is TemporalPrecision.HOURLY
        )
        or any(
            evidence.group is EvidenceGroup.LARGE_FLOW_CONTEXT for evidence in item.signal.evidence
        )
        for item in signals
    )


def _collapse_evidence(signals: tuple[EpisodeSignal, ...]) -> tuple[DetectorEvidence, ...]:
    grouped: dict[EvidenceGroup, list[DetectorEvidence]] = defaultdict(list)
    for item in signals:
        for evidence in item.signal.evidence:
            grouped[evidence.group].append(evidence)
    selected = []
    for group in sorted(grouped, key=int):
        values = sorted(
            grouped[group],
            key=lambda item: (
                -(item.metric_strength if item.metric_strength is not None else -1.0),
                -(item.support_count if item.support_count is not None else -1),
                item.metric_code,
                item.observed_value,
            ),
        )
        selected.append(values[0])
    return tuple(selected)


def _episode_id(
    day: UtcDay,
    detector_version: str,
    ranking_version: str,
    signals: tuple[EpisodeSignal, ...],
    start: datetime,
    end: datetime,
    service_id: str | None,
    asn_id: int | None,
) -> UUID:
    families = ",".join(sorted({item.signal.family.value for item in signals}))
    value = "|".join(
        (
            ranking_version,
            detector_version,
            day.value.isoformat(),
            signals[0].signal.client_ip,
            families,
            start.isoformat(),
            end.isoformat(),
            service_id or "",
            str(asn_id) if asn_id is not None else "",
        )
    )
    return uuid5(_CANDIDATE_NAMESPACE, value)


def _rank_key(item: RankedEpisode) -> tuple[object, ...]:
    return (
        _TIER_ORDER[item.evidence_tier],
        -item.family_strength,
        -item.independent_primary_family_count,
        -int(item.corroboration_present),
        -_HISTORY_ORDER[item.history_confidence],
        -_QUALITY_ORDER[item.data_quality_confidence],
        str(item.episode_id),
    )


def _assign_tie_groups(items: tuple[RankedEpisode, ...]) -> tuple[RankedEpisode, ...]:
    """Dense-rank the ordering key so indistinguishable episodes are visibly indistinguishable.

    v1 spread equivalent episodes across contiguous ranks and interpolated a score over that
    position, which asserted a discrimination the evidence does not support: roughly 90% of
    adjacent within-tier pairs tie on every substantive key and are separated only by a digest.
    Episodes sharing a tie group are equivalent on the evidence, and the consumer is told so.
    """
    result: list[RankedEpisode] = []
    group = 0
    previous: tuple[object, ...] | None = None
    for item in items:
        key = _tie_key(item)
        if key != previous:
            group += 1
            previous = key
        result.append(replace(item, tie_group=group))
    return tuple(result)


def _tie_key(item: RankedEpisode) -> tuple[object, ...]:
    """The substantive ordering key: _rank_key without the stable-ID tie-break."""
    return _rank_key(item)[:-1]


def _client_view(items: tuple[RankedEpisode, ...]) -> tuple[ClientHostProjection, ...]:
    seen: set[str] = set()
    result: list[ClientHostProjection] = []
    for item in items:
        if item.client_ip in seen:
            continue
        seen.add(item.client_ip)
        result.append(ClientHostProjection(item.client_ip, item))
    return tuple(result)
