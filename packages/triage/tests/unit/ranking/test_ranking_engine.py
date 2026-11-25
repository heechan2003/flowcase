from dataclasses import replace
from datetime import UTC, datetime, timedelta

from network_behaviour.baselines.models import HistoryConfidence, ServiceConfidence
from network_behaviour.detectors.models import (
    DETECTOR_VERSION,
    DetectionBatch,
    DetectorEvidence,
    DetectorFamily,
    DetectorSignal,
)
from network_behaviour.domain import EvidenceGroup, ReasonCode
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.ranking import (
    DataQualityConfidence,
    EpisodeSignal,
    EvidenceTier,
    RankingEngine,
    RankingPolicy,
    SignalStatus,
    TemporalPrecision,
    bitmap_signal_windows,
    day_level_signal,
)
from network_behaviour.time import UtcDay

DAY = UtcDay.parse("2026-07-10")
START = datetime(2026, 7, 10, tzinfo=UTC)


def _policy() -> RankingPolicy:
    return RankingPolicy()


def _signal(
    client_ip: str,
    family: DetectorFamily,
    strength: float,
    *,
    group: EvidenceGroup | None = None,
    service: str | None = None,
    asn_id: int | None = None,
    history: HistoryConfidence = HistoryConfidence.NORMAL,
    service_confidence: ServiceConfidence | None = None,
    evidence: tuple[DetectorEvidence, ...] | None = None,
) -> DetectorSignal:
    selected_group = (
        group
        or {
            DetectorFamily.TRANSFER: EvidenceGroup.TRANSFER_MAGNITUDE,
            DetectorFamily.RELATIONSHIP: EvidenceGroup.RELATIONSHIP_NOVELTY,
            DetectorFamily.FANOUT: EvidenceGroup.FANOUT,
            DetectorFamily.DNS: EvidenceGroup.DNS_CHANGE,
            DetectorFamily.PERSISTENCE: EvidenceGroup.RECURRENCE,
        }[family]
    )
    return DetectorSignal(
        client_ip,
        family,
        {
            DetectorFamily.TRANSFER: "unusual external transfer",
            DetectorFamily.RELATIONSHIP: "rare or new external relationship",
            DetectorFamily.FANOUT: "external fanout change",
            DetectorFamily.DNS: "DNS behaviour change",
            DetectorFamily.PERSISTENCE: "repeated rare external relationship",
        }[family],
        strength,
        history,
        evidence
        or (
            DetectorEvidence(
                selected_group,
                f"{family.value}_metric",
                100.0,
                metric_strength=strength,
            ),
        ),
        (
            {
                DetectorFamily.TRANSFER: ReasonCode.UNUSUAL_EXTERNAL_TRANSFER,
                DetectorFamily.RELATIONSHIP: ReasonCode.RARE_EXTERNAL_RELATIONSHIP,
                DetectorFamily.FANOUT: ReasonCode.EXTERNAL_FANOUT_CHANGE,
                DetectorFamily.DNS: ReasonCode.DNS_BEHAVIOUR_CHANGE,
                DetectorFamily.PERSISTENCE: ReasonCode.PERSISTENT_RARE_RELATIONSHIP,
            }[family],
        ),
        service,
        asn_id,
        service_confidence,
    )


def _input(
    signal: DetectorSignal,
    start_minute: int,
    end_minute: int,
    *,
    precision: TemporalPrecision = TemporalPrecision.FIVE_MINUTE,
    status: SignalStatus = SignalStatus.ELIGIBLE,
    quality: DataQualityConfidence = DataQualityConfidence.NORMAL,
) -> EpisodeSignal:
    return EpisodeSignal(
        signal,
        START + timedelta(minutes=start_minute),
        START + timedelta(minutes=end_minute),
        precision,
        status,
        quality,
    )


def _batch(*signals: DetectorSignal) -> DetectionBatch:
    return DetectionBatch(DAY.value.isoformat(), DETECTOR_VERSION, tuple(signals), ())


def test_fusion_requires_client_time_and_compatible_service_route_context() -> None:
    transfer = _signal("10.20.1.1", DetectorFamily.TRANSFER, 99.5)
    fanout = _signal("10.20.1.1", DetectorFamily.FANOUT, 99.0)
    relationship_a = _signal(
        "10.20.1.1",
        DetectorFamily.RELATIONSHIP,
        99.0,
        service="01" * 16,
        asn_id=64500,
    )
    relationship_b = replace(relationship_a, service_id_hex="02" * 16, asn_id=64501)
    signals = (transfer, fanout, relationship_a, relationship_b)

    result = RankingEngine(_policy()).rank(
        DAY,
        _batch(*signals),
        (
            _input(transfer, 0, 5),
            _input(fanout, 20, 25),  # exactly the default 15-minute gap
            _input(relationship_a, 0, 5),
            _input(relationship_b, 0, 5),
        ),
    )

    assert len(result.ranked_eligible) == 2
    fused = next(item for item in result.ranked_eligible if item.service_id_hex == "01" * 16)
    assert fused.evidence_tier is EvidenceTier.E1
    assert fused.independent_primary_family_count == 2
    assert fused.family is DetectorFamily.TRANSFER
    assert any(item.service_id_hex == "02" * 16 for item in result.ranked_eligible)


def test_day_precision_never_invents_temporal_corroboration_and_extended_gap_is_bounded() -> None:
    transfer = _signal(
        "10.20.1.1",
        DetectorFamily.TRANSFER,
        99.0,
        evidence=(
            DetectorEvidence(
                EvidenceGroup.TRANSFER_MAGNITUDE,
                "up_bytes",
                10_000.0,
                metric_strength=99.0,
            ),
            DetectorEvidence(
                EvidenceGroup.LARGE_FLOW_CONTEXT,
                "filtered_large_flow_count",
                1.0,
                support_count=1,
            ),
        ),
    )
    fanout = _signal("10.20.1.1", DetectorFamily.FANOUT, 99.0)
    batch = _batch(transfer, fanout)

    day_level = RankingEngine(_policy()).rank(
        DAY,
        batch,
        (
            _input(transfer, 0, 1440, precision=TemporalPrecision.DAY),
            _input(fanout, 0, 1440, precision=TemporalPrecision.DAY),
        ),
    )
    extended = RankingEngine(_policy()).rank(
        DAY,
        batch,
        (_input(transfer, 0, 5), _input(fanout, 35, 40)),
    )

    assert len(day_level.ranked_eligible) == 2
    assert len(extended.ranked_eligible) == 1
    assert extended.ranked_eligible[0].evidence_tier is EvidenceTier.E1


def test_correlated_evidence_and_repeated_family_do_not_create_independence() -> None:
    first = _signal(
        "10.20.1.1",
        DetectorFamily.DNS,
        99.0,
        evidence=(
            DetectorEvidence(
                EvidenceGroup.DNS_CHANGE,
                "query_volume",
                100.0,
                metric_strength=99.0,
            ),
            DetectorEvidence(
                EvidenceGroup.DNS_CHANGE,
                "session_volume",
                101.0,
                metric_strength=98.0,
            ),
        ),
    )
    repeated = replace(first, family_strength=99.5)

    result = RankingEngine(_policy()).rank(
        DAY,
        _batch(first, repeated),
        (_input(first, 0, 60, precision=TemporalPrecision.HOURLY), _input(repeated, 0, 60)),
    )

    assert len(result.ranked_eligible) == 1
    episode = result.ranked_eligible[0]
    assert episode.independent_primary_family_count == 1
    assert episode.evidence_tier is EvidenceTier.E2
    assert len(episode.evidence) == 1
    assert episode.evidence[0].metric_code == "query_volume"


def test_relationship_eligibility_rarity_is_not_independent_corroboration() -> None:
    relationship = _signal(
        "10.20.1.1",
        DetectorFamily.RELATIONSHIP,
        99.0,
        evidence=(
            DetectorEvidence(
                EvidenceGroup.RELATIONSHIP_NOVELTY,
                "client_relationship_novelty",
                0.0,
                metric_strength=99.0,
            ),
            DetectorEvidence(
                EvidenceGroup.POPULATION_RARITY,
                "service_prevalence",
                0.001,
                metric_strength=99.0,
            ),
        ),
    )

    result = RankingEngine(_policy()).rank(DAY, _batch(relationship), (_input(relationship, 0, 5),))

    episode = result.ranked_eligible[0]
    assert not episode.corroboration_present
    assert episode.evidence_tier is EvidenceTier.E2
    assert episode.independent_primary_family_count == 1


def test_persistence_eligibility_rarity_is_not_independent_corroboration() -> None:
    persistence = _signal(
        "10.20.1.1",
        DetectorFamily.PERSISTENCE,
        99.0,
        evidence=(
            DetectorEvidence(
                EvidenceGroup.RELATIONSHIP_RARITY,
                "relationship_population_prevalence",
                0.001,
                metric_strength=99.0,
            ),
            DetectorEvidence(
                EvidenceGroup.RECURRENCE,
                "comparable_time_run_gap_recurrence",
                1.0,
                metric_strength=100.0,
                support_count=4,
            ),
        ),
    )

    result = RankingEngine(_policy()).rank(
        DAY, _batch(persistence), (day_level_signal(DAY, persistence),)
    )

    episode = result.ranked_eligible[0]
    assert not episode.corroboration_present
    assert episode.evidence_tier is EvidenceTier.E2


def test_only_independent_context_groups_can_corroborate_a_strong_primary() -> None:
    for group in (EvidenceGroup.LARGE_FLOW_CONTEXT,):
        transfer = _signal(
            "10.20.1.1",
            DetectorFamily.TRANSFER,
            99.0,
            evidence=(
                DetectorEvidence(
                    EvidenceGroup.TRANSFER_MAGNITUDE,
                    "up_bytes",
                    10_000.0,
                    metric_strength=99.0,
                ),
                DetectorEvidence(group, f"{group.name.lower()}_metric", 1.0, metric_strength=99.0),
            ),
        )

        episode = (
            RankingEngine(_policy())
            .rank(DAY, _batch(transfer), (_input(transfer, 0, 5),))
            .ranked_eligible[0]
        )

        assert episode.corroboration_present
        assert episode.evidence_tier is EvidenceTier.E1


def test_large_flow_context_below_the_corroboration_strength_does_not_promote() -> None:
    """Presence alone stops promoting a tier in episode-ordering-v4.

    The flow is still on the episode — an analyst is entitled to know a large transfer
    happened — but a transfer that is ordinary for the host it belongs to no longer buys the
    top tier. On 2026-08-09 presence held for 26.01% of eligible relationship units.
    """
    policy = _policy()
    ordinary = _signal(
        "10.20.1.1",
        DetectorFamily.TRANSFER,
        99.0,
        evidence=(
            DetectorEvidence(
                EvidenceGroup.TRANSFER_MAGNITUDE, "up_bytes", 10_000.0, metric_strength=99.0
            ),
            DetectorEvidence(
                EvidenceGroup.LARGE_FLOW_CONTEXT,
                "filtered_large_flow_count",
                3.0,
                metric_strength=policy.corroboration_strength - 0.5,
                support_count=3,
            ),
        ),
    )

    episode = (
        RankingEngine(policy)
        .rank(DAY, _batch(ordinary), (_input(ordinary, 0, 5),))
        .ranked_eligible[0]
    )

    assert not episode.corroboration_present
    assert episode.evidence_tier is EvidenceTier.E2
    assert any(item.group is EvidenceGroup.LARGE_FLOW_CONTEXT for item in episode.evidence), (
        "unqualified large-flow context must stay on the episode"
    )


def test_two_moderate_independent_primary_families_are_p2() -> None:
    relationship = _signal("10.20.1.1", DetectorFamily.RELATIONSHIP, 98.0)
    persistence = _signal("10.20.1.1", DetectorFamily.PERSISTENCE, 97.5)

    result = RankingEngine(_policy()).rank(
        DAY,
        _batch(relationship, persistence),
        (_input(relationship, 0, 5), _input(persistence, 0, 5)),
    )

    assert result.ranked_eligible[0].evidence_tier is EvidenceTier.E2


def test_confidence_and_quality_caps_and_diagnostics_are_fail_closed() -> None:
    cold = _signal(
        "10.20.1.1",
        DetectorFamily.TRANSFER,
        100.0,
        history=HistoryConfidence.COLD,
    )
    low_service = _signal(
        "10.20.1.2",
        DetectorFamily.RELATIONSHIP,
        100.0,
        service="01" * 16,
        service_confidence=ServiceConfidence.LOW,
    )
    degraded = _signal("10.20.1.3", DetectorFamily.FANOUT, 100.0)

    result = RankingEngine(_policy()).rank(
        DAY,
        _batch(cold, low_service, degraded),
        (
            _input(cold, 0, 5),
            _input(low_service, 0, 5),
            _input(degraded, 0, 5, quality=DataQualityConfidence.DEGRADED),
        ),
    )

    assert [item.evidence_tier for item in result.ranked_eligible] == [
        EvidenceTier.E3,
        EvidenceTier.E3,
    ]
    assert [item.client_ip for item in result.diagnostics] == ["10.20.1.3"]
    assert all(item.client_ip != "10.20.1.3" for item in result.ranked_eligible)


def test_reordering_preserves_complete_ranked_population_and_episode_ids() -> None:
    signals = tuple(
        _signal(f"10.20.1.{index}", DetectorFamily.TRANSFER, 100.0 - index / 10)
        for index in range(1, 5)
    )
    inputs = tuple(_input(item, index * 10, index * 10 + 5) for index, item in enumerate(signals))
    batch = _batch(*signals)

    first = RankingEngine(_policy()).rank(DAY, batch, inputs)
    second = RankingEngine(_policy()).rank(DAY, batch, tuple(reversed(inputs)))

    assert first.to_bytes() == second.to_bytes()
    assert first.ranked_eligible == second.ranked_eligible
    assert first.client_view == second.client_view
    # Episode identity is scoped by behaviour version, so these changed when ordering moved from
    # episode-ranking-v2 to episode-ordering-v3, and again at primary-detectors-v3, -v4, -v5,
    # at the -v6/episode-ordering-v4 pair that qualified large-flow corroboration, at -v7,
    # which floored new-resolver novelty and demoted resolver service time to context, at -v8,
    # which restricted DNS to the clients that query and left DNS servers out, and at -v9, which
    # left addresses with no service row out of transfer and fanout. That is
    # the intended property: an episode built under different behaviour is a different episode,
    # and a published day keeps its own IDs. The client address is part of the identity, so these
    # changed again when the fixtures moved to 10.20.0.0/16.
    assert [item.episode_id.bytes for item in first.ranked_eligible] == [
        bytes.fromhex("6bbc02714680591db38025d185fce863"),
        bytes.fromhex("2fa90b1c94d050db88a1c540e223a89e"),
        bytes.fromhex("ccaab105e6645ae4bb68e8e27f6da3f9"),
        bytes.fromhex("a4c8353cc62a5659a59229b79f670772"),
    ]


def test_bitmap_windows_are_exact_and_day_level_adapter_stays_conservative() -> None:
    signal = _signal("10.20.1.1", DetectorFamily.RELATIONSHIP, 99.0)

    windows = bitmap_signal_windows(DAY, signal, ActivityBitmap.from_buckets((0, 1, 5, 287)))

    assert [(item.episode_start, item.episode_end) for item in windows] == [
        (START, START + timedelta(minutes=10)),
        (START + timedelta(minutes=25), START + timedelta(minutes=30)),
        (START + timedelta(minutes=1435), START + timedelta(days=1)),
    ]
    assert day_level_signal(DAY, signal).temporal_precision is TemporalPrecision.DAY
