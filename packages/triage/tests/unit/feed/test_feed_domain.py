import json
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

import pytest

from network_behaviour.baselines.models import HistoryConfidence
from network_behaviour.detectors.models import (
    DETECTOR_VERSION,
    DecisionStatus,
    DetectionBatch,
    DetectorDiagnostic,
    DetectorEvidence,
    DetectorFamily,
    DetectorSignal,
)
from network_behaviour.domain import EvidenceGroup, ReasonCode
from network_behaviour.feed import (
    STREAM_ENCODING_VERSION,
    STREAM_SCHEMA_VERSION,
    DailyEvidenceStream,
    StreamBuildMetadata,
    StreamEpisode,
    StreamEvidence,
    StreamValidationError,
    build_daily_evidence_stream,
    iter_daily_evidence_stream_jsonl,
)
from network_behaviour.ranking import (
    ORDERING_VERSION,
    DataQualityConfidence,
    EpisodeSignal,
    EvidenceTier,
    RankingBatch,
    RankingEngine,
    RankingPolicy,
    SignalStatus,
    TemporalPrecision,
)
from network_behaviour.time import UtcDay

DAY = UtcDay.parse("2026-07-10")
START = DAY.bounds.start
PUBLISHED = datetime(2026, 7, 11, 8, tzinfo=UTC)
RUN_ID = UUID("174d6ab7-69f7-4dba-a2ac-bb5f2f830f0c")

_LABELS = {
    DetectorFamily.TRANSFER: "unusual external transfer",
    DetectorFamily.RELATIONSHIP: "rare or new external relationship",
    DetectorFamily.FANOUT: "external fanout change",
    DetectorFamily.DNS: "DNS behaviour change",
    DetectorFamily.PERSISTENCE: "repeated rare external relationship",
}
_REASONS = {
    DetectorFamily.TRANSFER: ReasonCode.UNUSUAL_EXTERNAL_TRANSFER,
    DetectorFamily.RELATIONSHIP: ReasonCode.RARE_EXTERNAL_RELATIONSHIP,
    DetectorFamily.FANOUT: ReasonCode.EXTERNAL_FANOUT_CHANGE,
    DetectorFamily.DNS: ReasonCode.DNS_BEHAVIOUR_CHANGE,
    DetectorFamily.PERSISTENCE: ReasonCode.PERSISTENT_RARE_RELATIONSHIP,
}


def _signal(
    client_ip: str,
    family: DetectorFamily,
    strength: float,
    evidence: tuple[DetectorEvidence, ...],
    *,
    service_id: str | None = None,
    asn_id: int | None = None,
) -> DetectorSignal:
    return DetectorSignal(
        client_ip,
        family,
        _LABELS[family],
        strength,
        HistoryConfidence.NORMAL,
        evidence,
        (_REASONS[family],),
        service_id,
        asn_id,
    )


def _ranking(*, reverse: bool = False) -> RankingBatch:
    transfer = _signal(
        "10.20.1.1",
        DetectorFamily.TRANSFER,
        99.8,
        (
            DetectorEvidence(
                EvidenceGroup.TRANSFER_MAGNITUDE,
                "up_bytes",
                5_000_000.0,
                client_baseline_value=100_000.0,
                peer_reference_value=120_000.0,
                self_strength=99.9,
                peer_strength=99.8,
                metric_strength=99.8,
            ),
            DetectorEvidence(
                EvidenceGroup.LARGE_FLOW_CONTEXT,
                "filtered_large_flow_count",
                2.0,
                # Above RankingPolicy.corroboration_strength, so this episode still reaches E1
                # under episode-ordering-v4. Presence alone no longer would.
                metric_strength=99.4,
                support_count=2,
            ),
        ),
        service_id="01" * 16,
        asn_id=64500,
    )
    dns = _signal(
        "10.20.1.2",
        DetectorFamily.DNS,
        99.2,
        (
            DetectorEvidence(
                EvidenceGroup.DNS_VOLUME,
                "query_volume",
                10_000.0,
                client_baseline_value=1_000.0,
                peer_reference_value=2_000.0,
                self_strength=99.5,
                peer_strength=99.2,
                metric_strength=99.2,
                support_count=200,
            ),
        ),
    )
    fanout = _signal(
        "10.20.1.3",
        DetectorFamily.FANOUT,
        98.0,
        (
            DetectorEvidence(
                EvidenceGroup.FANOUT,
                "max_5m_unique_servers",
                80.0,
                client_baseline_value=10.0,
                peer_reference_value=20.0,
                self_strength=98.4,
                peer_strength=98.0,
                metric_strength=98.0,
                support_count=150,
            ),
        ),
    )
    degraded = _signal(
        "10.20.1.4",
        DetectorFamily.RELATIONSHIP,
        100.0,
        (
            DetectorEvidence(
                EvidenceGroup.RELATIONSHIP_NOVELTY,
                "client_relationship_novelty",
                0.0,
                metric_strength=100.0,
                support_count=10,
            ),
        ),
    )
    near_threshold = _signal(
        "10.20.1.5",
        DetectorFamily.TRANSFER,
        96.0,
        (
            DetectorEvidence(
                EvidenceGroup.TRANSFER_MAGNITUDE,
                "up_bytes",
                200_000.0,
                metric_strength=96.0,
            ),
        ),
    )
    signals: tuple[DetectorSignal, ...] = (transfer, dns, fanout, degraded)
    inputs: tuple[EpisodeSignal, ...] = (
        EpisodeSignal(
            transfer,
            START,
            START + timedelta(minutes=5),
            TemporalPrecision.FIVE_MINUTE,
        ),
        EpisodeSignal(
            dns,
            START + timedelta(hours=1),
            START + timedelta(hours=2),
            TemporalPrecision.HOURLY,
        ),
        EpisodeSignal(
            fanout,
            START + timedelta(hours=3),
            START + timedelta(hours=3, minutes=5),
            TemporalPrecision.FIVE_MINUTE,
        ),
        EpisodeSignal(
            degraded,
            START + timedelta(hours=4),
            START + timedelta(hours=4, minutes=5),
            TemporalPrecision.FIVE_MINUTE,
            data_quality_confidence=DataQualityConfidence.DEGRADED,
        ),
    )
    diagnostics = (
        DetectorDiagnostic(
            near_threshold.client_ip,
            near_threshold.family,
            DecisionStatus.INELIGIBLE,
            (ReasonCode.INSUFFICIENT_SUPPORT,),
            near_threshold_signal=near_threshold,
        ),
    )
    if reverse:
        signals = tuple(reversed(signals))
        inputs = tuple(reversed(inputs))
    detections = DetectionBatch(str(DAY), DETECTOR_VERSION, signals, diagnostics)
    return RankingEngine(RankingPolicy()).rank(DAY, detections, inputs)


def _stream_evidence(item: DetectorEvidence) -> StreamEvidence:
    return StreamEvidence(
        item.group,
        item.metric_code,
        item.observed_value,
        item.client_baseline_value,
        item.peer_reference_value,
        item.self_strength,
        item.peer_strength,
        item.metric_strength,
        item.support_count,
    )


def _metadata(*, expiry: datetime | None = None) -> StreamBuildMetadata:
    return StreamBuildMetadata(
        RUN_ID,
        PUBLISHED,
        PUBLISHED,
        PUBLISHED + timedelta(days=14) if expiry is None else expiry,
    )


def test_feed_is_complete_deterministic_and_independent_of_pre_ranking_row_order() -> None:
    first_ranking = _ranking()
    reordered_ranking = _ranking(reverse=True)
    metadata = _metadata()

    first = build_daily_evidence_stream(first_ranking, metadata)
    repeated = build_daily_evidence_stream(first_ranking, metadata)
    reordered = build_daily_evidence_stream(reordered_ranking, metadata)
    payload = json.loads(first.to_bytes())

    assert first.to_bytes() == repeated.to_bytes() == reordered.to_bytes()
    # The stream carries client addresses, so this changed when the fixtures moved to 10.20.0.0/16.
    assert sha256(first.to_bytes()).hexdigest() == (
        "c9d31b8b5768a7e25012983a495e37d7bd053325fa12d2ced0cdb7d84793da0d"
    )
    assert first.header.stream_schema_version == STREAM_SCHEMA_VERSION
    assert first.header.episode_count == len(first_ranking.ranked_eligible) == 3
    assert len(first_ranking.diagnostics) == 1
    assert [item.sequence for item in first.episodes] == [1, 2, 3]
    assert [item.evidence_tier for item in first.episodes] == [
        EvidenceTier.E1,
        EvidenceTier.E2,
        EvidenceTier.E3,
    ]
    assert [item.episode_id for item in first.episodes] == [
        item.episode_id for item in first_ranking.ranked_eligible
    ]
    assert payload["episode_count"] == len(payload["episodes"])
    assert all(item["evidence_tier"] != EvidenceTier.DIAGNOSTIC for item in payload["episodes"])
    assert {item["client_ip"] for item in payload["episodes"]}.isdisjoint(
        {"10.20.1.4", "10.20.1.5"}
    )


def test_feed_jsonl_stream_has_one_header_and_rank_ordered_candidates() -> None:
    feed = build_daily_evidence_stream(_ranking(), _metadata())
    payload = b"".join(iter_daily_evidence_stream_jsonl(feed))
    repeated = b"".join(iter_daily_evidence_stream_jsonl(feed))
    records = [json.loads(line) for line in payload.splitlines()]

    assert payload == repeated
    assert len(records) == feed.header.episode_count + 1
    assert records[0] == {
        "day": "2026-07-10",
        "detector_version": DETECTOR_VERSION,
        "episode_count": 3,
        "ordering_version": ORDERING_VERSION,
        "published_at": PUBLISHED.isoformat(),
        "record_type": "header",
        "run_id": str(RUN_ID),
        "stream_encoding_version": STREAM_ENCODING_VERSION,
        "stream_schema_version": STREAM_SCHEMA_VERSION,
    }
    assert [record["record_type"] for record in records] == [
        "header",
        "episode",
        "episode",
        "episode",
    ]
    assert [record["episode"]["sequence"] for record in records[1:]] == [1, 2, 3]
    # Tie groups are dense and non-decreasing; equal values mean equal evidence.
    groups = [record["episode"]["tie_group"] for record in records[1:]]
    assert groups == sorted(groups)
    assert set(groups) == set(range(1, max(groups) + 1))
    assert all("review" not in record for record in records)


def test_feed_preserves_exact_evidence_and_nullable_contract_fields() -> None:
    ranking = _ranking()
    feed = build_daily_evidence_stream(
        ranking,
        StreamBuildMetadata(RUN_ID, PUBLISHED, PUBLISHED, None),
    )

    for candidate, episode in zip(feed.episodes, ranking.ranked_eligible, strict=True):
        assert candidate.evidence == tuple(
            _stream_evidence(item)
            for item in sorted(episode.evidence, key=lambda item: int(item.group))
        )
        assert candidate.evidence_group_mask == episode.evidence_group_mask
        assert candidate.source_detail_expires_at is None

    assert feed.episodes[0].service_id == "01" * 16
    assert feed.episodes[0].asn_id == 64500
    assert any(item.service_id is None and item.asn_id is None for item in feed.episodes)
    assert all(item["source_detail_expires_at"] is None for item in feed.payload()["episodes"])


def test_feed_schema_excludes_raw_review_and_legacy_selection_fields() -> None:
    payload = build_daily_evidence_stream(_ranking(), _metadata()).payload()
    candidate = payload["episodes"][0]
    evidence = candidate["evidence"][0]

    assert set(payload) == {
        "stream_schema_version",
        "day",
        "published_at",
        "run_id",
        "detector_version",
        "ordering_version",
        "episode_count",
        "episodes",
    }
    assert set(candidate) == {
        "episode_id",
        "run_id",
        "day",
        "detected_at",
        "client_ip",
        "family",
        "episode_start",
        "episode_end",
        "service_id",
        "asn_id",
        "family_strength",
        "evidence_tier",
        "sequence",
        "tie_group",
        "service_domain",
        "evidence_group_mask",
        "history_confidence",
        "data_quality_confidence",
        "reason_code_mask",
        "detector_version",
        "ordering_version",
        "source_detail_expires_at",
        "evidence",
    }
    assert set(evidence) == {
        "evidence_group",
        "metric_code",
        "observed_value",
        "client_baseline_value",
        "peer_reference_value",
        "self_strength",
        "peer_strength",
        "metric_strength",
        "support_count",
    }
    candidate_fields = {item.name for item in fields(StreamEpisode)}
    assert candidate_fields.isdisjoint(
        {
            "selection_stratum",
            "investigate_by",
            "review",
            "endpoint",
            "server_ip",
            "domain",
            "sni",
            "flow",
            "source_row",
            "evidence_text",
            "label",
            "status",
        }
    )
    serialized = json.dumps(payload, sort_keys=True).lower()
    for wording in (
        "threat",
        "malware",
        "compromise",
        "scanning",
        "exfiltration",
        "command_and_control",
    ):
        assert wording not in serialized


def test_feed_rejects_count_rank_identity_and_version_drift() -> None:
    ranking = _ranking()
    feed = build_daily_evidence_stream(ranking, _metadata())

    with pytest.raises(StreamValidationError, match="episode count"):
        DailyEvidenceStream(
            replace(feed.header, episode_count=feed.header.episode_count + 1),
            feed.episodes,
        )
    with pytest.raises(StreamValidationError, match="sequence"):
        DailyEvidenceStream(
            feed.header,
            (feed.episodes[0], replace(feed.episodes[1], sequence=1), *feed.episodes[2:]),
        )
    with pytest.raises(StreamValidationError, match="IDs"):
        DailyEvidenceStream(
            feed.header,
            (
                feed.episodes[0],
                replace(feed.episodes[1], episode_id=feed.episodes[0].episode_id),
                *feed.episodes[2:],
            ),
        )
    with pytest.raises(StreamValidationError, match="version"):
        build_daily_evidence_stream(replace(ranking, ordering_version=""), _metadata())

    empty = build_daily_evidence_stream(
        replace(ranking, ranked_eligible=(), client_view=()),
        _metadata(),
    )
    assert empty.header.episode_count == 0
    assert empty.header.detector_version == DETECTOR_VERSION
    assert empty.header.ordering_version == RankingPolicy().version


def test_feed_rejects_timestamp_evidence_diagnostic_and_wording_drift() -> None:
    ranking = _ranking()
    episode = ranking.ranked_eligible[0]
    evidence = episode.evidence[0]

    with pytest.raises(StreamValidationError, match="UTC"):
        StreamBuildMetadata(RUN_ID, PUBLISHED.replace(tzinfo=None), PUBLISHED, None)
    with pytest.raises(StreamValidationError, match="expiry"):
        StreamBuildMetadata(
            RUN_ID,
            PUBLISHED,
            PUBLISHED,
            PUBLISHED - timedelta(seconds=1),
        )

    duplicate_evidence = replace(
        episode,
        evidence=(evidence, evidence),
        evidence_group_mask=1 << int(evidence.group),
    )
    with pytest.raises(StreamValidationError, match="groups must be unique"):
        build_daily_evidence_stream(
            replace(ranking, ranked_eligible=(duplicate_evidence, *ranking.ranked_eligible[1:])),
            _metadata(),
        )

    with pytest.raises(StreamValidationError, match="group mask"):
        build_daily_evidence_stream(
            replace(
                ranking,
                ranked_eligible=(
                    replace(episode, evidence_group_mask=0),
                    *ranking.ranked_eligible[1:],
                ),
            ),
            _metadata(),
        )

    prohibited_evidence = replace(evidence, metric_code="malware_score")
    with pytest.raises(StreamValidationError, match="prohibited wording"):
        build_daily_evidence_stream(
            replace(
                ranking,
                ranked_eligible=(
                    replace(
                        episode,
                        evidence=(prohibited_evidence, *episode.evidence[1:]),
                    ),
                    *ranking.ranked_eligible[1:],
                ),
            ),
            _metadata(),
        )

    with pytest.raises(StreamValidationError, match="non-eligible"):
        build_daily_evidence_stream(
            replace(
                ranking,
                ranked_eligible=(
                    replace(episode, status=SignalStatus.DIAGNOSTIC),
                    *ranking.ranked_eligible[1:],
                ),
            ),
            _metadata(),
        )
    with pytest.raises(StreamValidationError, match="overlap"):
        build_daily_evidence_stream(
            replace(ranking, diagnostics=(episode, *ranking.diagnostics)),
            _metadata(),
        )


def test_service_domain_is_attached_only_to_the_service_it_names() -> None:
    ranking = _ranking()
    metadata = _metadata()

    baseline = build_daily_evidence_stream(ranking, metadata)
    assert all(episode.service_domain is None for episode in baseline.episodes)

    keyed = [episode for episode in baseline.episodes if episode.service_id]
    assert keyed, "fixture must contain at least one service-keyed episode"
    resolved = build_daily_evidence_stream(
        ranking,
        metadata,
        {episode.service_id: "example.com" for episode in keyed if episode.service_id},
    )

    for episode in resolved.episodes:
        expected = "example.com" if episode.service_id else None
        assert episode.service_domain == expected


def test_an_unmatched_service_domain_mapping_resolves_nothing() -> None:
    """A domain reaches an episode only through its own service_id, never by position."""
    stream = build_daily_evidence_stream(_ranking(), _metadata(), {"00" * 16: "elsewhere.com"})

    assert all(episode.service_domain is None for episode in stream.episodes)


def test_an_observed_domain_is_data_not_a_claim_this_system_makes() -> None:
    """Vocabulary rules govern strings we author, never a destination we merely observed.

    A whole day's stream is published in one transaction, so rejecting an ordinary domain here
    destroyed every episode of that day. `malwarebytes.com` passed and `anti-malware.org` did
    not, on a word boundary.
    """
    ranking = _ranking()
    keyed = [
        episode
        for episode in build_daily_evidence_stream(ranking, _metadata()).episodes
        if episode.service_id
    ]
    assert keyed

    for domain in ("anti-malware.org", "risk.net", "scan.co.uk", "threat-intel.io"):
        stream = build_daily_evidence_stream(
            ranking,
            _metadata(),
            {episode.service_id: domain for episode in keyed if episode.service_id},
        )
        assert {episode.service_domain for episode in stream.episodes if episode.service_id} == {
            domain
        }


def test_authored_identifiers_still_reject_prohibited_wording() -> None:
    """The guard stays where the wording is ours: versions and metric codes."""
    ranking = _ranking()

    with pytest.raises(StreamValidationError, match="prohibited wording"):
        build_daily_evidence_stream(
            replace(ranking, ordering_version="threat-ordering-v1"), _metadata()
        )
