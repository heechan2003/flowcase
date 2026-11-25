from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import duckdb
import pytest

from network_behaviour.baselines.models import HistoryConfidence
from network_behaviour.detectors.models import DETECTOR_VERSION, DetectorFamily
from network_behaviour.domain import EvidenceGroup, ReasonCode, code_mask
from network_behaviour.feed import (
    STREAM_SCHEMA_VERSION,
    DailyEvidenceStream,
    StreamEpisode,
    StreamEvidence,
    StreamHeader,
    iter_daily_evidence_stream_jsonl,
)
from network_behaviour.feed.legacy_v1 import (
    LEGACY_FEED_SCHEMA_VERSION,
    DailyCandidateFeed,
    DailyFeedCandidate,
    DailyFeedEvidence,
    DailyFeedHeader,
    LegacyPriorityTier,
)
from network_behaviour.ranking import (
    ORDERING_VERSION,
    DataQualityConfidence,
    EvidenceTier,
)
from network_behaviour.storage import feed as feed_storage_module
from network_behaviour.storage.feed import (
    DailyFeedRepository,
    FeedDayKind,
    FeedStorageError,
    FeedStorageGuard,
    LegacySchemaVersionError,
    LegacySelectedDayError,
)
from network_behaviour.storage.migrations import MigrationRunner
from network_behaviour.time import UtcDay

MIGRATIONS = Path(__file__).parents[3] / "sql" / "migrations"
DAY = UtcDay.parse("2026-07-10")


def _feed(
    day: UtcDay,
    count: int,
    *,
    groups: tuple[EvidenceGroup, ...] = (EvidenceGroup.TRANSFER_MAGNITUDE,),
) -> DailyEvidenceStream:
    run_id = uuid5(NAMESPACE_URL, f"feed-run:{day}")
    published = day.eligible_at
    evidence_mask = code_mask(*groups)
    candidates = tuple(
        StreamEpisode(
            uuid5(NAMESPACE_URL, f"stream-episode:{day}:{rank}"),
            run_id,
            str(day),
            published,
            f"10.20.{(rank - 1) // 256}.{(rank - 1) % 256}",
            DetectorFamily.TRANSFER,
            day.bounds.start + timedelta(minutes=(rank - 1) % 1440),
            day.bounds.start + timedelta(minutes=(rank - 1) % 1440),
            None,  # service_id
            None,  # service_domain
            None,  # asn_id
            95.0,
            EvidenceTier.E3,
            rank,  # sequence
            rank,  # tie_group — every fixture episode is distinct on the ordering key
            evidence_mask,
            HistoryConfidence.NORMAL,
            DataQualityConfidence.NORMAL,
            code_mask(ReasonCode.UNUSUAL_EXTERNAL_TRANSFER),
            DETECTOR_VERSION,
            ORDERING_VERSION,
            None,
            tuple(_evidence(group, rank) for group in groups),
        )
        for rank in range(1, count + 1)
    )
    return DailyEvidenceStream(
        StreamHeader(
            STREAM_SCHEMA_VERSION,
            str(day),
            published,
            run_id,
            DETECTOR_VERSION,
            ORDERING_VERSION,
            count,
        ),
        candidates,
    )


def _evidence(group: EvidenceGroup, rank: int) -> StreamEvidence:
    if group is EvidenceGroup.LARGE_FLOW_CONTEXT:
        return StreamEvidence(
            group,
            "filtered_large_flow_count",
            float(rank % 17 + 1),
            None,
            None,
            None,
            None,
            None,
            rank % 17 + 1,
        )
    return StreamEvidence(
        group,
        "up_bytes",
        float(rank * 1000),
        float(rank * 100),
        float(rank * 110),
        95.0,
        94.0,
        94.0,
        None,
    )


def _connection(database: str = ":memory:") -> duckdb.DuckDBPyConnection:
    connection = duckdb.connect(database)
    MigrationRunner(MIGRATIONS).apply(connection)
    return connection


def _insert_run(
    connection: duckdb.DuckDBPyConnection,
    feed: DailyEvidenceStream | DailyCandidateFeed,
    *,
    status: str = "running",
) -> None:
    connection.execute(
        """
        INSERT INTO ops.pipeline_run (
            run_id, day, status, started_at, completed_at, source_sql_version,
            schema_version, normalization_version, detector_version
        ) VALUES (?, ?, ?, ?, ?, 'source-v1', 7, 'normalization-v1', ?)
        """,
        [
            feed.header.run_id,
            feed.header.day,
            status,
            feed.header.published_at,
            feed.header.published_at if status == "published" else None,
            feed.header.detector_version,
        ],
    )


def test_bulk_publication_round_trips_exact_bytes_and_is_idempotent() -> None:
    connection = _connection()
    feed = _feed(
        DAY,
        3,
        groups=(EvidenceGroup.TRANSFER_MAGNITUDE, EvidenceGroup.LARGE_FLOW_CONTEXT),
    )
    _insert_run(connection, feed)
    repository = DailyFeedRepository(connection)

    first = repository.publish(feed)
    repeated = repository.publish(feed)
    loaded = repository.load(DAY)

    assert not first.idempotent
    assert repeated.idempotent
    assert first.candidate_rows == 3
    assert first.evidence_rows == 6
    assert first.feed_sha256 == repeated.feed_sha256
    assert loaded.to_bytes() == feed.to_bytes()
    assert repository.day_kind(DAY) is FeedDayKind.COMPLETE
    assert connection.execute("SELECT count(*) FROM feed.episode").fetchone() == (3,)
    assert connection.execute("SELECT count(*) FROM feed.episode_evidence").fetchone() == (6,)


def test_empty_complete_feed_round_trips_with_versions() -> None:
    connection = _connection()
    feed = _feed(DAY, 0)
    _insert_run(connection, feed)
    repository = DailyFeedRepository(connection)

    result = repository.publish(feed)

    assert result.candidate_rows == result.evidence_rows == 0
    assert repository.load(DAY).to_bytes() == feed.to_bytes()


def test_complete_feed_requires_a_matching_running_completed_day_run() -> None:
    connection = _connection()
    feed = _feed(DAY, 1)
    repository = DailyFeedRepository(connection)

    with pytest.raises(FeedStorageError, match="run does not exist"):
        repository.publish(feed)

    _insert_run(connection, feed)
    connection.execute(
        "UPDATE ops.pipeline_run SET started_at = ? WHERE run_id = ?",
        [DAY.bounds.end, feed.header.run_id],
    )
    with pytest.raises(FeedStorageError, match="before day-D eligibility"):
        repository.publish(feed)

    connection.execute(
        "UPDATE ops.pipeline_run SET started_at = ?, day = ? WHERE run_id = ?",
        [feed.header.published_at, DAY.value - timedelta(days=1), feed.header.run_id],
    )
    with pytest.raises(FeedStorageError, match="does not match"):
        repository.publish(feed)

    connection.execute(
        "UPDATE ops.pipeline_run SET day = ?, status = 'created' WHERE run_id = ?",
        [DAY.value, feed.header.run_id],
    )
    with pytest.raises(FeedStorageError, match="requires a running"):
        repository.publish(feed)

    connection.execute(
        "UPDATE ops.pipeline_run SET status = 'running', started_at = ? WHERE run_id = ?",
        [feed.header.published_at + timedelta(minutes=1), feed.header.run_id],
    )
    with pytest.raises(FeedStorageError, match="precedes its run"):
        repository.publish(feed)


def test_conflicting_retry_is_rejected_without_mutating_the_feed() -> None:
    connection = _connection()
    feed = _feed(DAY, 2)
    _insert_run(connection, feed)
    repository = DailyFeedRepository(connection)
    repository.publish(feed)
    conflict = DailyEvidenceStream(
        replace(feed.header, published_at=feed.header.published_at + timedelta(minutes=1)),
        feed.episodes,
    )

    with pytest.raises(FeedStorageError, match="retry conflicts"):
        repository.publish(conflict)

    assert repository.load(DAY).to_bytes() == feed.to_bytes()


def test_repository_rolls_back_header_candidates_and_evidence_on_reconciliation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _connection()
    feed = _feed(DAY, 2)
    _insert_run(connection, feed)
    repository = DailyFeedRepository(connection)
    evidence_arrow = feed_storage_module._evidence_arrow
    monkeypatch.setattr(
        feed_storage_module,
        "_evidence_arrow",
        lambda _candidates: evidence_arrow(()),
    )

    with pytest.raises(FeedStorageError, match="evidence count"):
        repository.publish(feed)

    assert connection.execute("SELECT count(*) FROM feed.daily_publication").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM feed.episode").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM feed.episode_evidence").fetchone() == (0,)


def test_caller_owned_transaction_can_atomically_include_or_rollback_the_feed() -> None:
    connection = _connection()
    feed = _feed(DAY, 2)
    _insert_run(connection, feed)
    repository = DailyFeedRepository(connection)

    connection.execute("BEGIN TRANSACTION")
    result = repository.publish_in_transaction(feed)
    assert result.candidate_rows == 2
    assert connection.execute("SELECT count(*) FROM feed.daily_publication").fetchone() == (1,)
    connection.execute("ROLLBACK")

    assert repository.day_kind(DAY) is FeedDayKind.ABSENT
    assert connection.execute("SELECT count(*) FROM feed.episode").fetchone() == (0,)


def test_legacy_selected_days_are_queryable_but_never_load_as_complete_feeds() -> None:
    connection = _connection()
    legacy_feed = _feed(DAY, 1)
    _insert_run(connection, legacy_feed, status="published")
    candidate = legacy_feed.episodes[0]
    connection.execute(
        """
        INSERT INTO detect.candidate_episode (
            candidate_id, run_id, day, detected_at, client_ip, family,
            episode_start, episode_end, service_id, asn_id, family_strength,
            priority_tier, priority_score, evidence_group_mask,
            history_confidence, data_quality_confidence, reason_code_mask,
            detector_version, selection_stratum, investigate_by,
            source_detail_expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?,
                  'main_queue', ?, ?)
        """,
        [
            candidate.episode_id,
            candidate.run_id,
            candidate.day,
            candidate.detected_at,
            candidate.client_ip,
            candidate.family.value,
            candidate.episode_start,
            candidate.episode_end,
            candidate.family_strength,
            "P3",  # frozen v1 tier code, not the v2 evidence tier
            30,  # frozen v1 priority score; the v2 stream no longer carries one
            candidate.evidence_group_mask,
            candidate.history_confidence.value,
            candidate.data_quality_confidence.value,
            candidate.reason_code_mask,
            f"{candidate.detector_version}/{candidate.ordering_version}",
            candidate.detected_at + timedelta(days=7),
            candidate.detected_at + timedelta(days=14),
        ],
    )
    repository = DailyFeedRepository(connection)

    assert connection.execute(
        "SELECT publication_kind FROM detect.legacy_selected_episode"
    ).fetchone() == ("legacy_selected",)
    assert repository.day_kind(DAY) is FeedDayKind.LEGACY_SELECTED
    with pytest.raises(LegacySelectedDayError, match="not a complete feed"):
        repository.load(DAY)
    with pytest.raises(LegacySelectedDayError, match="already has"):
        repository.publish(legacy_feed)

    empty_legacy_day = UtcDay.parse("2026-07-09")
    empty_legacy = _feed(empty_legacy_day, 0)
    _insert_run(connection, empty_legacy, status="published")
    assert repository.day_kind(empty_legacy_day) is FeedDayKind.LEGACY_SELECTED
    with pytest.raises(LegacySelectedDayError):
        repository.load(empty_legacy_day)


def test_corrupt_persisted_evidence_fails_closed_on_read() -> None:
    connection = _connection()
    feed = _feed(DAY, 2)
    _insert_run(connection, feed)
    repository = DailyFeedRepository(connection)
    repository.publish(feed)
    connection.execute(
        "DELETE FROM feed.episode_evidence WHERE episode_id = ?",
        [feed.episodes[0].episode_id],
    )

    with pytest.raises(FeedStorageError, match=r"typed contract|evidence count"):
        repository.load(DAY)


def test_storage_guard_stops_growth_without_partial_rows() -> None:
    connection = _connection()
    feed = _feed(DAY, 1)
    _insert_run(connection, feed)
    repository = DailyFeedRepository(
        connection,
        FeedStorageGuard(alert_bytes=1, stop_bytes=2),
    )

    with pytest.raises(FeedStorageError, match="storage reaches"):
        repository.publish(feed)

    assert connection.execute("SELECT count(*) FROM feed.daily_publication").fetchone() == (0,)


def test_caller_owned_transaction_reserves_pending_history_growth() -> None:
    connection = _connection()
    feed = _feed(DAY, 1)
    _insert_run(connection, feed)
    guard = FeedStorageGuard(
        alert_bytes=1,
        stop_bytes=10_000,
        estimated_header_bytes=1,
        estimated_candidate_bytes=1,
        estimated_evidence_bytes=1,
    )
    repository = DailyFeedRepository(connection, guard)

    with pytest.raises(FeedStorageError, match="storage reaches"):
        repository.publish_in_transaction(feed, reserved_bytes=10_000)

    assert connection.execute("SELECT count(*) FROM feed.daily_publication").fetchone() == (0,)


@pytest.mark.parametrize(
    ("candidate_count", "groups"),
    [
        (250, (EvidenceGroup.TRANSFER_MAGNITUDE,)),
        (10_001, (EvidenceGroup.TRANSFER_MAGNITUDE,)),
        (
            10_001,
            (EvidenceGroup.TRANSFER_MAGNITUDE, EvidenceGroup.LARGE_FLOW_CONTEXT),
        ),
    ],
)
def test_representative_and_stress_feed_storage_is_measured_without_read_truncation(
    tmp_path: Path,
    candidate_count: int,
    groups: tuple[EvidenceGroup, ...],
) -> None:
    database = tmp_path / f"complete-feed-{candidate_count}-{len(groups)}.duckdb"
    connection = _connection(str(database))
    feed = _feed(DAY, candidate_count, groups=groups)
    _insert_run(connection, feed)
    connection.execute("CHECKPOINT")
    bytes_before = database.stat().st_size
    repository = DailyFeedRepository(connection)

    result = repository.publish(feed)
    connection.execute("CHECKPOINT")
    bytes_after = database.stat().st_size
    loaded = repository.load(DAY)

    assert len(loaded.episodes) == candidate_count
    assert loaded.episodes[-1].sequence == candidate_count
    assert loaded.to_bytes() == feed.to_bytes()
    assert sum(1 for _ in iter_daily_evidence_stream_jsonl(loaded)) == candidate_count + 1
    assert bytes_after > bytes_before
    actual_growth = bytes_after - bytes_before
    projected_growth = result.storage.projected_bytes - result.storage.current_bytes
    assert actual_growth < projected_growth
    assert result.serialized_bytes > 0
    connection.close()


def test_v1_published_day_streams_back_unchanged_under_the_v2_schema() -> None:
    """A day published under daily-candidate-feed-v1 must survive the v2 cutover byte-for-byte.

    Published feeds are reconstructed from stored rows and verified against a stored digest, not
    replayed from saved bytes. So the frozen v1 contract has to keep serializing exactly as it did
    when the digest was taken. This seeds the v1 tables directly, the way a pre-cutover day exists
    in a production database, and proves both that it still verifies and that it is never
    re-encoded as v2.
    """
    connection = _connection()
    day = DAY
    run_id = uuid5(NAMESPACE_URL, f"legacy-run:{day}")
    published = day.eligible_at
    candidate_id = uuid5(NAMESPACE_URL, f"legacy-candidate:{day}")

    evidence = (
        DailyFeedEvidence(
            EvidenceGroup.TRANSFER_MAGNITUDE,
            "up_bytes",
            5_000_000.0,
            None,
            None,
            None,
            None,
            99.5,
            None,
        ),
    )
    candidate = DailyFeedCandidate(
        candidate_id,
        run_id,
        str(day),
        published,
        "10.20.1.1",
        DetectorFamily.TRANSFER,
        day.bounds.start,
        day.bounds.start + timedelta(minutes=5),
        None,
        None,
        99.5,
        LegacyPriorityTier.P1,
        1,
        100,
        code_mask(EvidenceGroup.TRANSFER_MAGNITUDE),
        HistoryConfidence.NORMAL,
        DataQualityConfidence.NORMAL,
        code_mask(ReasonCode.UNUSUAL_EXTERNAL_TRANSFER),
        DETECTOR_VERSION,
        "episode-ranking-v2",
        None,
        evidence,
    )
    legacy = DailyCandidateFeed(
        DailyFeedHeader(
            LEGACY_FEED_SCHEMA_VERSION,
            str(day),
            published,
            run_id,
            DETECTOR_VERSION,
            "episode-ranking-v2",
            1,
        ),
        (candidate,),
    )
    payload = legacy.to_bytes()

    _insert_run(connection, legacy, status="published")
    connection.execute(
        """
        INSERT INTO feed.daily_publication VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            day.value,
            LEGACY_FEED_SCHEMA_VERSION,
            published,
            run_id,
            DETECTOR_VERSION,
            "episode-ranking-v2",
            1,
            1,
            len(payload),
            sha256(payload).hexdigest(),
        ],
    )
    connection.execute(
        """
        INSERT INTO feed.candidate_episode VALUES (
            ?, ?, ?, ?, '10.20.1.1', 'transfer', ?, ?, NULL, NULL, 99.5,
            'P1', 1, 100, ?, 'normal', 'normal', ?, ?, 'episode-ranking-v2', NULL
        )
        """,
        [
            candidate_id,
            run_id,
            day.value,
            published,
            day.bounds.start,
            day.bounds.start + timedelta(minutes=5),
            code_mask(EvidenceGroup.TRANSFER_MAGNITUDE),
            code_mask(ReasonCode.UNUSUAL_EXTERNAL_TRANSFER),
            DETECTOR_VERSION,
        ],
    )
    connection.execute(
        """
        INSERT INTO feed.candidate_evidence VALUES (
            ?, 0, 'up_bytes', 5000000.0, NULL, NULL, NULL, NULL, 99.5, NULL
        )
        """,
        [candidate_id],
    )

    repository = DailyFeedRepository(connection)

    # The day is complete, and its metadata is readable without re-encoding it.
    assert repository.day_kind(day) is FeedDayKind.COMPLETE
    assert repository.published_metadata(day).feed_schema_version == LEGACY_FEED_SCHEMA_VERSION

    # It streams back in the encoding it was published under, byte-for-byte.
    streamed = b"".join(repository.load_jsonl(day))
    assert b'"feed_schema_version":"daily-candidate-feed-v1"' in streamed
    assert b'"record_type":"candidate"' in streamed
    assert b'"daily_rank":1' in streamed
    assert b"evidence_tier" not in streamed
    assert b"tie_group" not in streamed

    # And it is never presented as a v2 stream.
    with pytest.raises(LegacySchemaVersionError):
        repository.load(day)
