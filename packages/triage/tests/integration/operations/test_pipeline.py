from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb
import pytest

from network_behaviour.aggregation import ActivityObservation, DayAggregator, StagedDay
from network_behaviour.baselines.models import BASELINE_VERSION, HistoryConfidence
from network_behaviour.detectors import (
    DETECTOR_VERSION,
    DetectionBatch,
    DetectorFamily,
    DetectorSignal,
    DnsDailyObservation,
)
from network_behaviour.detectors.models import (
    DecisionStatus,
    DetectorDiagnostic,
    DetectorEvidence,
    DetectorPolicy,
)
from network_behaviour.domain import EvidenceGroup, ReasonCode
from network_behaviour.drift import DriftPolicy
from network_behaviour.feed import DailyEvidenceStream, iter_daily_evidence_stream_jsonl
from network_behaviour.operations import pipeline as pipeline_module
from network_behaviour.operations import scoring as scoring_module
from network_behaviour.operations.pipeline import (
    DayRunError,
    DayRunReport,
    DayRunService,
    run_days_sequentially,
)
from network_behaviour.population import (
    POPULATION_VERSION,
    RETIRED_SUPPORT_DEFINITION_V1,
)
from network_behaviour.publication import PublicationError, StorageGuard
from network_behaviour.ranking import ORDERING_VERSION, RankingPolicy
from network_behaviour.source.day import ReconciliationTotals, SourceDayInputs
from network_behaviour.storage.feed import (
    DailyFeedRepository,
    FeedDayKind,
    FeedPublicationResult,
    FeedStorageGuard,
)
from network_behaviour.storage.migrations import MigrationRunner
from network_behaviour.time import UtcDay

ROOT = Path(__file__).parents[3]
MIGRATIONS = ROOT / "sql" / "migrations"
DAY = UtcDay.parse("2026-07-10")
NOW = datetime(2026, 7, 11, 8, tzinfo=UTC)


class _Provider:
    def __init__(
        self,
        source: SourceDayInputs,
        staged: StagedDay,
        dns: tuple[DnsDailyObservation, ...] = (),
    ) -> None:
        self.source = source
        self.staged = staged
        self.dns = dns
        self.calls = 0

    def load(
        self, day: UtcDay
    ) -> tuple[SourceDayInputs, StagedDay, tuple[DnsDailyObservation, ...]]:
        self.calls += 1
        assert day == self.source.day
        return self.source, self.staged, self.dns


def _inputs(day: UtcDay) -> tuple[SourceDayInputs, StagedDay]:
    observation = ActivityObservation(
        day.bounds.start,
        "10.20.1.2",
        "8.8.8.8",
        443,
        6,
        "example.com",
        None,
        None,
        "web",
        "browsing",
        "AS15169",
        100,
        50,
        10,
        5,
        2,
        (0,),
    )
    staged = DayAggregator().aggregate(day, (observation,), (), ())
    source = SourceDayInputs(
        day,
        ReconciliationTotals(100, 50, 100, 50),
        (
            '{"day_activity_observations":1,"day_long_flow_observations":1,'
            '"day_rate_observations":1,"dns_daily_observations":1}'
        ),
        6,
        100,
        1_000,
        20_000,
        1.0,
        0.5,
    )
    return source, staged


def _connection() -> duckdb.DuckDBPyConnection:
    connection = duckdb.connect(":memory:")
    MigrationRunner(MIGRATIONS).apply(connection)
    return connection


def _service(
    connection: duckdb.DuckDBPyConnection,
    *,
    feed_storage_guard: FeedStorageGuard | None = None,
    drift_policy: DriftPolicy | None = None,
) -> DayRunService:
    return DayRunService(
        connection,
        RankingPolicy(),
        StorageGuard(),
        feed_storage_guard=feed_storage_guard,
        drift_policy=drift_policy,
    )


def _signal(
    client_ip: str,
    family: DetectorFamily,
    strength: float,
    evidence: tuple[DetectorEvidence, ...],
) -> DetectorSignal:
    labels = {
        DetectorFamily.TRANSFER: "unusual external transfer",
        DetectorFamily.FANOUT: "external fanout change",
        DetectorFamily.DNS: "DNS behaviour change",
    }
    reasons = {
        DetectorFamily.TRANSFER: ReasonCode.UNUSUAL_EXTERNAL_TRANSFER,
        DetectorFamily.FANOUT: ReasonCode.EXTERNAL_FANOUT_CHANGE,
        DetectorFamily.DNS: ReasonCode.DNS_BEHAVIOUR_CHANGE,
    }
    return DetectorSignal(
        client_ip,
        family,
        labels[family],
        strength,
        HistoryConfidence.NORMAL,
        evidence,
        (reasons[family],),
    )


def _complete_detection_batch(day: UtcDay) -> DetectionBatch:
    shared_client = "10.20.1.2"
    p1 = _signal(
        shared_client,
        DetectorFamily.TRANSFER,
        99.8,
        (
            DetectorEvidence(
                EvidenceGroup.TRANSFER_MAGNITUDE,
                "up_bytes",
                5_000_000.0,
                metric_strength=99.8,
            ),
            DetectorEvidence(
                EvidenceGroup.LARGE_FLOW_CONTEXT,
                "filtered_large_flow_count",
                2.0,
                # Qualified against the host's own prior large flows, which is what promotes an
                # episode to E1 under episode-ordering-v4. Presence alone no longer does.
                metric_strength=99.6,
                support_count=2,
            ),
        ),
    )
    p2 = _signal(
        shared_client,
        DetectorFamily.DNS,
        99.2,
        (
            DetectorEvidence(
                EvidenceGroup.DNS_VOLUME,
                "query_volume",
                10_000.0,
                metric_strength=99.2,
                support_count=200,
            ),
        ),
    )
    p3 = _signal(
        "10.20.1.3",
        DetectorFamily.FANOUT,
        98.0,
        (
            DetectorEvidence(
                EvidenceGroup.FANOUT,
                "max_5m_unique_servers",
                80.0,
                metric_strength=98.0,
                support_count=150,
            ),
        ),
    )
    below_threshold = _signal(
        "10.20.1.4",
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
    return DetectionBatch(
        str(day),
        DETECTOR_VERSION,
        (p1, p2, p3),
        (
            DetectorDiagnostic(
                below_threshold.client_ip,
                below_threshold.family,
                DecisionStatus.INELIGIBLE,
                (ReasonCode.INSUFFICIENT_SUPPORT,),
                near_threshold_signal=below_threshold,
            ),
        ),
    )


def _install_complete_detector(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Detector:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def detect(self, day: UtcDay, *_args: object, **_kwargs: object) -> DetectionBatch:
            return _complete_detection_batch(day)

    monkeypatch.setattr(scoring_module, "DetectorEngine", _Detector)


def test_run_day_publishes_atomically_and_rerun_skips_all_source_queries() -> None:
    connection = _connection()
    source, staged = _inputs(DAY)
    provider = _Provider(source, staged)
    service = _service(connection)

    preflight = service.preflight(DAY, now=NOW)
    first = service.run(DAY, provider, now=NOW)
    second = service.run(DAY, provider, now=NOW)

    assert preflight.status == "ready"
    assert first.status == "published"
    assert second.status == "already_published"
    assert first.run_id == second.run_id
    assert provider.calls == 1
    assert first.query_count == 6
    assert connection.execute("SELECT count(*) FROM history.client_day").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM feed.daily_publication").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM detect.candidate_episode").fetchone() == (0,)
    assert connection.execute(
        "SELECT detector_version FROM ops.pipeline_run WHERE status = 'published'"
    ).fetchone() == (f"{DETECTOR_VERSION}/{ORDERING_VERSION}",)

    connection.execute("UPDATE ops.pipeline_run SET source_sql_version = 'phase3-source-bundle-v2'")
    assert service.preflight(DAY, now=NOW).status == "already_published"

    connection.execute("UPDATE ops.pipeline_run SET detector_version = 'incompatible-version'")
    with pytest.raises(DayRunError, match="chronological replay"):
        service.preflight(DAY, now=NOW)


def test_publication_records_the_baseline_generation_that_produced_the_day() -> None:
    """`BASELINE_VERSION` was carried on every batch and persisted nowhere until migration 0009.

    Baselines set every denominator a strength is measured against, so a change to them is a
    behaviour change. Without this column it would have shipped with no version marker at all.
    """
    connection = _connection()
    source, staged = _inputs(DAY)
    service = _service(connection)

    service.run(DAY, _Provider(source, staged), now=NOW)

    assert connection.execute(
        "SELECT baseline_version FROM ops.pipeline_run WHERE status = 'published'"
    ).fetchone() == (BASELINE_VERSION,)


def test_publication_counts_and_records_what_the_support_gate_left_out() -> None:
    """`staged_client_rows` is every observed address. The supported population is a different
    number, and until migration 0010 no published day recorded which."""
    connection = _connection()
    source, staged = _inputs(DAY)
    service = _service(connection)

    report = service.run(DAY, _Provider(source, staged), now=NOW)

    assert report.supported_client_rows + report.out_of_scope_client_rows == report.client_rows
    assert "out-of-scope client rows" in report.render()
    assert connection.execute(
        """
        SELECT supported_client_rows, out_of_scope_client_rows, population_definition_version
        FROM ops.pipeline_run WHERE status = 'published'
        """
    ).fetchone() == (
        report.supported_client_rows,
        report.out_of_scope_client_rows,
        POPULATION_VERSION,
    )


def test_a_day_published_before_baseline_versioning_stays_readable() -> None:
    """NULL is a day published before migration 0009, and the forward-only policy keeps it.

    Those days cannot be re-derived — source detail expires in roughly fifteen days — so treating
    an unrecorded generation as a mismatch would strand every day already in the archive.
    """
    connection = _connection()
    source, staged = _inputs(DAY)
    service = _service(connection)
    service.run(DAY, _Provider(source, staged), now=NOW)

    connection.execute("UPDATE ops.pipeline_run SET baseline_version = NULL")

    assert service.preflight(DAY, now=NOW).status == "already_published"


def test_a_day_published_under_an_unknown_baseline_generation_refuses_to_stream_back() -> None:
    connection = _connection()
    source, staged = _inputs(DAY)
    service = _service(connection)
    service.run(DAY, _Provider(source, staged), now=NOW)

    connection.execute("UPDATE ops.pipeline_run SET baseline_version = 'baseline-calibration-v99'")

    with pytest.raises(DayRunError, match="incompatible baseline generation"):
        service.preflight(DAY, now=NOW)


def test_a_day_written_under_an_earlier_schema_streams_back_unchanged() -> None:
    """The real archive holds days written at schema 5, 7 and 10.

    Strict equality with the current schema stranded every v1-feed day written at schema 7
    (2026-07-13 to 08-09): `run-day` refused them, and they cannot be re-derived. A schema version
    records when a day was written, not what it needs, because every migration since 0005 is
    additive.
    """
    connection = _connection()
    source, staged = _inputs(DAY)
    provider = _Provider(source, staged)
    service = _service(connection)
    service.run(DAY, provider, now=NOW)
    stored = b"".join(iter_daily_evidence_stream_jsonl(DailyFeedRepository(connection).load(DAY)))

    connection.execute("UPDATE ops.pipeline_run SET schema_version = 7")

    assert service.preflight(DAY, now=NOW).status == "already_published"
    assert service.run(DAY, provider, now=NOW).status == "already_published"
    assert provider.calls == 1
    assert (
        b"".join(iter_daily_evidence_stream_jsonl(DailyFeedRepository(connection).load(DAY)))
        == stored
    )


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("schema_version", "99"),
        ("query_versions_json", "'{\"day_activity_observations\":99}'"),
        ("aggregation_version", "'day-aggregation-v99'"),
        ("reconciliation_version", "'activity-rate-relative-v99'"),
        ("normalization_version", "'service-id-v99'"),
    ],
)
def test_a_day_written_under_an_unknown_generation_refuses_to_stream_back(
    column: str, value: str
) -> None:
    connection = _connection()
    source, staged = _inputs(DAY)
    service = _service(connection)
    service.run(DAY, _Provider(source, staged), now=NOW)

    connection.execute(f"UPDATE ops.pipeline_run SET {column} = {value}")

    with pytest.raises(DayRunError, match="incompatible versions"):
        service.preflight(DAY, now=NOW)


def test_ranking_v1_feed_remains_source_free_byte_stable_and_immutable_under_v2() -> None:
    connection = _connection()
    source, staged = _inputs(DAY)
    old_provider = _Provider(source, staged)
    # A genuinely historical day: the ranking version *and* the detector generation that went with
    # it, including the support gate retired in behavioural-support-v2. Publishing under today's
    # detector and yesterday's ranking would fabricate a pair that no run ever produced.
    old_service = DayRunService(
        connection,
        RankingPolicy(version="episode-ranking-v1"),
        StorageGuard(),
        detector_policy=DetectorPolicy(
            version="primary-detectors-v2", support=RETIRED_SUPPORT_DEFINITION_V1
        ),
    )

    old_service.run(DAY, old_provider, now=NOW)
    old_feed = DailyFeedRepository(connection).load(DAY)
    old_bytes = old_feed.to_bytes()
    old_jsonl = b"".join(iter_daily_evidence_stream_jsonl(old_feed))

    current_service = _service(connection)
    assert current_service.preflight(DAY, now=NOW).status == "already_published"
    assert current_service.run(DAY, old_provider, now=NOW).status == "already_published"
    assert old_provider.calls == 1
    assert DailyFeedRepository(connection).load(DAY).to_bytes() == old_bytes
    assert (
        b"".join(iter_daily_evidence_stream_jsonl(DailyFeedRepository(connection).load(DAY)))
        == old_jsonl
    )

    later_day = UtcDay(DAY.value + timedelta(days=1))
    later_source, later_staged = _inputs(later_day)
    current_service.run(
        later_day,
        _Provider(later_source, later_staged),
        now=NOW + timedelta(days=1),
    )

    assert DailyFeedRepository(connection).load(DAY).to_bytes() == old_bytes
    assert (
        DailyFeedRepository(connection).load(later_day).header.ordering_version == ORDERING_VERSION
    )


def test_run_day_publishes_every_eligible_tier_and_excludes_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_complete_detector(monkeypatch)
    connection = _connection()
    source, staged = _inputs(DAY)
    provider = _Provider(source, staged)
    service = _service(connection)

    first = service.run(DAY, provider, now=NOW)
    stored_before = DailyFeedRepository(connection).load(DAY).to_bytes()
    repeated = service.run(DAY, provider, now=NOW)
    feed = DailyFeedRepository(connection).load(DAY)

    assert first.candidate_rows == repeated.candidate_rows == 3
    assert provider.calls == 1
    assert feed.to_bytes() == stored_before
    assert b"".join(iter_daily_evidence_stream_jsonl(feed)) == b"".join(
        iter_daily_evidence_stream_jsonl(DailyFeedRepository(connection).load(DAY))
    )
    assert [item.evidence_tier.value for item in feed.episodes] == ["E1", "E2", "E3"]
    assert [item.sequence for item in feed.episodes] == [1, 2, 3]
    assert [item.client_ip for item in feed.episodes].count("10.20.1.2") == 2
    assert "10.20.1.4" not in {item.client_ip for item in feed.episodes}
    assert connection.execute("SELECT count(*) FROM detect.candidate_episode").fetchone() == (0,)
    assert first.storage_bytes is not None and first.storage_bytes >= 4 * 1024**2
    assert connection.execute(
        "SELECT projected_storage_bytes FROM ops.pipeline_run WHERE run_id = ?",
        [first.run_id],
    ).fetchone() == (first.storage_bytes,)


def test_diagnostic_suppressed_ineligible_and_below_threshold_inputs_publish_no_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    below_threshold = _signal(
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

    class _DiagnosticDetector:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def detect(self, day: UtcDay, *_args: object, **_kwargs: object) -> DetectionBatch:
            return DetectionBatch(
                str(day),
                DETECTOR_VERSION,
                (),
                (
                    DetectorDiagnostic(
                        "10.20.1.3",
                        DetectorFamily.FANOUT,
                        DecisionStatus.DIAGNOSTIC,
                        (ReasonCode.DEGRADED_SOURCE_QUALITY,),
                    ),
                    DetectorDiagnostic(
                        "10.20.1.4",
                        DetectorFamily.DNS,
                        DecisionStatus.INELIGIBLE,
                        (ReasonCode.BROAD_EVENT_SUPPRESSED,),
                    ),
                    DetectorDiagnostic(
                        below_threshold.client_ip,
                        below_threshold.family,
                        DecisionStatus.INELIGIBLE,
                        (ReasonCode.INSUFFICIENT_SUPPORT,),
                        near_threshold_signal=below_threshold,
                    ),
                ),
            )

    monkeypatch.setattr(scoring_module, "DetectorEngine", _DiagnosticDetector)
    connection = _connection()
    source, staged = _inputs(DAY)

    report = _service(connection).run(DAY, _Provider(source, staged), now=NOW)
    feed = DailyFeedRepository(connection).load(DAY)

    assert report.candidate_rows == feed.header.episode_count == 0
    assert feed.episodes == ()


def test_feed_failure_rolls_back_history_feed_and_published_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_complete_detector(monkeypatch)
    connection = _connection()
    source, staged = _inputs(DAY)
    original = DailyFeedRepository.publish_in_transaction

    def interrupt(
        repository: DailyFeedRepository,
        feed: DailyEvidenceStream,
        *,
        reserved_bytes: int = 0,
    ) -> FeedPublicationResult:
        original(repository, feed, reserved_bytes=reserved_bytes)
        raise RuntimeError("synthetic interruption after feed insertion")

    monkeypatch.setattr(DailyFeedRepository, "publish_in_transaction", interrupt)

    with pytest.raises(PublicationError, match="publication failed"):
        _service(connection).run(DAY, _Provider(source, staged), now=NOW)

    assert connection.execute("SELECT count(*) FROM history.client_day").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM feed.daily_publication").fetchone() == (0,)
    assert connection.execute("SELECT count(*) FROM feed.candidate_episode").fetchone() == (0,)
    assert connection.execute("SELECT status FROM ops.pipeline_run").fetchone() == ("failed",)


def test_later_day_cannot_mutate_an_earlier_complete_feed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_complete_detector(monkeypatch)
    connection = _connection()
    service = _service(connection)
    first_source, first_staged = _inputs(DAY)
    later_day = UtcDay(DAY.value + timedelta(days=1))
    later_source, later_staged = _inputs(later_day)

    service.run(DAY, _Provider(first_source, first_staged), now=NOW)
    earlier_bytes = DailyFeedRepository(connection).load(DAY).to_bytes()
    service.run(
        later_day,
        _Provider(later_source, later_staged),
        now=NOW + timedelta(days=1),
    )

    assert DailyFeedRepository(connection).load(DAY).to_bytes() == earlier_bytes
    assert DailyFeedRepository(connection).load(later_day).header.episode_count == 3


def test_pre_cutover_published_day_fails_closed_as_incomplete_feed() -> None:
    connection = _connection()
    source, staged = _inputs(DAY)
    service = _service(connection)
    service.run(DAY, _Provider(source, staged), now=NOW)
    connection.execute("DELETE FROM feed.daily_publication WHERE day = ?", [DAY.value])

    with pytest.raises(DayRunError, match="pre-cutover selected output"):
        service.preflight(DAY, now=NOW)


def test_interrupted_manifest_is_failed_before_safe_restart() -> None:
    connection = _connection()
    source, staged = _inputs(DAY)
    connection.execute(
        """
        INSERT INTO ops.pipeline_run (
            run_id, day, status, started_at, source_sql_version, schema_version,
            normalization_version
        ) VALUES (uuid(), ?, 'running', ?, 'source-v1', 5, 'normalization-v1')
        """,
        [DAY.value, NOW - timedelta(hours=1)],
    )

    report = _service(connection).run(DAY, _Provider(source, staged), now=NOW)

    assert report.status == "published"
    assert connection.execute(
        "SELECT status, failure_code FROM ops.pipeline_run ORDER BY started_at"
    ).fetchall() == [
        ("failed", "interrupted_before_publication"),
        ("published", None),
    ]


def test_backfill_helper_is_inclusive_strictly_sequential_and_stops_on_failure() -> None:
    observed: list[str] = []

    def run(day: UtcDay) -> DayRunReport:
        observed.append(str(day))
        return DayRunReport(str(day), "published", None, 0, 0, 0, 0, 0, 0, 0, 0, None)

    reports = run_days_sequentially(UtcDay.parse("2026-07-01"), UtcDay.parse("2026-07-03"), run)

    assert observed == ["2026-07-01", "2026-07-02", "2026-07-03"]
    assert [item.day for item in reports] == observed

    observed.clear()

    def fail_second(day: UtcDay) -> DayRunReport:
        observed.append(str(day))
        if str(day) == "2026-07-02":
            raise RuntimeError("stop")
        return DayRunReport(str(day), "published", None, 0, 0, 0, 0, 0, 0, 0, 0, None)

    with pytest.raises(RuntimeError, match="stop"):
        run_days_sequentially(UtcDay.parse("2026-07-01"), UtcDay.parse("2026-07-03"), fail_second)
    assert observed == ["2026-07-01", "2026-07-02"]


def test_run_manifest_exists_before_source_work_and_failure_is_recorded() -> None:
    connection = _connection()

    class FailingProvider:
        def load(
            self, _day: UtcDay
        ) -> tuple[SourceDayInputs, StagedDay, tuple[DnsDailyObservation, ...]]:
            assert connection.execute("SELECT status FROM ops.pipeline_run").fetchone() == (
                "running",
            )
            raise RuntimeError("source interrupted")

    with pytest.raises(RuntimeError, match="source interrupted"):
        _service(connection).run(DAY, FailingProvider(), now=NOW)

    assert connection.execute("SELECT status, failure_code FROM ops.pipeline_run").fetchone() == (
        "failed",
        "RuntimeError",
    )


def test_population_drift_beyond_tolerance_aborts_the_day_and_publishes_nothing() -> None:
    """Tier 0 invariant 5, on the population the detectors score.

    `drift-gates-v2` counts addresses with a service row and compares a day against the same
    UTC weekday, so the step is set up a week apart and carried by service rows.
    """

    connection = _connection()
    first_source, first_staged = _inputs(DAY)
    _service(connection).run(DAY, _Provider(first_source, first_staged), now=NOW)

    later_day = UtcDay(DAY.value + timedelta(days=7))
    later_source, later_staged = _inputs(later_day)
    # One scored address last week, two today: a 100% step, well past any usable tolerance.
    client = replace(later_staged.client_rows[0], client_ip="10.20.9.9")
    service = replace(later_staged.service_rows[0], client_ip="10.20.9.9")
    later_staged = replace(
        later_staged,
        client_rows=(*later_staged.client_rows, client),
        service_rows=(*later_staged.service_rows, service),
    )

    with pytest.raises(DayRunError, match="population_step beyond tolerance"):
        _service(connection).run(
            later_day,
            _Provider(later_source, later_staged),
            now=NOW + timedelta(days=7),
        )

    assert DailyFeedRepository(connection).day_kind(later_day) is FeedDayKind.ABSENT
    assert connection.execute(
        "SELECT status FROM ops.pipeline_run WHERE day = ?", [later_day.value]
    ).fetchall() == [("failed",)]
    assert connection.execute(
        "SELECT count(*) FROM history.client_day WHERE day = ?", [later_day.value]
    ).fetchone() == (0,)


def test_addresses_without_service_rows_never_move_the_gate() -> None:
    """The `drift-gates-v1` false positive, pinned.

    Every population step that gate reacted to was in addresses carrying only unaddressed rows,
    which no detector scores. Doubling them a week later must not abort the day.
    """

    connection = _connection()
    first_source, first_staged = _inputs(DAY)
    _service(connection).run(DAY, _Provider(first_source, first_staged), now=NOW)

    later_day = UtcDay(DAY.value + timedelta(days=7))
    later_source, later_staged = _inputs(later_day)
    # Zero bytes, so the activity reconciliation still balances; only the address count moves.
    unaddressed = replace(
        later_staged.client_rows[0], client_ip="10.20.9.9", up_bytes=0, down_bytes=0
    )
    later_staged = replace(later_staged, client_rows=(*later_staged.client_rows, unaddressed))

    report = _service(connection).run(
        later_day,
        _Provider(later_source, later_staged),
        now=NOW + timedelta(days=7),
    )

    assert report.status == "published"


def _dns_rows(day: UtcDay, clients: int) -> tuple[DnsDailyObservation, ...]:
    return tuple(
        DnsDailyObservation(
            day=day.value,
            client_ip=f"10.20.5.{index}",
            resolver_id="resolver",
            complete_sessions=50,
            unanswered_sessions=0,
            unsolicited_sessions=0,
            query_packets=100,
            response_packets=100,
            unanswered_query_packets=0,
            unsolicited_response_packets=0,
            weighted_service_nanos=50_000.0,
            weighted_service_sessions=50,
        )
        for index in range(1, clients + 1)
    )


def _scored_policies(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    seen: list[object] = []
    real = scoring_module.score_day

    def capture(*args: object, **kwargs: object) -> object:
        seen.append(kwargs["policies"])
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(pipeline_module, "score_day", capture)
    return seen


@pytest.mark.parametrize(("today_clients", "dns_enabled"), [(1, False), (4, True)])
def test_a_moved_dns_population_disables_dns_and_the_day_still_publishes(
    monkeypatch: pytest.MonkeyPatch, today_clients: int, dns_enabled: bool
) -> None:
    """`drift-gates-v3`: DNS is optional context, so its coverage check aborts nothing."""

    connection = _connection()
    first_source, first_staged = _inputs(DAY)
    _service(connection).run(DAY, _Provider(first_source, first_staged), now=NOW)

    later_day = UtcDay(DAY.value + timedelta(days=7))
    later_source, later_staged = _inputs(later_day)
    dns = (*_dns_rows(DAY, 4), *_dns_rows(later_day, today_clients))
    seen = _scored_policies(monkeypatch)

    report = _service(connection).run(
        later_day,
        _Provider(later_source, later_staged, dns),
        now=NOW + timedelta(days=7),
    )

    assert report.status == "published"
    assert [policy.source_quality.dns_context_available for policy in seen] == [dns_enabled]  # type: ignore[attr-defined]


def test_a_day_within_tolerance_publishes_normally() -> None:
    """The gate must not be a gate that always fires. Same shape twice: nothing moves."""

    connection = _connection()
    first_source, first_staged = _inputs(DAY)
    _service(connection).run(DAY, _Provider(first_source, first_staged), now=NOW)

    later_day = UtcDay(DAY.value + timedelta(days=1))
    later_source, later_staged = _inputs(later_day)
    report = _service(connection).run(
        later_day,
        _Provider(later_source, later_staged),
        now=NOW + timedelta(days=1),
    )

    assert report.status == "published"
    assert report.supported_client_rows == report.client_rows == 1
    assert report.out_of_scope_client_rows == 0


@pytest.mark.parametrize("long_flows_present", [True, False])
def test_an_absent_long_flow_source_reaches_scoring_as_missing_context(
    monkeypatch: pytest.MonkeyPatch, long_flows_present: bool
) -> None:
    """Optional context: an empty `long_flows` never fails the day or lowers a strength,
    but the run says it scored without it instead of implying the context was there."""

    source, staged = _inputs(DAY)
    seen = _scored_policies(monkeypatch)

    report = _service(_connection()).run(
        DAY,
        _Provider(replace(source, long_flow_context_available=long_flows_present), staged),
        now=NOW,
    )

    assert report.status == "published"
    assert [policy.source_quality.long_flow_context_available for policy in seen] == [  # type: ignore[attr-defined]
        long_flows_present
    ]


def test_the_scope_the_census_reports_is_the_population_the_drift_gate_counts() -> None:
    """`behavioural-support-v3` admits exactly the addresses with a service row, the population
    `drift.population_step` gates, so the two can never describe different populations."""

    _, addressed = _inputs(DAY)
    unaddressed = ActivityObservation(
        DAY.bounds.start, "10.20.1.9", "", 0, 0, None, None, None, "Web Browsing", None, None,
        30, 70, 1, 1, 0, (0,),
    )  # fmt: skip
    observations = (
        *(
            ActivityObservation(
                DAY.bounds.start, row.client_ip, "8.8.8.8", 443, 6, "example.com", None, None,
                "web", "browsing", "AS15169", 100, 50, 10, 5, 2, (0,),
            )
            for row in addressed.client_rows
        ),
        unaddressed,
    )  # fmt: skip
    staged = DayAggregator().aggregate(DAY, observations, (), ())
    source, _ = _inputs(DAY)
    source = replace(source, reconciliation=ReconciliationTotals(130, 120, 130, 120))

    report = _service(_connection()).run(DAY, _Provider(source, staged), now=NOW)

    scored = {row.client_ip for row in staged.service_rows}
    assert report.supported_client_rows == len(scored) == 1
    assert report.out_of_scope_client_rows == 1
