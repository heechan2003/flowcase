from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import duckdb
import pytest

from network_behaviour import __version__
from network_behaviour.cli import build_parser, main
from network_behaviour.detectors import DETECTOR_VERSION
from network_behaviour.feed import STREAM_SCHEMA_VERSION, DailyEvidenceStream, StreamHeader
from network_behaviour.operations.pipeline import DayRunReport
from network_behaviour.ranking import ORDERING_VERSION
from network_behaviour.storage.feed import DailyFeedRepository
from network_behaviour.storage.migrations import MigrationRunner
from network_behaviour.time import UtcDay


def test_package_has_version() -> None:
    assert __version__ == "0.2.0"


def test_help_describes_publisher_scope() -> None:
    help_text = build_parser().format_help()

    assert "daily behavioural candidate feed" in help_text


def test_empty_command_is_successful() -> None:
    assert main([]) == 0


def test_help_exposes_only_the_product_p0_publisher_operation() -> None:
    help_text = build_parser().format_help()

    assert "run-day" in help_text
    for command in (
        "source-check",
        "backfill",
        "replay",
        "list-candidates",
        "inspect-candidate",
        "review-candidate",
        "export-candidates",
        "evaluation-report",
        "storage-report",
        "backup",
        "restore",
    ):
        assert command not in help_text


def test_run_day_dry_run_is_offline_and_requires_no_queue_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = Path(__file__).parents[2]
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(tmp_path / "triage.duckdb"))
    monkeypatch.setenv("NETWORK_BEHAVIOUR_MIGRATION_DIR", str(root / "sql" / "migrations"))
    monkeypatch.setenv("NETWORK_BEHAVIOUR_LOCK_PATH", str(tmp_path / "triage.lock"))
    monkeypatch.setenv("NETWORK_BEHAVIOUR_MAIN_QUEUE_SIZE", "invalid-and-ignored")
    monkeypatch.setenv("NETWORK_BEHAVIOUR_PER_CLIENT_CAP", "0")
    monkeypatch.setenv("NETWORK_BEHAVIOUR_PER_FAMILY_CAP", "0")
    monkeypatch.setenv("NETWORK_BEHAVIOUR_RANDOM_AUDIT_SIZE", "-1")
    monkeypatch.setenv("NETWORK_BEHAVIOUR_BELOW_THRESHOLD_AUDIT_SIZE", "-1")

    assert main(["run-day", "--day", "2026-07-10", "--dry-run"]) == 0

    assert "status: ready" in capsys.readouterr().out


def test_published_run_day_streams_the_stored_feed_without_clickhouse_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    root = Path(__file__).parents[2]
    database = tmp_path / "triage.duckdb"
    migrations = root / "sql" / "migrations"
    day = UtcDay.parse("2026-07-10")
    run_id = uuid4()
    feed = DailyEvidenceStream(
        StreamHeader(
            STREAM_SCHEMA_VERSION,
            str(day),
            datetime(2026, 7, 11, 8, tzinfo=UTC),
            run_id,
            DETECTOR_VERSION,
            ORDERING_VERSION,
            0,
        ),
        (),
    )
    connection = duckdb.connect(str(database))
    try:
        MigrationRunner(migrations).apply(connection)
        connection.execute(
            """
            INSERT INTO ops.pipeline_run (
                run_id, day, status, started_at, source_sql_version, schema_version,
                normalization_version
            ) VALUES (?, ?, 'running', ?, 'source-v1', 7, 'normalization-v1')
            """,
            [run_id, day.value, feed.header.published_at],
        )
        DailyFeedRepository(connection).publish(feed)
    finally:
        connection.close()

    class _PublishedService:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def preflight(self, requested_day: UtcDay) -> DayRunReport:
            assert requested_day == day
            return DayRunReport(str(day), "already_published", run_id, 0, 0, 0, 0, 0, 0, 0, 0, None)

    monkeypatch.setattr("network_behaviour.cli.DayRunService", _PublishedService)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(database))
    monkeypatch.setenv("NETWORK_BEHAVIOUR_MIGRATION_DIR", str(migrations))
    monkeypatch.setenv("NETWORK_BEHAVIOUR_LOCK_PATH", str(tmp_path / "triage.lock"))
    monkeypatch.delenv("CLICKHOUSE_HOST", raising=False)
    monkeypatch.delenv("CLICKHOUSE_USER", raising=False)
    monkeypatch.delenv("CLICKHOUSE_PASSWORD", raising=False)

    assert main(["run-day", "--day", str(day)]) == 0

    output = capsysbinary.readouterr().out
    assert output == (
        b'{"day":"2026-07-10","detector_version":"primary-detectors-v9",'
        b'"episode_count":0,"ordering_version":"episode-ordering-v4",'
        b'"published_at":"2026-07-11T08:00:00+00:00","record_type":"header",'
        b'"run_id":"' + str(run_id).encode("ascii") + b'",'
        b'"stream_encoding_version":"daily-evidence-stream-jsonl-v2",'
        b'"stream_schema_version":"daily-evidence-stream-v2"}\n'
    )
