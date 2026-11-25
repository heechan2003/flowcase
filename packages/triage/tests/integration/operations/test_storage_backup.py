from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import duckdb
import pytest

from network_behaviour.detectors import DETECTOR_VERSION
from network_behaviour.feed import STREAM_SCHEMA_VERSION, DailyEvidenceStream, StreamHeader
from network_behaviour.operations.config import StorageControls
from network_behaviour.operations.storage import (
    BackupRestoreError,
    create_backup,
    restore_backup,
    storage_report,
)
from network_behaviour.ranking import ORDERING_VERSION
from network_behaviour.storage.feed import DailyFeedRepository
from network_behaviour.storage.migrations import MigrationRunner
from network_behaviour.time import UtcDay

ROOT = Path(__file__).parents[3]
MIGRATIONS = ROOT / "sql" / "migrations"


def test_backup_and_restore_are_verified_and_non_overwriting(tmp_path: Path) -> None:
    database = tmp_path / "source.duckdb"
    backup = tmp_path / "backup.duckdb"
    restored = tmp_path / "restored.duckdb"
    connection = duckdb.connect(str(database))
    MigrationRunner(MIGRATIONS).apply(connection)
    connection.execute(
        """
        INSERT INTO history.client_day
        SELECT DATE '2026-07-10', '192.0.2.1',
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        """
    )
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
    expected_feed = feed.to_bytes()

    create_backup(connection, database, backup)
    with pytest.raises(BackupRestoreError, match="already exists"):
        create_backup(connection, database, backup)
    connection.close()
    restore_backup(backup, restored, MIGRATIONS)

    restored_connection = duckdb.connect(str(restored))
    try:
        assert restored_connection.execute(
            "SELECT count(*) FROM history.client_day"
        ).fetchone() == (1,)
        feed_repository = DailyFeedRepository(restored_connection)
        assert feed_repository.load(day).to_bytes() == expected_feed
        assert feed_repository.publish(feed).idempotent
        report = storage_report(restored_connection, StorageControls(40 * 1024**3, 45 * 1024**3))
        assert report.history_client_rows == 1
        assert report.candidate_rows == 0
        assert not report.alert and not report.stop
    finally:
        restored_connection.close()


def test_restore_refuses_existing_destination(tmp_path: Path) -> None:
    source = tmp_path / "backup.duckdb"
    output = tmp_path / "output.duckdb"
    source.touch()
    output.touch()

    with pytest.raises(BackupRestoreError, match="already exists"):
        restore_backup(source, output, MIGRATIONS)
