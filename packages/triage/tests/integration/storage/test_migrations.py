from pathlib import Path
from shutil import copytree
from uuid import uuid4

import duckdb
import pytest

from network_behaviour.storage.migrations import (
    COMPATIBLE_SCHEMA_VERSIONS,
    MigrationError,
    MigrationRunner,
)

MIGRATIONS = Path(__file__).parents[3] / "sql" / "migrations"


def _scalar(connection: duckdb.DuckDBPyConnection, query: str) -> object:
    row = connection.execute(query).fetchone()
    assert row is not None
    return row[0]


def _schema_snapshot(connection: duckdb.DuckDBPyConnection) -> tuple[object, ...]:
    columns = connection.execute(
        """
        SELECT schema_name, table_name, column_name, data_type, is_nullable, column_default
        FROM duckdb_columns()
        WHERE NOT internal AND table_name <> '_schema_migrations'
        ORDER BY schema_name, table_name, column_index
        """
    ).fetchall()
    constraints = connection.execute(
        """
        SELECT schema_name, table_name, constraint_type, constraint_text
        FROM duckdb_constraints()
        WHERE table_name <> '_schema_migrations'
        ORDER BY schema_name, table_name, constraint_index
        """
    ).fetchall()
    return tuple(columns), tuple(constraints)


def test_fresh_and_upgraded_database_have_identical_schema() -> None:
    runner = MigrationRunner(MIGRATIONS)
    fresh = duckdb.connect(":memory:")
    upgraded = duckdb.connect(":memory:")

    assert runner.apply(fresh) == 10
    assert runner.apply(upgraded, target_version=2) == 2
    assert runner.apply(upgraded) == 10

    assert _schema_snapshot(fresh) == _schema_snapshot(upgraded)


def test_migrations_are_idempotent_and_integrity_checked(tmp_path: Path) -> None:
    migration_copy = tmp_path / "migrations"
    copytree(MIGRATIONS, migration_copy)
    runner = MigrationRunner(migration_copy)
    connection = duckdb.connect(":memory:")

    assert runner.apply(connection) == 10
    assert runner.apply(connection) == 10
    with (migration_copy / "0001_history.sql").open("a", encoding="utf-8") as file:
        file.write("\n-- changed after application\n")

    with pytest.raises(MigrationError, match="integrity mismatch"):
        runner.apply(connection)


def test_failed_migration_rolls_back_schema_and_version(tmp_path: Path) -> None:
    migration_root = tmp_path / "migrations"
    migration_root.mkdir()
    (migration_root / "0001_first.sql").write_text(
        "CREATE TABLE first_table (value INTEGER);", encoding="utf-8"
    )
    (migration_root / "0002_broken.sql").write_text(
        "CREATE TABLE should_rollback (value INTEGER); INVALID SQL;", encoding="utf-8"
    )
    connection = duckdb.connect(":memory:")

    with pytest.raises(MigrationError, match="0002"):
        MigrationRunner(migration_root).apply(connection)

    assert _scalar(connection, "SELECT count(*) FROM _schema_migrations WHERE version = 2") == 0
    assert (
        _scalar(
            connection,
            "SELECT count(*) FROM duckdb_tables() WHERE table_name = 'should_rollback'",
        )
        == 0
    )


def test_released_phase8_baseline_checksum_upgrades_to_feed_schema() -> None:
    connection = duckdb.connect(":memory:")
    runner = MigrationRunner(MIGRATIONS)
    assert runner.apply(connection, target_version=6) == 6
    cohort_id = uuid4()
    connection.execute(
        """
        INSERT INTO review.baseline_cohort_item VALUES (
            ?, DATE '2026-07-10', '192.0.2.10', 'baseline-selection-v1',
            TIMESTAMPTZ '2026-07-11 08:00:00+00', 10, 1, NULL,
            TIMESTAMPTZ '2026-07-18 08:00:00+00',
            TIMESTAMPTZ '2026-07-25 08:00:00+00'
        )
        """,
        [cohort_id],
    )
    connection.execute(
        "UPDATE _schema_migrations SET checksum = ? WHERE version = 6",
        ["6491769659f29877c276c2a58bf1c374fe5c041961395b5a6fee9a8502dd4513"],
    )

    assert runner.apply(connection) == 10
    assert connection.execute(
        "SELECT name FROM _schema_migrations WHERE version = 7"
    ).fetchone() == ("phase8c_daily_feed",)
    assert connection.execute("SELECT count(*) FROM feed.daily_publication").fetchone() == (0,)
    assert connection.execute(
        """
        SELECT client_ip, selection_version, queue_size, top_volume_rank, top_fanout_rank
        FROM review.baseline_cohort_item WHERE cohort_item_id = ?
        """,
        [cohort_id],
    ).fetchone() == ("192.0.2.10", "baseline-selection-v1", 10, 1, None)


def test_retained_blob_width_constraints_fail_closed() -> None:
    connection = duckdb.connect(":memory:")
    MigrationRunner(MIGRATIONS).apply(connection)

    with pytest.raises(duckdb.ConstraintException):
        connection.execute(
            """
            INSERT INTO history.client_service_day VALUES (
                DATE '2026-07-10', '192.0.2.10', blob 'too-short', 'domain',
                0, 0, 6, 443, repeat('00', 36)::BLOB,
                0, 0, 0, 0, 0, 0, 0, 0
            )
            """
        )


def test_phase6_evidence_migration_preserves_rows_and_allows_sparse_context() -> None:
    connection = duckdb.connect(":memory:")
    runner = MigrationRunner(MIGRATIONS)
    runner.apply(connection, target_version=3)
    episode_id = uuid4()
    connection.execute(
        """
        INSERT INTO detect.candidate_evidence VALUES (
            ?, 0, 'up_bytes', 10, 1, 2, 99, 99, 99, 10
        )
        """,
        [episode_id],
    )

    assert runner.apply(connection) == 10
    assert connection.execute(
        "SELECT metric_code FROM detect.candidate_evidence WHERE candidate_id = ?",
        [episode_id],
    ).fetchone() == ("up_bytes",)
    connection.execute(
        """
        INSERT INTO detect.candidate_evidence VALUES (
            ?, 17, 'mean_service_nanos', 10, NULL, NULL, NULL, NULL, NULL, NULL
        )
        """,
        [uuid4()],
    )


def test_phase8c_migration_preserves_and_explicitly_marks_legacy_selected_rows() -> None:
    connection = duckdb.connect(":memory:")
    runner = MigrationRunner(MIGRATIONS)
    runner.apply(connection, target_version=5)
    episode_id = uuid4()
    connection.execute(
        """
        INSERT INTO detect.candidate_episode (
            candidate_id, run_id, day, detected_at, client_ip, family,
            episode_start, episode_end, service_id, asn_id, family_strength,
            priority_tier, priority_score, evidence_group_mask,
            history_confidence, data_quality_confidence, reason_code_mask,
            detector_version, selection_stratum, investigate_by,
            source_detail_expires_at
        ) VALUES (
            ?, ?, DATE '2026-07-10', TIMESTAMPTZ '2026-07-11 08:00:00+00',
            '192.0.2.10', 'transfer', TIMESTAMPTZ '2026-07-10 01:00:00+00',
            TIMESTAMPTZ '2026-07-10 01:05:00+00', NULL, NULL, 99, 'P1', 90,
            1, 'normal', 'normal', 1, 'primary-detectors-v2/episode-ranking-v1',
            'main_queue', TIMESTAMPTZ '2026-07-18 08:00:00+00',
            TIMESTAMPTZ '2026-07-25 08:00:00+00'
        )
        """,
        [episode_id, uuid4()],
    )
    connection.execute(
        """
        INSERT INTO detect.candidate_evidence VALUES (
            ?, 0, 'up_bytes', 1000, 100, 110, 95, 94, 94, NULL
        )
        """,
        [episode_id],
    )

    assert runner.apply(connection) == 10
    assert connection.execute(
        """
        SELECT publication_kind, candidate_id
        FROM detect.legacy_selected_episode
        """
    ).fetchone() == ("legacy_selected", episode_id)
    assert connection.execute(
        """
        SELECT publication_kind, candidate_id, metric_code
        FROM detect.legacy_selected_evidence
        """
    ).fetchone() == ("legacy_selected", episode_id, "up_bytes")
    assert connection.execute("SELECT count(*) FROM feed.daily_publication").fetchone() == (0,)


def test_schema_contains_only_product_and_immutable_compatibility_tables() -> None:
    connection = duckdb.connect(":memory:")
    MigrationRunner(MIGRATIONS).apply(connection)

    tables = {
        str(row[0])
        for row in connection.execute(
            """
            SELECT schema_name || '.' || table_name
            FROM duckdb_tables()
            WHERE NOT internal AND table_name <> '_schema_migrations'
            """
        ).fetchall()
    }

    assert tables == {
        "history.client_day",
        "history.client_service_day",
        "detect.candidate_episode",
        "detect.candidate_evidence",
        "feed.daily_publication",
        # v1 tables: retained read-only so days published under daily-candidate-feed-v1
        # still reconstruct to the exact bytes their stored digest was taken over.
        "feed.candidate_episode",
        "feed.candidate_evidence",
        # v2 tables: everything published from daily-evidence-stream-v2 onward.
        "feed.episode",
        "feed.episode_evidence",
        "review.candidate_disposition",
        "review.candidate_review_session",
        "review.baseline_cohort_item",
        "review.baseline_disposition",
        "review.baseline_review_session",
        "ops.pipeline_run",
    }


def test_retained_tables_have_exact_authoritative_columns() -> None:
    connection = duckdb.connect(":memory:")
    MigrationRunner(MIGRATIONS).apply(connection)
    observed = {
        (str(schema), str(table)): {
            str(column)
            for (column,) in connection.execute(
                """
            SELECT column_name FROM duckdb_columns()
            WHERE schema_name = ? AND table_name = ? ORDER BY column_index
            """,
                [schema, table],
            ).fetchall()
        }
        for schema, table in (
            ("history", "client_day"),
            ("history", "client_service_day"),
        )
    }

    assert observed[("history", "client_day")] == {
        "day",
        "client_ip",
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
    }
    assert observed[("history", "client_service_day")] == {
        "day",
        "client_ip",
        "service_id",
        "service_basis",
        "asn_id",
        "application_category_id",
        "transport_protocol",
        "port_group",
        "active_5m_bitmap",
        "up_bytes",
        "down_bytes",
        "flow_count",
        "unique_servers",
        "large_flow_count",
        "large_flow_up_bytes",
        "max_large_flow_bytes",
        "max_large_flow_duration_sec",
    }


def test_schema_retains_no_forbidden_raw_detail_columns() -> None:
    connection = duckdb.connect(":memory:")
    MigrationRunner(MIGRATIONS).apply(connection)
    columns = {
        str(row[0])
        for row in connection.execute(
            "SELECT lower(column_name) FROM duckdb_columns() WHERE NOT internal"
        ).fetchall()
    }

    assert columns.isdisjoint(
        {
            "server_ip",
            "domain",
            "root_domain",
            "sni",
            "dns",
            "subscriber_id",
            "client_tag",
            "client_group",
            "network_tag",
            "evidence_prose",
        }
    )


def test_baseline_version_migration_preserves_published_runs_as_unrecorded() -> None:
    """The thirty-seven days already in the archive predate the column and must survive it.

    They cannot be re-derived — source detail expires in roughly fifteen days — so a migration
    that stranded them would be irreversible. Null means "published before baseline versioning",
    which the compatibility check accepts.
    """
    connection = duckdb.connect(":memory:")
    runner = MigrationRunner(MIGRATIONS)
    runner.apply(connection, target_version=8)
    run_id = uuid4()
    connection.execute(
        """
        INSERT INTO ops.pipeline_run (
            run_id, day, status, started_at, source_sql_version, schema_version,
            normalization_version, detector_version
        ) VALUES (
            ?, DATE '2026-07-10', 'published', TIMESTAMPTZ '2026-07-11 08:00:00+00',
            'phase3-source-bundle-v3', 8, 'normalization-bundle-v1',
            'primary-detectors-v2/episode-ordering-v3'
        )
        """,
        [run_id],
    )

    assert runner.apply(connection) == 10
    assert connection.execute(
        "SELECT status, detector_version, baseline_version FROM ops.pipeline_run WHERE run_id = ?",
        [run_id],
    ).fetchone() == (
        "published",
        "primary-detectors-v2/episode-ordering-v3",
        None,
    )


def test_population_census_migration_preserves_published_runs_as_uncounted() -> None:
    """Days published before the census keep NULL: nothing counted what their gate excluded."""
    connection = duckdb.connect(":memory:")
    runner = MigrationRunner(MIGRATIONS)
    runner.apply(connection, target_version=9)
    run_id = uuid4()
    connection.execute(
        """
        INSERT INTO ops.pipeline_run (
            run_id, day, status, started_at, source_sql_version, schema_version,
            normalization_version, staged_client_rows
        ) VALUES (
            ?, DATE '2026-07-10', 'published', TIMESTAMPTZ '2026-07-11 08:00:00+00',
            'phase3-source-bundle-v3', 9, 'normalization-bundle-v1', 12234
        )
        """,
        [run_id],
    )

    assert runner.apply(connection) == 10
    assert connection.execute(
        """
        SELECT staged_client_rows, supported_client_rows, out_of_scope_client_rows,
               population_definition_version
        FROM ops.pipeline_run WHERE run_id = ?
        """,
        [run_id],
    ).fetchone() == (12234, None, None, None)


def test_every_released_schema_version_from_0005_streams_back() -> None:
    """A new migration joins `COMPATIBLE_SCHEMA_VERSIONS`, or every day it writes is stranded."""
    latest = MigrationRunner(MIGRATIONS).discover()[-1].version
    assert set(range(5, latest + 1)) == COMPATIBLE_SCHEMA_VERSIONS
