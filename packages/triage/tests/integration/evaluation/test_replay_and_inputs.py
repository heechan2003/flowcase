"""Seeding the leakage boundary, and reading day D back out of the retained grains."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import duckdb
import pytest
from day_fixture import DAY, MIGRATIONS, Fixture, build_database

from network_behaviour.evaluation.inputs import (
    InputsError,
    load_from_history,
    open_product_database,
)
from network_behaviour.evaluation.replay import ReplaySeedError, seed_history_before
from network_behaviour.evaluation.volume import (
    VolumeUnavailableError,
    measure_volume,
    project_growth,
)
from network_behaviour.publication import StorageGuard
from network_behaviour.time import UtcDay


@pytest.fixture(scope="session")
def production(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A file-backed database including day D, because seeding attaches one by path.

    Session-scoped and only ever read after it is built; the seeding tests write their replays
    into their own `tmp_path`.
    """
    path = tmp_path_factory.mktemp("production") / "production.duckdb"
    connection = duckdb.connect(str(path))
    build_database(connection, include_day_d=True)
    connection.close()
    return path


def test_seeding_copies_history_strictly_before_the_day(
    fixture: Fixture, production: Path, tmp_path: Path
) -> None:
    report = seed_history_before(
        production, tmp_path / "replay.duckdb", fixture.day, migrations=MIGRATIONS
    )

    assert report.last_day is not None and report.last_day < fixture.day.value
    with duckdb.connect(str(report.replay_path)) as replay:
        row = replay.execute(
            "SELECT count(*) FROM history.client_day WHERE day >= ?", [fixture.day.value]
        ).fetchone()
    assert row is not None and row[0] == 0


def test_held_out_days_are_absent_from_the_seeded_history(
    fixture: Fixture, production: Path, tmp_path: Path
) -> None:
    held_out = fixture.day.value - timedelta(days=3)
    report = seed_history_before(
        production,
        tmp_path / "replay.duckdb",
        fixture.day,
        migrations=MIGRATIONS,
        exclude_days=(held_out,),
    )

    assert report.excluded_days == (held_out,)
    with duckdb.connect(str(report.replay_path)) as replay:
        row = replay.execute(
            "SELECT count(*) FROM history.client_day WHERE day = ?", [held_out]
        ).fetchone()
    assert row is not None and row[0] == 0
    assert "held-out days" in report.render()


def test_holding_out_a_day_at_or_after_the_boundary_is_refused(
    fixture: Fixture, production: Path, tmp_path: Path
) -> None:
    with pytest.raises(ReplaySeedError, match="already outside"):
        seed_history_before(
            production,
            tmp_path / "replay.duckdb",
            fixture.day,
            migrations=MIGRATIONS,
            exclude_days=(fixture.day.value,),
        )


def test_seeding_refuses_to_overwrite_an_existing_replay(
    fixture: Fixture, production: Path, tmp_path: Path
) -> None:
    target = tmp_path / "replay.duckdb"
    seed_history_before(production, target, fixture.day, migrations=MIGRATIONS)

    with pytest.raises(ReplaySeedError, match="already exists"):
        seed_history_before(production, target, fixture.day, migrations=MIGRATIONS)


def test_day_d_round_trips_through_the_retained_grains(fixture: Fixture, production: Path) -> None:
    with duckdb.connect(str(production), read_only=True) as connection:
        inputs = load_from_history(connection, fixture.day)

    assert inputs.staged.client_rows == fixture.staged.client_rows
    assert inputs.staged.service_rows == fixture.staged.service_rows
    assert inputs.query_count == 0
    assert any("DNS" in caveat for caveat in inputs.caveats)


def test_an_unpublished_day_says_so_rather_than_returning_an_empty_day(
    production: Path,
) -> None:
    with (
        duckdb.connect(str(production), read_only=True) as connection,
        pytest.raises(InputsError, match="no retained history"),
    ):
        load_from_history(connection, UtcDay.parse("2020-01-01"))


def test_growth_is_projected_from_the_retained_grains_against_the_ceiling(
    production: Path,
) -> None:
    with duckdb.connect(str(production), read_only=True) as connection:
        growth = project_growth(connection, StorageGuard())

    assert growth is not None
    assert growth.retained_client_rows > 0
    assert growth.projected_bytes_at_retention > 0
    assert "365-day retention" in growth.render()


def test_a_range_without_a_weekend_is_not_called_a_projection(production: Path) -> None:
    with duckdb.connect(str(production), read_only=True) as connection:
        report = measure_volume(connection, UtcDay.parse("2026-07-06"), UtcDay.parse("2026-07-08"))

    assert not report.coverage.sufficient
    assert "NOT a week including a weekend" in report.render()


def test_reading_the_product_database_never_migrates_it(production: Path) -> None:
    """A measurement that upgrades the schema of the store it measures is not a measurement.

    The product database on a deployment can sit at an older schema than the checkout. Opening it
    through `DuckDbStore` would apply every pending migration as a side effect of reading a day.
    """
    with duckdb.connect(str(production)) as connection:
        connection.execute("DELETE FROM _schema_migrations WHERE version = 8")
        before = connection.execute("SELECT max(version) FROM _schema_migrations").fetchone()

    with open_product_database(production) as connection:
        load_from_history(connection, DAY)

    with duckdb.connect(str(production), read_only=True) as connection:
        after = connection.execute("SELECT max(version) FROM _schema_migrations").fetchone()
    assert before == after


def test_a_database_without_the_v2_stream_refuses_section_four(tmp_path: Path) -> None:
    path = tmp_path / "old.duckdb"
    with duckdb.connect(str(path)) as connection:
        connection.execute("CREATE SCHEMA feed")

    with (
        open_product_database(path) as connection,
        pytest.raises(VolumeUnavailableError, match="predates migration 0008"),
    ):
        measure_volume(connection, DAY, DAY)


def test_a_missing_product_database_is_named_rather_than_created(tmp_path: Path) -> None:
    absent = tmp_path / "absent.duckdb"

    with pytest.raises(InputsError, match="not found"), open_product_database(absent):
        pass
    assert not absent.exists()
