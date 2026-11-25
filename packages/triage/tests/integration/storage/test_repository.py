from pathlib import Path

import pytest

from network_behaviour.storage.repository import DuckDbStore, StorageConfig

MIGRATIONS = Path(__file__).parents[3] / "sql" / "migrations"


def test_repository_migrates_and_reopens_one_duckdb_file(tmp_path: Path) -> None:
    database = tmp_path / "nested" / "network_behaviour.duckdb"
    config = StorageConfig(database, MIGRATIONS)

    with DuckDbStore(config) as store:
        assert store.connection.execute(
            "SELECT max(version) FROM _schema_migrations"
        ).fetchone() == (10,)
    with DuckDbStore(config) as reopened:
        assert reopened.connection.execute(
            "SELECT count(*) FROM history.client_day"
        ).fetchone() == (0,)


def test_repository_connection_is_unavailable_outside_lifecycle(tmp_path: Path) -> None:
    store = DuckDbStore(StorageConfig(tmp_path / "network_behaviour.duckdb", MIGRATIONS))

    with pytest.raises(RuntimeError, match="not open"):
        _ = store.connection
    assert store.open() == 10
    with pytest.raises(RuntimeError, match="already open"):
        store.open()
    store.close()


def test_storage_config_requires_runtime_path() -> None:
    with pytest.raises(ValueError, match="DUCKDB_PATH"):
        StorageConfig.from_env({})


@pytest.mark.parametrize("schema", ["history", "detect", "feed", "review", "ops"])
def test_storage_config_rejects_catalog_schema_name_collision(tmp_path: Path, schema: str) -> None:
    with pytest.raises(ValueError, match="collide"):
        StorageConfig(tmp_path / f"{schema}.duckdb", MIGRATIONS)
