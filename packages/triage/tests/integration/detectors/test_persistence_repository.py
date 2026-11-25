from datetime import date, timedelta
from pathlib import Path

import duckdb

from network_behaviour.aggregation import ClientServiceDayRow
from network_behaviour.detectors.persistence import PersistenceHistoryRepository
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.storage.migrations import MigrationRunner
from network_behaviour.time import UtcDay

MIGRATIONS = Path(__file__).parents[3] / "sql" / "migrations"
DAY = UtcDay.parse("2026-07-10")
SERVICE = bytes.fromhex("01" * 16)
SERVICE_COLUMNS = ", ".join(ClientServiceDayRow.__dataclass_fields__)


def _service(day: date, bitmap: ActivityBitmap, category: int = 1) -> ClientServiceDayRow:
    return ClientServiceDayRow(
        day,
        "10.20.1.1",
        SERVICE,
        "domain",
        64500,
        category,
        6,
        443,
        bitmap.value,
        100,
        50,
        5,
        1,
        0,
        0,
        0,
        0.0,
    )


def test_persistence_history_is_pre_d_bounded_and_merges_component_bitmaps() -> None:
    connection = duckdb.connect(":memory:")
    MigrationRunner(MIGRATIONS).apply(connection)
    prior_day = DAY.value - timedelta(days=1)
    rows = (
        _service(prior_day, ActivityBitmap.from_buckets((10,)), 1),
        _service(prior_day, ActivityBitmap.from_buckets((20,)), 2),
        _service(DAY.value, ActivityBitmap.from_buckets((200,)), 1),
    )
    placeholders = ", ".join("?" for _ in ClientServiceDayRow.__dataclass_fields__)
    connection.executemany(
        f"INSERT INTO history.client_service_day ({SERVICE_COLUMNS}) VALUES ({placeholders})",
        [row.values() for row in rows],
    )
    current = _service(DAY.value, ActivityBitmap.from_buckets((10,)))

    history = PersistenceHistoryRepository(connection).load(DAY, (current,))

    assert len(history) == 1
    assert history[0].day == prior_day
    assert history[0].bitmap.active_buckets() == (10, 20)
