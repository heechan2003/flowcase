"""A small but real day: retained history for `day < D`, and staged rows for D.

Synthetic, per `CLAUDE.md`, and sized so the day actually produces episodes. A fixture that scores
an empty population tests only that the machinery runs.

**The relationship family scores a unit against the rest of the day, so the day needs a shape.**
Under `baseline-calibration-v3` this fixture gave every host three services of its own, so every
service was used by exactly one client and every one of the 300 units was equally rare and equally
new. That was adequate while rarity was the absolute `100 * (1 - prevalence)` — one client in a
hundred scored 99.0 and cleared the threshold outright, which is what the previous version of this
docstring was reasoning about. It is not adequate for a tail probability: a population in which
every unit is identical has no tail, so a third of it sat at the top and nothing was unusual
relative to anything. The whole family fell out of the fixture, and §1 measured an implant against
a day where nothing was distinguishable.

So destinations are now shared unevenly, the way they are in the real data (`CASE_STUDY` §11:
845 distinct rarity values over 125,862 units on 2026-08-09):

| Slot | Destination | Clients | Novelty |
|---|---|---|---|
| 0 | one of 5 popular services | ~20 | seen every day of history |
| 1 | one of 20 mid services | ~5 | seen every day of history |
| 2, hosts 0-5 | a service of the host's own | 1 | never seen before today |
| 2, other hosts | one of 12 shared services | ~8 | seen, with the gap varying by host |

Six of 300 units are both first contacts and singleton destinations, so the extreme of each axis
is a small group rather than a third of the day, and an injected implant — a distinct synthetic
destination per host, never seen before — is genuinely unusual against it.

Hosts differ in volume, destination count and occupancy so the permutation strata and the peer
bands have something to separate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa
import pytest

from network_behaviour.aggregation import ClientDayRow, ClientServiceDayRow, StagedDay
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.storage.migrations import MigrationRunner
from network_behaviour.time import UtcDay

MIGRATIONS = Path(__file__).parents[3] / "sql" / "migrations"
DAY = UtcDay.parse("2026-07-10")
HOST_COUNT = 100
HOSTS = tuple(f"10.20.1.{index}" for index in range(1, HOST_COUNT + 1))
# Enough for NORMAL history confidence, which is what keeps the tier ladder off its
# confidence cap, and comfortably past the persistence support gate.
HISTORY_DAYS = 15
CLIENT_COLUMNS = ", ".join(ClientDayRow.__dataclass_fields__)
SERVICE_COLUMNS = ", ".join(ClientServiceDayRow.__dataclass_fields__)


def service_id(index: int) -> bytes:
    return index.to_bytes(4, "big") + bytes(12)


# Hosts whose third destination is theirs alone and new today. Kept small on purpose: it is the
# extreme of both relationship axes, and an extreme that holds a third of the day is not one.
FIRST_CONTACT_HOSTS = 6


def day_d_service_indices(position: int) -> tuple[int, ...]:
    """The three destinations host `position` contacts on day D, by shared popularity."""
    popular = position % 5
    mid = 10 + position % 20
    own = position < FIRST_CONTACT_HOSTS
    third = 1_000 + position if own else 100 + position % 12
    return (popular, mid, third)


def history_service_indices(position: int, offset: int) -> tuple[int, ...]:
    """The same host's destinations `offset` days before D.

    Slots 0 and 1 are present throughout, so they are familiar. The third is withheld from the
    first-contact hosts entirely and from the others for a stretch that varies by host, which is
    what gives the novelty axis a spread of `days_since_seen` rather than two values.
    """
    popular, mid, third = day_d_service_indices(position)
    if position < FIRST_CONTACT_HOSTS or offset <= position % 7:
        return (popular, mid)
    return (popular, mid, third)


def client_row(
    day: date,
    client_ip: str,
    scale: int,
    *,
    buckets: int = 60,
    servers: int = 12,
) -> ClientDayRow:
    return ClientDayRow(
        day=day,
        client_ip=client_ip,
        up_bytes=scale * 1_000,
        down_bytes=scale * 2_000,
        up_packets=scale * 10,
        down_packets=scale * 20,
        flow_count=scale * 5,
        active_minutes=min(1440, buckets * 5),
        active_5m_buckets=buckets,
        unique_servers=servers,
        unique_services=max(2, servers // 2),
        unique_routes=max(2, servers // 2),
        unique_asns=3,
        unique_port_groups=2,
        top_service_up_bytes=scale * 400,
        top_service_total_bytes=scale * 900,
        opaque_bytes=scale * 10,
        p95_5m_up_bytes=float(scale * 40),
        max_5m_up_bytes=scale * 90,
        p95_5m_unique_servers=3.0,
        max_5m_unique_servers=6,
        p95_5m_unique_services=2.0,
        max_5m_unique_services=4,
        p95_5m_unique_port_groups=1.0,
        max_5m_unique_port_groups=2,
        p95_bucket_up_rate_p95_bps=float(scale * 100),
        max_bucket_up_rate_p95_bps=float(scale * 200),
        large_flow_count=1 if scale % 3 == 0 else 0,
        large_flow_up_bytes=scale * 100 if scale % 3 == 0 else 0,
        max_large_flow_bytes=scale * 500 if scale % 3 == 0 else 0,
        max_large_flow_duration_sec=90.0 if scale % 3 == 0 else 0.0,
    )


def service_row(
    day: date,
    client_ip: str,
    index: int,
    *,
    first_bucket: int = 0,
    span: int = 8,
) -> ClientServiceDayRow:
    bitmap = ActivityBitmap.from_buckets(tuple(range(first_bucket, min(288, first_bucket + span))))
    return ClientServiceDayRow(
        day=day,
        client_ip=client_ip,
        service_id=service_id(index),
        service_basis="domain",
        asn_id=64500 + (index % 4),
        application_category_id=1 + (index % 3),
        transport_protocol=6,
        port_group=443,
        active_5m_bitmap=bitmap.value,
        up_bytes=1_000 * (index + 1),
        down_bytes=2_000 * (index + 1),
        flow_count=20 + index,
        unique_servers=1,
        large_flow_count=1 if index % 4 == 0 else 0,
        large_flow_up_bytes=5_000 if index % 4 == 0 else 0,
        max_large_flow_bytes=9_000 if index % 4 == 0 else 0,
        max_large_flow_duration_sec=120.0 if index % 4 == 0 else 0.0,
    )


def history_rows() -> tuple[tuple[ClientDayRow, ...], tuple[ClientServiceDayRow, ...]]:
    """`day < D` only. See the module docstring for the popularity and novelty shape."""
    clients: list[ClientDayRow] = []
    services: list[ClientServiceDayRow] = []
    for offset in range(HISTORY_DAYS, 0, -1):
        past = DAY.value - timedelta(days=offset)
        for position, host in enumerate(HOSTS):
            clients.append(
                client_row(
                    past,
                    host,
                    100 + position * 7 + offset,
                    buckets=20 + (position % 12) * 4,
                    servers=6 + (position % 12),
                )
            )
            for index in history_service_indices(position, offset):
                services.append(service_row(past, host, index, first_bucket=(position * 12) % 240))
    return tuple(clients), tuple(services)


def staged_day() -> StagedDay:
    """Day D, ordered exactly as `DayAggregator.finish()` would order it."""
    clients = tuple(
        client_row(
            DAY.value,
            host,
            # One host with a step change in volume, so the transfer family has something to see.
            100 + position * 7 + (9_000 if position == 0 else 0),
            buckets=20 + (position % 12) * 4,
            servers=6 + (position % 12),
        )
        for position, host in enumerate(HOSTS)
    )
    services = tuple(
        service_row(DAY.value, host, index, first_bucket=(position * 12) % 240)
        for position, host in enumerate(HOSTS)
        for index in day_d_service_indices(position)
    )
    return StagedDay(
        DAY,
        tuple(sorted(clients, key=lambda row: row.client_ip)),
        tuple(sorted(services, key=_service_sort_key)),
    )


def bulk_insert(
    connection: duckdb.DuckDBPyConnection,
    table: str,
    rows: tuple[ClientDayRow, ...] | tuple[ClientServiceDayRow, ...],
) -> None:
    """Append through Arrow. Row-at-a-time inserts cost minutes at this fixture's size."""
    if not rows:
        return
    names = list(type(rows[0]).__dataclass_fields__)
    columns: dict[str, list[Any]] = {name: [getattr(row, name) for row in rows] for name in names}
    connection.register("_bulk_rows", pa.table(columns))
    try:
        connection.execute(f"INSERT INTO {table} SELECT * FROM _bulk_rows")
    finally:
        connection.unregister("_bulk_rows")


def build_database(connection: duckdb.DuckDBPyConnection, *, include_day_d: bool) -> None:
    MigrationRunner(MIGRATIONS).apply(connection)
    clients, services = history_rows()
    if include_day_d:
        staged = staged_day()
        clients = (*clients, *staged.client_rows)
        services = (*services, *staged.service_rows)
    bulk_insert(connection, "history.client_day", clients)
    bulk_insert(connection, "history.client_service_day", services)


def _service_sort_key(row: ClientServiceDayRow) -> tuple[object, ...]:
    return (
        row.client_ip,
        row.service_id,
        row.asn_id,
        row.application_category_id,
        row.transport_protocol,
        row.port_group,
    )


@dataclass(frozen=True, slots=True)
class Fixture:
    connection: duckdb.DuckDBPyConnection
    day: UtcDay
    staged: StagedDay


# Session-scoped: nothing in the evaluation harness writes to it, which `test_harness.py`
# asserts rather than assumes.
@pytest.fixture(scope="session")
def fixture() -> Fixture:
    connection = duckdb.connect(":memory:")
    build_database(connection, include_day_d=False)
    return Fixture(connection, DAY, staged_day())
