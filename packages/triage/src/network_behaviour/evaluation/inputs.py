"""Where a harness gets its day D staged rows.

Two routes, and the choice matters enough that every report states which was used.

**Retained history (default).** `history.client_day` and `history.client_service_day` *are* the
staged grains — publication persists them unchanged, which is why `replay_day.sh` can seed a
replay from them. Reading day D back costs no live query, works on any published day, and works
after the source's detail has expired (the original source kept about fifteen days, `CASE_STUDY`
§1; here a day stays while it is loaded, unless `NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS` sets a
retention).

Two things it cannot return, both stated in `HistoryInputs.caveats`:

- **No DNS observations.** DNS is queried directly and no copy is retained, by contract. The DNS
  family therefore produces no signal on a history-derived day, so any figure for it is a floor.
- **No `service_domains`.** The map is current-day only and is discarded with the run. Nothing in
  detection, ranking or eligibility reads it, so this changes no measurement — it only means a
  reconstructed episode is not resolvable.

**The source (`--source`).** The full day aggregation, exactly as `run-day` performs it, DNS
included. Correct for every family, and the most expensive query this system makes: use it when a
measurement turns on DNS behaviour, and report the footprint it returns.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import duckdb

from network_behaviour.aggregation import (
    AGGREGATION_VERSION,
    ClientDayRow,
    ClientServiceDayRow,
    StagedDay,
)
from network_behaviour.detectors.dns import DnsDailyObservation
from network_behaviour.operations.pipeline import SourceDayInputProvider
from network_behaviour.source.client import ReadOnlyQueryRunner, bytes_read
from network_behaviour.time import UtcDay


class InputsError(RuntimeError):
    """Raised when a day cannot be reconstructed for evaluation."""


@contextmanager
def open_product_database(path: Path) -> Iterator[duckdb.DuckDBPyConnection]:
    """Open the product database read-only, without applying migrations.

    Deliberately not `DuckDbStore`, which opens read-write and migrates on open: a measurement
    that silently upgrades the schema of the store it is measuring is not a measurement. A
    database at an older schema is read here exactly as it stands, and a section that needs a
    table it does not have says so.
    """
    if not path.is_file():
        raise InputsError(f"product database not found: {path}")
    connection = duckdb.connect(str(path), read_only=True)
    try:
        yield connection
    finally:
        connection.close()


@dataclass(frozen=True, slots=True)
class DayInputs:
    """One day's staged rows, with the provenance every bundle section has to state."""

    staged: StagedDay
    dns: tuple[DnsDailyObservation, ...]
    provenance: str
    caveats: tuple[str, ...]
    query_count: int = 0
    read_rows: int = 0
    read_bytes: int = 0

    def render(self) -> str:
        lines = [
            f"inputs: {self.provenance}",
            f"staged: {len(self.staged.client_rows):,} client rows, "
            f"{len(self.staged.service_rows):,} client-service rows, "
            f"{len(self.dns):,} DNS observations",
            f"live query footprint: {self.query_count} queries, {self.read_rows:,} rows read"
            f"{bytes_read(self.read_bytes)}",
        ]
        lines.extend(f"caveat: {item}" for item in self.caveats)
        return "\n".join(lines)


def load_from_history(connection: duckdb.DuckDBPyConnection, day: UtcDay) -> DayInputs:
    """Rebuild day D's staged rows from the retained grains. No live query."""

    clients = tuple(
        ClientDayRow(*row)
        for row in connection.execute(
            "SELECT * FROM history.client_day WHERE day = ? ORDER BY client_ip",
            [day.value],
        ).fetchall()
    )
    services = tuple(
        ClientServiceDayRow(*row)
        for row in connection.execute(
            """
            SELECT * FROM history.client_service_day WHERE day = ?
            ORDER BY client_ip, service_id, asn_id, application_category_id,
                     transport_protocol, port_group
            """,
            [day.value],
        ).fetchall()
    )
    if not clients:
        raise InputsError(
            f"{day} has no retained history; publish it first, or evaluate from source"
        )
    return DayInputs(
        StagedDay(day, clients, services, AGGREGATION_VERSION),
        (),
        "retained history (no live query)",
        (
            "no DNS observations are retained, so the DNS family produces nothing here and any "
            "figure for it is a floor",
            "service_domains is current-day only and is not retained, so episodes are not "
            "resolvable; nothing in detection, ranking or eligibility reads it",
        ),
    )


def load_from_source(
    runner: ReadOnlyQueryRunner,
    sql_root: Path,
    day: UtcDay,
    *,
    timeout_seconds: int,
) -> DayInputs:
    """Re-derive day D from the source, exactly as `run-day` does. Reports its own footprint."""

    source, staged, dns = SourceDayInputProvider(
        runner, sql_root, timeout_seconds=timeout_seconds
    ).load(day)
    return DayInputs(
        staged,
        dns,
        "source re-derivation (full day aggregation)",
        (),
        source.query_count,
        source.read_rows,
        source.read_bytes,
    )
