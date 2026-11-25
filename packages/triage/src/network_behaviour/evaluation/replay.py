"""Seed an isolated database with retained history strictly before day D.

`day < D` is the leakage boundary in `PRODUCT_CONTRACT.md` Tier 0, and every evaluation in
`docs/EVALUATION.md` depends on it holding: an implant injected into a day whose baselines were
built from that same day measures nothing, and a held-out day that was not held out is not one.

`scripts/replay_day.sh` and the harness both call this, so there is one implementation of the
boundary rather than one in shell and one in Python.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from network_behaviour.storage.repository import DuckDbStore, StorageConfig
from network_behaviour.time import UtcDay

_GRAINS = ("client_day", "client_service_day")


class ReplaySeedError(RuntimeError):
    """Raised when an isolated replay database cannot be seeded safely."""


@dataclass(frozen=True, slots=True)
class SeedReport:
    replay_path: Path
    client_day_rows: int
    client_service_day_rows: int
    first_day: date | None
    last_day: date | None
    excluded_days: tuple[date, ...]

    def render(self) -> str:
        excluded = (
            ", ".join(day.isoformat() for day in self.excluded_days)
            if self.excluded_days
            else "none"
        )
        return "\n".join(
            (
                f"seeded client-day rows:         {self.client_day_rows:,}",
                f"seeded client-service-day rows: {self.client_service_day_rows:,}",
                f"history range:                  {self.first_day} to {self.last_day}",
                f"held-out days:                  {excluded}",
            )
        )


def seed_history_before(
    production: Path,
    replay: Path,
    day: UtcDay,
    *,
    migrations: Path = Path("sql/migrations"),
    exclude_days: Iterable[date] = (),
) -> SeedReport:
    """Create `replay` at the current schema, holding only history for `day < D`.

    `production` is attached read-only and never written. `exclude_days` holds out further days
    for the sensitivity and stability measurements, which need baselines built without them.
    """

    production = production.resolve()
    replay = replay.resolve()
    if not production.is_file():
        raise ReplaySeedError(f"production database not found: {production}")
    if replay.exists():
        raise ReplaySeedError(f"replay database already exists: {replay}")
    held_out = tuple(sorted(set(exclude_days)))
    if any(value >= day.value for value in held_out):
        raise ReplaySeedError("held-out days are already outside the day < D boundary")
    replay.parent.mkdir(parents=True, exist_ok=True)

    quoted = str(production).replace("'", "''")
    placeholders = ", ".join("?" for _ in held_out)
    predicate = f"day < ?{f' AND day NOT IN ({placeholders})' if held_out else ''}"
    parameters: list[object] = [day.value, *held_out]

    with DuckDbStore(StorageConfig(replay, migrations)) as store:
        connection = store.connection
        connection.execute(f"ATTACH '{quoted}' AS production (READ_ONLY)")
        try:
            connection.execute("BEGIN")
            try:
                for grain in _GRAINS:
                    connection.execute(
                        f"INSERT INTO history.{grain} "
                        f"SELECT * FROM production.history.{grain} WHERE {predicate}",
                        parameters,
                    )
            except Exception:
                connection.execute("ROLLBACK")
                raise
            connection.execute("COMMIT")
            row = connection.execute(
                """
                SELECT (SELECT count(*) FROM history.client_day),
                       (SELECT count(*) FROM history.client_service_day),
                       (SELECT min(day) FROM history.client_day),
                       (SELECT max(day) FROM history.client_day)
                """
            ).fetchone()
        finally:
            connection.execute("DETACH production")
    if row is None:
        raise ReplaySeedError("seeded history counts are unavailable")
    return SeedReport(replay, int(row[0]), int(row[1]), row[2], row[3], held_out)
