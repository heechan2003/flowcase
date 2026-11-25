"""Score one day repeatedly under controlled changes, and record what changed.

Every section of `docs/EVALUATION.md` is the same shape: take a day, change exactly one thing —
inject a synthesised behaviour, permute the host labels, drop part of the population, move a
parameter — score it again through the real pipeline, and compare. This module is that loop. The
sections supply the transform and read the outcome.

The connection is never written to. It holds retained history for `day < D` and nothing else, so
a harness run cannot contaminate the baselines a later run is measured against.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace

import duckdb

from network_behaviour.aggregation import StagedDay
from network_behaviour.detectors.dns import DnsDailyObservation
from network_behaviour.instrumentation import ConditionLog
from network_behaviour.operations.scoring import ScoredDay, ScoringPolicies, score_day
from network_behaviour.ranking.models import RankedEpisode
from network_behaviour.time import UtcDay

StagedTransform = Callable[[StagedDay], StagedDay]


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """One scoring pass, with everything a bundle section needs to compare it to another."""

    label: str
    scored: ScoredDay
    conditions: ConditionLog
    seconds: float
    client_rows: int
    service_rows: int

    @property
    def episodes(self) -> tuple[RankedEpisode, ...]:
        return self.scored.ranking.ranked_eligible

    @property
    def episode_count(self) -> int:
        return len(self.scored.ranking.ranked_eligible)

    @property
    def host_count(self) -> int:
        return len(self.scored.ranking.client_view)

    def episode_positions(self) -> dict[str, int]:
        return {
            str(episode.episode_id): index
            for index, episode in enumerate(self.scored.ranking.ranked_eligible)
        }


@dataclass(slots=True)
class DayEvaluator:
    """One day, one history scope, many scored variants of it."""

    connection: duckdb.DuckDBPyConnection
    day: UtcDay
    staged: StagedDay
    dns: tuple[DnsDailyObservation, ...] = ()
    policies: ScoringPolicies = field(default_factory=ScoringPolicies)
    _baseline: RunOutcome | None = None

    def run(
        self,
        label: str,
        *,
        transform: StagedTransform | None = None,
        policies: ScoringPolicies | None = None,
        dns: tuple[DnsDailyObservation, ...] | None = None,
    ) -> RunOutcome:
        staged = self.staged if transform is None else transform(self.staged)
        if staged.day != self.day:
            raise ValueError("a staged transform must not change the UTC day")
        log = ConditionLog()
        started = time.monotonic()
        scored = score_day(
            self.connection,
            self.day,
            staged,
            self.dns if dns is None else dns,
            policies=policies or self.policies,
            recorder=log,
        )
        return RunOutcome(
            label,
            scored,
            log,
            time.monotonic() - started,
            len(staged.client_rows),
            len(staged.service_rows),
        )

    def baseline(self) -> RunOutcome:
        """The day as published, scored once and reused as the comparison for every variant."""
        if self._baseline is None:
            self._baseline = self.run("baseline")
        return self._baseline


def restrict_to_clients(clients: frozenset[str]) -> StagedTransform:
    """Keep only these hosts. Used by §3 resampling and by §1 to hold a sweep small."""

    def transform(staged: StagedDay) -> StagedDay:
        return replace(
            staged,
            client_rows=tuple(row for row in staged.client_rows if row.client_ip in clients),
            service_rows=tuple(row for row in staged.service_rows if row.client_ip in clients),
        )

    return transform


def compose(*transforms: StagedTransform) -> StagedTransform:
    def transform(staged: StagedDay) -> StagedDay:
        for step in transforms:
            staged = step(staged)
        return staged

    return transform
