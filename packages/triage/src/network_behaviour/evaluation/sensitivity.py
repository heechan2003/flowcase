"""§1 sensitivity envelope: the region of parameter space this system can see at all.

Reports what fraction of injections surface, per cell of the swept grid. Never as recall: recall
is measured against real compromise, which nothing in this deployment can measure. §1 is a
statement about the instrument.

An implant "surfaces" when the injected host carries an eligible episode attributed to the
implant's own service. That is direct attribution, not a downstream ranking position — a host can
be reordered for reasons the implant did not cause, and counting that would inflate the envelope.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from random import Random

from network_behaviour.aggregation import StagedDay
from network_behaviour.evaluation.harness import DayEvaluator, RunOutcome, StagedTransform
from network_behaviour.evaluation.injection import (
    ImplantProfile,
    Injection,
    InjectionFidelity,
    inject,
)


@dataclass(frozen=True, slots=True)
class Surfacing:
    """One injected host under one profile."""

    client_ip: str
    profile_name: str
    surfaced: bool
    episodes_attributed: int


@dataclass(frozen=True, slots=True)
class EnvelopeCell:
    """One point of the swept grid, aggregated over the hosts injected at it."""

    period_minutes: int
    occurrences: int
    up_bytes_per_contact: int
    jitter_minutes: int
    injections: int
    surfaced: int

    @property
    def surfaced_rate(self) -> float:
        return self.surfaced / self.injections if self.injections else 0.0

    def render(self) -> str:
        return (
            f"period {self.period_minutes:>5}m  n {self.occurrences:>4}  "
            f"amplitude {self.up_bytes_per_contact:>12,}B  jitter +/-{self.jitter_minutes:>3}m  "
            f"surfaced {self.surfaced_rate:6.1%} ({self.surfaced}/{self.injections})"
        )


# §1 wants a region of parameter space. An axis swept at fewer than this many points describes a
# line or a dot, and the report refuses to call the result an envelope.
MINIMUM_AXIS_POINTS = 3


@dataclass(frozen=True, slots=True)
class SensitivityEnvelope:
    day: str
    seed: int
    hosts: tuple[str, ...]
    cells: tuple[EnvelopeCell, ...]
    fidelity: InjectionFidelity
    baseline_episodes: int
    baseline_hosts: int
    seconds: float

    @property
    def axes(self) -> tuple[tuple[str, int], ...]:
        """Distinct points swept per axis, taken from the cells rather than from the request."""
        return (
            ("period", len({cell.period_minutes for cell in self.cells})),
            ("occurrences", len({cell.occurrences for cell in self.cells})),
            ("amplitude", len({cell.up_bytes_per_contact for cell in self.cells})),
        )

    @property
    def is_envelope(self) -> bool:
        """False when the grid is too coarse to describe a region of parameter space."""
        return all(points >= MINIMUM_AXIS_POINTS for _, points in self.axes)

    def render(self) -> str:
        grid = " x ".join(f"{name} {points}" for name, points in self.axes)
        lines = [
            f"day {self.day}  seed {self.seed}  hosts injected {len(self.hosts)}",
            f"baseline: {self.baseline_episodes:,} episodes over {self.baseline_hosts:,} hosts",
            f"grid: {grid} = {len(self.cells)} scoring passes in {self.seconds / 60:.1f} min",
            "",
        ]
        if not self.is_envelope:
            lines += [
                "PILOT, NOT AN ENVELOPE. At least one axis was swept at fewer than "
                f"{MINIMUM_AXIS_POINTS} points, so this",
                "describes a line or a point in parameter space. Quote it as a spot check and",
                "widen the grid before stating a region. See docs/EVALUATION.md section 1.",
                "",
            ]
        lines.extend(cell.render() for cell in self.cells)
        lines += ["", "merge fidelity:", self.fidelity.render()]
        return "\n".join(lines)


def measure_sensitivity(
    evaluator: DayEvaluator,
    hosts: Sequence[str],
    profiles: Sequence[ImplantProfile],
    *,
    seed: int,
) -> SensitivityEnvelope:
    """Sweep `profiles` across `hosts`, one scoring pass per profile.

    Every host in a pass gets its own synthetic destination, so implants do not make each other
    prevalent. They do still share a population: an implant shifts the day's rarity denominators
    by one service for every other implant in the same pass. With a host sample far smaller than
    the population that shift is negligible, and it is stated rather than assumed away.
    """

    if not hosts:
        raise ValueError("a sensitivity sweep needs at least one host to inject")
    if not profiles:
        raise ValueError("a sensitivity sweep needs at least one profile")
    baseline = evaluator.baseline()

    cells: list[EnvelopeCell] = []
    fidelity: InjectionFidelity | None = None
    seconds = 0.0
    for profile in profiles:
        # One seed per profile, so every cell of the grid sees the same jitter draws and the
        # cells differ only by the swept parameter.
        rng = Random(seed)
        injections, injected = _plan(evaluator, hosts, profile, rng)
        outcome = evaluator.run(profile.name, transform=_replace_with(injected))
        seconds += outcome.seconds
        results = tuple(_surfacing(injection, outcome) for injection in injections)
        fidelity = fidelity or injections[0].fidelity
        cells.append(
            EnvelopeCell(
                profile.period_minutes,
                profile.occurrences,
                profile.up_bytes_per_contact,
                profile.jitter_minutes,
                len(results),
                sum(1 for item in results if item.surfaced),
            )
        )
    assert fidelity is not None
    return SensitivityEnvelope(
        str(evaluator.day),
        seed,
        tuple(hosts),
        tuple(cells),
        fidelity,
        baseline.episode_count,
        baseline.host_count,
        seconds,
    )


def _plan(
    evaluator: DayEvaluator,
    hosts: Sequence[str],
    profile: ImplantProfile,
    rng: Random,
) -> tuple[tuple[Injection, ...], StagedDay]:
    """Merge one implant per host, each into the result of the last, so all of them land."""

    staged = evaluator.staged
    injections: list[Injection] = []
    for index, host in enumerate(hosts):
        result = inject(staged, host, profile.for_host(index), rng)
        injections.append(result)
        staged = result.staged
    return tuple(injections), staged


def _replace_with(staged: StagedDay) -> StagedTransform:
    return lambda _current: staged


def _surfacing(injection: Injection, outcome: RunOutcome) -> Surfacing:
    attributed = sum(
        1
        for episode in outcome.episodes
        if episode.client_ip == injection.client_ip
        and episode.service_id_hex == injection.service_id_hex
    )
    return Surfacing(
        injection.client_ip,
        injection.profile.name,
        attributed > 0,
        attributed,
    )
