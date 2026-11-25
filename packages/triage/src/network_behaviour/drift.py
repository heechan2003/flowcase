"""Fail-closed gates on the source changing underneath a day.

Tier 0 invariant 5 has listed *population drift beyond tolerance* among the conditions that abort
publication since the contract was adopted. Nothing implemented it until `drift-gates-v1`, and
`drift-gates-v1` gated the wrong population.

**Which population.** The gate counts the addresses with at least one service row: the population
relationship and persistence prevalence are drawn from (`baselines/engine.py`, since
`baseline-calibration-v3`), and since `behavioural-support-v3` exactly the addresses the transfer
and fanout families score and pool. Until then those two families also scored, and pooled,
addresses with no service row, so a step in the ungated addresses did move their peer cohorts, if
slightly (17 of 5,146 transfer and fanout episodes over 2026-09-16..10-18 sat in the band they
filled). It is now the only population whose size moves what the activity families compute; DNS
has its own check below.
`drift-gates-v1` counted every observed address. Measured 2026-10-23 over retained history, 60-75%
of those carry nothing but unaddressed `Web Browsing` rows — no server address, port or domain
(`CASE_STUDY` §3) — and across 390,056 published episodes they produced 11. Every "population
step" the v1 gate reacted to was in those addresses alone:

| Day | All observed | With a service row |
|---|---|---|
| 2026-08-09 (Sun) | 12,234 | 3,523 |
| 2026-09-01 (Tue) | 10,221 | 4,278 |
| 2026-09-13 (Sun) | 10,579 | 3,498 |
| 2026-09-16 (Wed) | 5,987 | 4,454 |

So v1 blocked 2026-08-26 and 2026-09-16 and was widened by hand twice, 0.20 to 0.30 to 0.44, for
steps in which the scored population rose; the 57% "known failure" of 2026-08-11 is the same
artifact. And it could not see the scored population move: the near-constant unaddressed block held
its median day-over-day movement at 0.2%, so a halving of service-carrying addresses would have
moved it by about 19%, under even the first tolerance. Their count is still rendered, as
information, because a step in it is an upstream change worth knowing about; it gates nothing.

**Against which day.** The scored population tracks the week: about 2,800 addresses on a UTC
Saturday against about 4,500 on a Tuesday, a day-over-day movement of median 13.0% and max 33.8%.
Against the most recent retained day *with the same UTC weekday* the 75 pairs in retained history
move median 1.67%, p90 4.26%, max 30.87%, and every pair outside the 2026-10-05 public-holiday weeks
stays at or under 5.4%, including pairs 28 to 35 days apart across retention gaps. The gap is
rendered, not compensated for. A day with no earlier same-weekday day — a deployment's first week —
has nothing to compare against and passes saying so, as the very first run always has.

**Why a composition gate as well.** The population gate catches the source measuring a different
*amount*. It cannot catch the source measuring a different *thing*: an upstream change that stops
resolving domains would leave the address count untouched while moving every service identity from
the `domain` basis to `asn` or `server_ip`, silently redefining what a "service" is and therefore
what novelty and rarity mean. The basis mix does not follow the week, so it still compares against
the most recent published day.

**DNS coverage, which aborts nothing.** DNS resolver novelty divides by the day's own DNS
clients — addresses that sent a query, without the DNS servers (`detectors/dns.py`) — which neither
gate above counts. `assess_dns_coverage` compares that population against the most recent day with
the same UTC weekday in the DNS observations the run already holds (90 days, so no state is
retained for it). `dns_pairs` is optional context, and its absence disables the DNS family rather
than the day (Tier 1 "Authorized sources"), so a failure does the same: the day publishes without
DNS. The DNS population is about 308 addresses a day and follows the week (`CASE_STUDY` §9).
Before `drift-gates-v3` nothing watched it, and a backscatter of unsolicited responses on 864 to
64,000 addresses a day moved the DNS family's denominator unseen until `primary-detectors-v8`.

**Composition thresholds.** `COMPOSITION_TVD` is fitted on the legitimate side only, measured
2026-08-25 over 36 comparisons in 2026-06-29..08-09 (median 0.00086, p90 0.00234, max 0.00281): no
observed composition failure exists to calibrate against. At 0.05 it is roughly eighteen times the
loudest legitimate day, a guard against a gross redefinition rather than a tuned detector.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date

DRIFT_VERSION = "drift-gates-v3"

POPULATION_STEP_FRACTION = 0.35
"""Movement in the scored population against the same UTC weekday that aborts the day.

Fitted 2026-10-23 on the 75 same-weekday pairs in `history.client_service_day`, 2026-06-29 to
2026-10-18: median 1.67%, p90 4.26%, max 30.87% (2026-10-04 -> 10-11, the rebound after the
public-holiday weekend). 0.35 passes every one of them and fails a halving or a doubling. The margin
over the holiday is the thin side — 4.1 points — and it is recorded here rather than only in
`CASE_STUDY.md`, evaluations (2026-10-23-drift-gates-v2-scored-population).
"""

DNS_POPULATION_STEP_FRACTION = 0.35
"""Movement in the DNS population against the same UTC weekday that disables DNS for the day.

Fitted 2026-10-23 on the 107 same-weekday pairs of query-sending, non-server DNS clients in
`dns_pairs`, 2026-07-01 to 2026-10-22: median 4.8%, p90 14.9%. Above 20% sit 2026-09-14 (24%, a
day of incomplete source ingestion), 09-21 (32%, against it), 10-12 (21%, a public holiday), and
07-23 (70%) and 07-30 (43%), which were not explained. 0.35 passes all but those last two. Failing
here costs one day of DNS episodes and nothing else, which is why it sits closer to the legitimate
range than `POPULATION_STEP_FRACTION` can.
"""

COMPOSITION_TVD = 0.05
"""Total variation distance in the `service_basis` mix that aborts the day.

Fitted on the legitimate range only — median 0.00086, p90 0.00234, max 0.00281 over the same 36
comparisons. No observed failure exists to calibrate the other side; see the module docstring.
"""


@dataclass(frozen=True, slots=True)
class DriftPolicy:
    """The tolerances, as an object a run carries rather than two loose floats."""

    population_step_fraction: float = POPULATION_STEP_FRACTION
    composition_tvd: float = COMPOSITION_TVD
    dns_population_step_fraction: float = DNS_POPULATION_STEP_FRACTION
    version: str = DRIFT_VERSION

    def __post_init__(self) -> None:
        if not 0 < self.population_step_fraction <= 1:
            raise ValueError("the population step tolerance must sit in (0, 1]")
        if not 0 < self.dns_population_step_fraction <= 1:
            raise ValueError("the DNS population step tolerance must sit in (0, 1]")
        if not 0 < self.composition_tvd <= 1:
            raise ValueError("the composition tolerance must sit in (0, 1]")
        if not self.version.strip():
            raise ValueError("a drift policy needs a version identifier")


@dataclass(frozen=True, slots=True)
class DayShape:
    """What a day looks like to these gates: how many scored hosts, and what kind of services.

    `population` counts addresses with at least one service row. `unaddressed_only` counts the
    observed addresses with none, when known; it is reported and never gated.
    """

    day: date
    population: int
    basis_counts: tuple[tuple[str, int], ...]
    unaddressed_only: int | None = None

    def __post_init__(self) -> None:
        if self.population < 0:
            raise ValueError("a population cannot be negative")
        if self.unaddressed_only is not None and self.unaddressed_only < 0:
            raise ValueError("an unaddressed-only count cannot be negative")
        if any(count < 0 for _, count in self.basis_counts):
            raise ValueError("a basis count cannot be negative")

    def distribution(self) -> dict[str, float]:
        total = sum(count for _, count in self.basis_counts)
        if not total:
            return {}
        return {basis: count / total for basis, count in self.basis_counts}


@dataclass(frozen=True, slots=True)
class DriftCheck:
    """One gate's verdict, carrying what it measured so a failure explains itself."""

    name: str
    measured: float | None
    tolerance: float
    passed: bool
    detail: str

    def render(self) -> str:
        measured = "n/a" if self.measured is None else f"{self.measured:.4f}"
        return (
            f"  {self.name:<22} {'pass' if self.passed else 'FAIL'}  "
            f"measured {measured}  tolerance {self.tolerance:.4f}  {self.detail}"
        )


@dataclass(frozen=True, slots=True)
class DriftAssessment:
    current: DayShape
    population_prior: DayShape | None
    composition_prior: DayShape | None
    policy: DriftPolicy
    checks: tuple[DriftCheck, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def population_gap_days(self) -> int | None:
        return _gap(self.current, self.population_prior)

    @property
    def composition_gap_days(self) -> int | None:
        return _gap(self.current, self.composition_prior)

    def failure_reason(self) -> str | None:
        """The first failing check, phrased for a `DayRunError`. `None` when the day may proceed."""

        for check in self.checks:
            if not check.passed:
                return f"{check.name} beyond tolerance: {check.detail}"
        return None

    def render(self) -> str:
        lines = [f"day {self.current.day.isoformat()}  policy {self.policy.version}"]
        lines.append(
            "  population against "
            + (
                "no earlier day with the same UTC weekday"
                if self.population_prior is None
                else f"{self.population_prior.day.isoformat()} (same weekday, "
                f"gap {self.population_gap_days}d)"
            )
        )
        lines.append(
            "  composition against "
            + (
                "no prior published day"
                if self.composition_prior is None
                else f"{self.composition_prior.day.isoformat()} (gap {self.composition_gap_days}d)"
            )
        )
        lines.extend(check.render() for check in self.checks)
        if self.current.unaddressed_only is not None:
            lines.append(
                f"  not gated: {self.current.unaddressed_only:,} observed address(es) with no "
                "service row"
            )
        return "\n".join(lines)


def _gap(current: DayShape, prior: DayShape | None) -> int | None:
    return None if prior is None else (current.day - prior.day).days


@dataclass(frozen=True, slots=True)
class DnsCoverage:
    """Whether the DNS family may run today. Never a reason to abort the day."""

    day: date
    population: int
    prior: tuple[date, int] | None
    check: DriftCheck

    @property
    def dns_enabled(self) -> bool:
        return self.check.passed

    def render(self) -> str:
        if self.prior is None:
            against = "no earlier DNS day with the same UTC weekday"
        else:
            gap = (self.day - self.prior[0]).days
            against = f"{self.prior[0].isoformat()} (same weekday, gap {gap}d)"
        effect = "" if self.check.passed else "  — DNS disabled for this day"
        return f"  dns coverage against {against}\n{self.check.render()}{effect}"


def assess_dns_coverage(
    day: date,
    population: int,
    prior: tuple[date, int] | None,
    policy: DriftPolicy | None = None,
) -> DnsCoverage:
    """Compare the day's DNS population with the same weekday's. `prior` is `(day, population)`."""

    active = policy or DriftPolicy()
    tolerance = active.dns_population_step_fraction
    if prior is None:
        check = DriftCheck(
            "dns_population_step",
            None,
            tolerance,
            True,
            "no earlier DNS day with the same UTC weekday to compare against",
        )
    else:
        movement = abs(population - prior[1]) / prior[1]
        check = DriftCheck(
            "dns_population_step",
            movement,
            tolerance,
            movement <= tolerance,
            f"{prior[1]:,} -> {population:,} DNS clients, against {prior[0].isoformat()} "
            f"({movement:.2%})",
        )
    return DnsCoverage(day, population, prior, check)


def total_variation_distance(left: Mapping[str, float], right: Mapping[str, float]) -> float:
    """Half the L1 distance between two distributions over the union of their keys.

    A basis absent from one side counts as zero there, which is the point: a source that stops
    emitting the `domain` basis entirely must register as maximal movement, not as a missing key.
    """

    keys = set(left) | set(right)
    return 0.5 * sum(abs(left.get(key, 0.0) - right.get(key, 0.0)) for key in keys)


def basis_counts(bases: Sequence[str]) -> tuple[tuple[str, int], ...]:
    """Tally `service_basis` values into the shape `DayShape` holds, sorted for determinism."""

    tally: dict[str, int] = {}
    for basis in bases:
        tally[basis] = tally.get(basis, 0) + 1
    return tuple(sorted(tally.items()))


def assess(
    current: DayShape,
    population_prior: DayShape | None,
    composition_prior: DayShape | None,
    policy: DriftPolicy | None = None,
) -> DriftAssessment:
    """Compare a day against its priors. Every check states what it measured.

    `population_prior` is the most recent retained day with the same UTC weekday;
    `composition_prior` is the most recent published day. Either may be `None`, and a missing
    prior passes its check saying so: failing closed on its absence would make a deployment's
    first run, or first week, impossible.
    """

    active = policy or DriftPolicy()
    population = (
        DriftCheck(
            "population_step",
            None,
            active.population_step_fraction,
            True,
            "no earlier day with the same UTC weekday to compare against",
        )
        if population_prior is None
        else _population_check(current, population_prior, active)
    )
    composition = (
        DriftCheck(
            "composition_tvd",
            None,
            active.composition_tvd,
            True,
            "no prior published day to compare against",
        )
        if composition_prior is None
        else _composition_check(current, composition_prior, active)
    )
    return DriftAssessment(
        current, population_prior, composition_prior, active, (population, composition)
    )


def _population_check(current: DayShape, prior: DayShape, policy: DriftPolicy) -> DriftCheck:
    if prior.population <= 0:
        # A published day with no population is already broken, and dividing by it would hide
        # that behind a ZeroDivisionError rather than a fail-closed reason. Refuse to proceed.
        return DriftCheck(
            "population_step",
            None,
            policy.population_step_fraction,
            False,
            f"the prior published day {prior.day.isoformat()} recorded no population",
        )
    movement = abs(current.population - prior.population) / prior.population
    return DriftCheck(
        "population_step",
        movement,
        policy.population_step_fraction,
        movement <= policy.population_step_fraction,
        f"{prior.population:,} -> {current.population:,} addresses with a service row, against "
        f"{prior.day.isoformat()} ({movement:.2%})",
    )


def _composition_check(current: DayShape, prior: DayShape, policy: DriftPolicy) -> DriftCheck:
    left, right = prior.distribution(), current.distribution()
    if not left or not right:
        side = "prior" if not left else "current"
        return DriftCheck(
            "composition_tvd",
            None,
            policy.composition_tvd,
            False,
            f"the {side} day carries no service rows to take a composition from",
        )
    distance = total_variation_distance(left, right)
    largest = max(right, key=lambda basis: right[basis])
    return DriftCheck(
        "composition_tvd",
        distance,
        policy.composition_tvd,
        distance <= policy.composition_tvd,
        f"largest basis {largest} at {right[largest]:.2%} of service rows",
    )
