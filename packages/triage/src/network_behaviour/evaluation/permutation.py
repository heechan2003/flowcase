"""§2 blocked permutation null: how much of the output responds to structure, not to a host.

**What is permuted.** The host label on the staged day. Every detector scores today's rows against
that host's own history and against the current population, both keyed by `client_ip`. Moving the
label breaks the link between a day's behaviour and the history it is judged against, while
leaving the day's rows exactly as they were. Whatever still fires is responding to the shape of
the data.

**Marginals are preserved exactly**, not approximately: no row is edited, only relabelled, so the
volume, destination-count and activity distributions after permutation are the same multiset they
were before. `verify_marginals` asserts this rather than asserting it in prose.

**Blocking.** Naive shuffling moves a night-only host onto a daytime host's history, destroys the
diurnal structure and inflates the apparent null — a flattering result. Labels move only within a
stratum of (weekday, occupancy signature), where the signature is which quarters of the UTC day
the host was active in, from the union of its service bitmaps. Day-of-week is constant within one
day and varies across a multi-day run; it is part of the key either way so a run over a week
cannot move a Saturday host onto a Tuesday.

**What the result is: a per-condition table, not a single number.** This module used to divide
permuted episodes by observed and call the quotient an upper bound on the structural-artefact share
of the output. On 2026-08-09 that quotient was 792%, which bounds nothing. The cause is not a defect
in the permutation: `relationship` and `persistence` are defined against *a host's own history*, so
breaking the host-to-history pairing must make everything look novel and nothing look recurrent.
Permuted output exceeding observed output is the expected behaviour of a history-relative detector
under this null, and no ratio built from the totals survives it.

What does survive is the comparison condition by condition, because each condition is its own
question:

- A condition whose pass rate is **unchanged** under permutation does not respond to the host label
  at all. Whatever it is measuring is a property of something else — the service, the population,
  the day. `structural_conditions` names these. It is not a verdict that they are useless: a
  service-level filter can be exactly what a rule needs. It is a statement about where the
  information comes from, which is what §2 asks.
- A condition whose pass rate **moves** is responding to the host label. For a history-relative
  condition, movement is expected and its size estimates nothing.

The totals are still reported, because they show the direction and scale of the response. They are
not divided into each other.

Neither figure is a false-positive rate against real behaviour, and this module never names one.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from random import Random

from network_behaviour.aggregation import StagedDay
from network_behaviour.detectors.dns import DnsDailyObservation
from network_behaviour.evaluation.harness import DayEvaluator, RunOutcome, StagedTransform
from network_behaviour.instrumentation import ConditionLog
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.time import UtcDay

QUARTERS = 4
_BUCKETS_PER_QUARTER = 288 // QUARTERS

INVARIANCE_TOLERANCE = 0.05
"""Relative distance within which a permuted pass rate counts as unchanged.

Five percent of the observed rate. Wide enough that a replicate-to-replicate wobble in a mean over
a handful of permutations does not register as a response to the host label, narrow enough that the
smallest genuine movement measured on real data — `transfer_eligibility.strong_strength`, 0.76% to
1.06%, a relative 39% — stays outside it.
"""


class PermutationError(ValueError):
    """Raised when a permutation would not preserve what §2 requires it to preserve."""


@dataclass(frozen=True, slots=True)
class Strata:
    """The blocking key, and how much freedom it left the permutation."""

    sizes: tuple[tuple[str, int], ...]

    @property
    def count(self) -> int:
        return len(self.sizes)

    @property
    def singletons(self) -> int:
        """Hosts alone in a stratum. Their label cannot move, so they are not permuted at all."""
        return sum(1 for _, size in self.sizes if size == 1)

    @property
    def hosts(self) -> int:
        return sum(size for _, size in self.sizes)

    def render(self) -> str:
        return (
            f"{self.count} strata over {self.hosts} hosts; "
            f"{self.singletons} host(s) alone in a stratum and therefore unmoved"
        )


@dataclass(frozen=True, slots=True)
class RuleRate:
    """A condition's pass rate as observed, and under permutation."""

    rule: str
    condition: str
    observed: float | None
    permuted: float | None

    @property
    def is_invariant(self) -> bool:
        """Whether permuting the host label left this condition's pass rate where it was.

        Relative, not absolute: a condition passing at 0.58% observed and 0.43% permuted moved by
        a quarter of itself, and an absolute tolerance wide enough to ignore 0.15 percentage points
        would call that invariant.
        """

        if self.observed is None or self.permuted is None:
            return False
        if self.observed == 0.0:
            return self.permuted == 0.0
        return abs(self.permuted - self.observed) / self.observed <= INVARIANCE_TOLERANCE

    def render(self) -> str:
        return (
            f"  {f'{self.rule}.{self.condition}':<56} "
            f"observed {_percent(self.observed)}  permuted {_percent(self.permuted)}"
        )


@dataclass(frozen=True, slots=True)
class PermutationNull:
    day: str
    seed: int
    replicates: int
    strata: Strata
    observed_episodes: int
    observed_hosts: int
    permuted_episodes: tuple[int, ...]
    permuted_hosts: tuple[int, ...]
    per_family: tuple[tuple[str, int, tuple[int, ...]], ...]
    conditions: tuple[RuleRate, ...]
    labels_moved: tuple[float, ...]

    @property
    def structural_conditions(self) -> tuple[RuleRate, ...]:
        """Conditions whose pass rate does not respond to the host label.

        Measured, not asserted: a condition is listed when its permuted rate matches its observed
        rate to within `INVARIANCE_TOLERANCE` relatively. Such a condition draws its information
        from the service, the population or the day rather than from the host, which is the
        question §2 exists to ask. It is not a claim that the condition is redundant.
        """

        return tuple(
            rate
            for rate in self.conditions
            if rate.observed is not None and rate.permuted is not None and rate.is_invariant
        )

    def render(self) -> str:
        lines = [
            f"day {self.day}  seed {self.seed}  replicates {self.replicates}",
            f"blocking: {self.strata.render()}",
            f"labels actually moved: {_percent(sum(self.labels_moved) / len(self.labels_moved))}",
            "",
            f"observed:  {self.observed_episodes:,} episodes over {self.observed_hosts:,} hosts",
            f"permuted:  {_summary(self.permuted_episodes)} episodes over "
            f"{_summary(self.permuted_hosts)} hosts",
            "",
            "Permuted totals are not divided into observed ones. A history-relative detector must",
            "fire more once the host-to-history pairing is broken, so no ratio of these is a bound",
            "on anything. Read the per-condition table below.",
            "",
            "per family (observed -> permuted):",
        ]
        for family, observed, permuted in self.per_family:
            lines.append(f"  {family:<14} {observed:>8,} -> {_summary(permuted)}")
        lines += ["", "per condition (pass rate among units the rule was evaluated on):"]
        lines.extend(item.render() for item in self.conditions)
        invariant = self.structural_conditions
        lines += [
            "",
            "carries no host-specific information (pass rate invariant under permutation):",
        ]
        if invariant:
            lines.extend(f"  {item.rule}.{item.condition}" for item in invariant)
        else:
            lines.append("  none — every condition responded to the host label")
        return "\n".join(lines)


def stratum_key(staged: StagedDay, client_ip: str) -> str:
    """(weekday, occupancy signature) — the block a host's label may move inside."""

    occupied = ActivityBitmap()
    for row in staged.service_rows:
        if row.client_ip == client_ip:
            occupied = occupied | ActivityBitmap(row.active_5m_bitmap)
    quarters = "".join(
        "1"
        if any(
            quarter * _BUCKETS_PER_QUARTER <= bucket < (quarter + 1) * _BUCKETS_PER_QUARTER
            for bucket in occupied.active_buckets()
        )
        else "0"
        for quarter in range(QUARTERS)
    )
    return f"{staged.day.value.strftime('%a').lower()}:{quarters}"


def build_strata(staged: StagedDay) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for row in staged.client_rows:
        grouped[stratum_key(staged, row.client_ip)].append(row.client_ip)
    return {key: tuple(sorted(members)) for key, members in sorted(grouped.items())}


def label_mapping(staged: StagedDay, rng: Random) -> dict[str, str]:
    """Draw one within-stratum relabelling. Separate from applying it, because the same mapping
    has to reach every input keyed by host — the staged day and, since `primary-detectors-v7`
    put a DNS condition in front of §2, day D's DNS observations."""

    mapping: dict[str, str] = {}
    for members in build_strata(staged).values():
        shuffled = list(members)
        rng.shuffle(shuffled)
        mapping.update(dict(zip(members, shuffled, strict=True)))
    return mapping


def moved_share(mapping: Mapping[str, str]) -> float:
    moved = sum(1 for source, target in mapping.items() if source != target)
    return moved / len(mapping) if mapping else 0.0


def apply_labels(staged: StagedDay, mapping: Mapping[str, str]) -> StagedDay:
    permuted = replace(
        staged,
        client_rows=tuple(
            sorted(
                (replace(row, client_ip=mapping[row.client_ip]) for row in staged.client_rows),
                key=lambda row: row.client_ip,
            )
        ),
        service_rows=tuple(
            sorted(
                (replace(row, client_ip=mapping[row.client_ip]) for row in staged.service_rows),
                key=lambda row: (
                    row.client_ip,
                    row.service_id,
                    row.asn_id,
                    row.application_category_id,
                    row.transport_protocol,
                    row.port_group,
                ),
            )
        ),
    )
    verify_marginals(staged, permuted)
    return permuted


def permute_labels(staged: StagedDay, rng: Random) -> tuple[StagedDay, float]:
    """Relabel hosts within their stratum. Returns the day and the share of labels that moved."""

    mapping = label_mapping(staged, rng)
    return apply_labels(staged, mapping), moved_share(mapping)


def relabel_dns(
    observations: Sequence[DnsDailyObservation],
    mapping: Mapping[str, str],
    day: UtcDay,
) -> tuple[DnsDailyObservation, ...]:
    """Move day D's DNS observations with the host label, leaving prior days where they are.

    This is the same break the staged permutation makes: today's behaviour is judged against a
    history that is no longer its own. DNS is the one family whose day and whose history arrive
    in the same tuple rather than from the retained store, so without this the DNS conditions
    were scored on unpermuted input and §2 could say nothing about them. Rows for an address the
    staged day does not carry are left alone; the mapping is a bijection on staged addresses, so
    they cannot collide with a moved label.
    """

    relabelled = tuple(
        replace(row, client_ip=mapping.get(row.client_ip, row.client_ip))
        if row.day == day.value
        else row
        for row in observations
    )
    before = sorted(_dns_marginal(row) for row in observations)
    after = sorted(_dns_marginal(row) for row in relabelled)
    if before != after:
        raise PermutationError("permutation altered the DNS marginals")
    return relabelled


def _dns_marginal(row: DnsDailyObservation) -> tuple[object, ...]:
    """Everything about a DNS row except which host it is attached to."""

    return (
        row.day,
        row.resolver_id,
        row.complete_sessions,
        row.unanswered_sessions,
        row.unsolicited_sessions,
        row.query_packets,
        row.response_packets,
        row.unanswered_query_packets,
        row.unsolicited_response_packets,
        row.weighted_service_nanos,
        row.weighted_service_sessions,
    )


def verify_marginals(before: StagedDay, after: StagedDay) -> None:
    """§2 requires the marginals survive. Relabelling preserves them; this proves it did."""

    for name, left, right in (
        (
            "client",
            sorted(row.values()[2:] for row in before.client_rows),
            sorted(row.values()[2:] for row in after.client_rows),
        ),
        (
            "service",
            sorted(row.values()[2:] for row in before.service_rows),
            sorted(row.values()[2:] for row in after.service_rows),
        ),
    ):
        if left != right:
            raise PermutationError(f"permutation altered the {name} marginals")


def measure_permutation_null(
    evaluator: DayEvaluator,
    *,
    seed: int,
    replicates: int = 5,
) -> PermutationNull:
    if replicates < 1:
        raise ValueError("a null needs at least one replicate")
    observed = evaluator.baseline()
    strata = build_strata(evaluator.staged)
    outcomes: list[RunOutcome] = []
    moved: list[float] = []
    for index in range(replicates):
        rng = Random(seed + index)
        mapping = label_mapping(evaluator.staged, rng)
        moved.append(moved_share(mapping))
        outcomes.append(
            evaluator.run(
                f"permuted-{index}",
                transform=_replace_with(apply_labels(evaluator.staged, mapping)),
                dns=relabel_dns(evaluator.dns, mapping, evaluator.day),
            )
        )
    return PermutationNull(
        str(evaluator.day),
        seed,
        replicates,
        Strata(tuple((key, len(members)) for key, members in strata.items())),
        observed.episode_count,
        observed.host_count,
        tuple(item.episode_count for item in outcomes),
        tuple(item.host_count for item in outcomes),
        _per_family(observed, outcomes),
        _condition_rates(observed.conditions, [item.conditions for item in outcomes]),
        tuple(moved),
    )


def _replace_with(staged: StagedDay) -> StagedTransform:
    return lambda _current: staged


def _per_family(
    observed: RunOutcome, outcomes: Sequence[RunOutcome]
) -> tuple[tuple[str, int, tuple[int, ...]], ...]:
    families = sorted(
        {episode.family.value for episode in observed.episodes}
        | {episode.family.value for item in outcomes for episode in item.episodes}
    )
    return tuple(
        (
            family,
            sum(1 for episode in observed.episodes if episode.family.value == family),
            tuple(
                sum(1 for episode in item.episodes if episode.family.value == family)
                for item in outcomes
            ),
        )
        for family in families
    )


def _condition_rates(
    observed: ConditionLog, permuted: Sequence[ConditionLog]
) -> tuple[RuleRate, ...]:
    rates: list[RuleRate] = []
    for rule in observed.rules():
        for condition in _conditions_of(observed, rule):
            rates.append(
                RuleRate(
                    rule,
                    condition,
                    _pass_rate(observed, rule, condition),
                    _mean(
                        [
                            value
                            for log in permuted
                            if (value := _pass_rate(log, rule, condition)) is not None
                        ]
                    ),
                )
            )
    return tuple(rates)


def _conditions_of(log: ConditionLog, rule: str) -> tuple[str, ...]:
    names: list[str] = []
    for key in log.observations:
        if key[0] != rule:
            continue
        for name, _ in key[2]:
            if name not in names:
                names.append(name)
    return tuple(names)


def _pass_rate(log: ConditionLog, rule: str, condition: str) -> float | None:
    total = 0
    passed = 0
    for key, count in log.observations.items():
        if key[0] != rule:
            continue
        for name, value in key[2]:
            if name != condition:
                continue
            total += count
            if value:
                passed += count
    return passed / total if total else None


def _mean(values: Sequence[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _summary(values: Sequence[int]) -> str:
    if not values:
        return "n/a"
    ordered = sorted(values)
    return f"{ordered[0]:,} to {ordered[-1]:,} (median {ordered[len(ordered) // 2]:,})"


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:7.2%}"
