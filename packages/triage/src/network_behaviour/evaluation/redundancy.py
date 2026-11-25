"""§5 conjunction redundancy: does adding a condition actually remove anything?

For every rule that needs more than one condition, this reports the realised joint rate against
the product of the marginals. The realised rate is observed directly and needs no independence
assumption; the product is what the rate would be if the conditions were independent, and the
ratio of the two says how much the extra condition bought.

The failure this exists for is concrete. The relationship family conjoined novelty and population
rarity, both required to pass, while producing 99.5% of the stream (measured 2026-08-21), because a
service seen today for the first time is almost by construction one that few others use. The
conjunction removes almost nothing, and no test could see that until the marginals were counted.

Pairwise independence does not establish joint independence. A ratio near one is a screen saying
"look here", not a proof that the conditions are independent, and `render` says so.

Rates are over the units the rule was *evaluated* on. Units that never reached it — blocked on
source quality, or below a support gate — are counted separately and excluded from every rate,
because folding them in would make a conjunction look selective when what removed them was a gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import prod

from network_behaviour.instrumentation import Combinator, ConditionLog


@dataclass(frozen=True, slots=True)
class ConditionMarginal:
    name: str
    passed: int
    evaluated: int

    @property
    def rate(self) -> float:
        return self.passed / self.evaluated if self.evaluated else 0.0


@dataclass(frozen=True, slots=True)
class RuleRedundancy:
    rule: str
    combinator: Combinator
    evaluated: int
    excluded: int
    exclusion_reasons: tuple[tuple[str, int], ...]
    marginals: tuple[ConditionMarginal, ...]
    satisfied: int

    @property
    def realised(self) -> float:
        return self.satisfied / self.evaluated if self.evaluated else 0.0

    @property
    def independent(self) -> float:
        """The rate the rule would show if its conditions were independent."""
        rates = [item.rate for item in self.marginals]
        if self.combinator is Combinator.ALL:
            return prod(rates)
        return 1.0 - prod(1.0 - rate for rate in rates)

    @property
    def lift(self) -> float | None:
        """Realised over independent. Near 1 means the conditions are close to redundant."""
        return self.realised / self.independent if self.independent else None

    @property
    def removed_by_conjunction(self) -> float | None:
        """How much of the loosest single condition the whole rule removes beyond it.

        Zero means every unit that passed the easiest condition passed the rule: the other
        conditions removed nothing at all.
        """
        if not self.marginals or self.combinator is not Combinator.ALL:
            return None
        loosest = max(item.rate for item in self.marginals)
        if loosest == 0:
            return None
        return (loosest - self.realised) / loosest

    def render(self) -> str:
        header = (
            f"{self.rule} ({self.combinator.value} of "
            f"{len(self.marginals)}): evaluated {self.evaluated:,}, "
            f"excluded before the rule {self.excluded:,}"
        )
        lines = [header]
        for item in self.marginals:
            lines.append(f"    {item.name:<28} {item.rate:7.2%}  ({item.passed:,})")
        lines.append(f"    {'realised joint':<28} {self.realised:7.2%}  ({self.satisfied:,})")
        lines.append(f"    {'product of marginals':<28} {self.independent:7.2%}")
        if self.lift is not None:
            lines.append(f"    {'lift (realised/product)':<28} {self.lift:7.2f}")
        removed = self.removed_by_conjunction
        if removed is not None:
            lines.append(
                f"    {'removed beyond loosest':<28} {removed:7.2%} "
                "of what the loosest condition admitted"
            )
        if self.exclusion_reasons:
            reasons = ", ".join(f"{name} {count:,}" for name, count in self.exclusion_reasons)
            lines.append(f"    excluded: {reasons}")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class RedundancyReport:
    day: str
    rules: tuple[RuleRedundancy, ...]

    def render(self) -> str:
        lines = [
            f"day {self.day}",
            "",
            "Rates are over the units each rule was evaluated on. A lift near 1 is a screen for",
            "redundancy, not a proof of independence: pairwise independence does not establish",
            "joint independence.",
            "",
        ]
        for rule in self.rules:
            lines.append(rule.render())
            lines.append("")
        return "\n".join(lines).rstrip()


def measure_redundancy(day: str, log: ConditionLog) -> RedundancyReport:
    """Turn a run's condition log into the §5 table. Reports every rule, single-condition ones
    included, because a marginal is worth having even where there is no conjunction to test."""

    grouped: dict[tuple[str, Combinator], list[tuple[tuple[tuple[str, bool], ...], int]]] = {}
    for (rule, combinator, vector), count in log.observations.items():
        grouped.setdefault((rule, combinator), []).append((vector, count))

    rules = []
    for (rule, combinator), rows in sorted(grouped.items()):
        names: list[str] = []
        for vector, _ in rows:
            for name, _value in vector:
                if name not in names:
                    names.append(name)
        evaluated = sum(count for _, count in rows)
        marginals = tuple(
            ConditionMarginal(
                name,
                sum(count for vector, count in rows if dict(vector).get(name, False)),
                evaluated,
            )
            for name in names
        )
        satisfied = sum(
            count
            for vector, count in rows
            if _satisfies(combinator, [value for _, value in vector])
        )
        reasons = tuple(
            sorted(
                (
                    (reason, count)
                    for (name, reason), count in log.exclusions.items()
                    if name == rule
                ),
                key=lambda item: (-item[1], item[0]),
            )
        )
        rules.append(
            RuleRedundancy(
                rule,
                combinator,
                evaluated,
                sum(count for _, count in reasons),
                reasons,
                marginals,
                satisfied,
            )
        )
    return RedundancyReport(day, tuple(rules))


def _satisfies(combinator: Combinator, values: list[bool]) -> bool:
    return all(values) if combinator is Combinator.ALL else any(values)
