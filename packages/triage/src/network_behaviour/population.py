"""What it means for an observed address to be in scope for behavioural comparison.

The support gate decides which addresses have a behavioural day at all. Everything downstream
rests on that decision: it is the denominator of every rarity strength, the membership of every
peer band, and the population a baseline is built from. It was two integers on `DetectorPolicy`
and an inline `or` inside one detector, and nothing counted what it excluded.

Three things this module exists to make possible, none of which change behaviour on its own:

- **A definition that can be stated.** `SupportDefinition` names its arms and how they combine, and
  renders itself, so `population.support_definition` in the registry is the same object the code
  applies rather than a string describing it.
- **A count of what falls outside.** `take_census` reports every observed address as admitted or
  excluded, and — because this is what showed the current gate to be decorative — which arm alone
  carried each admission.
- **Alternatives that can be compared.** A candidate definition is measured against the current one
  before either is chosen. Any candidate expressible as minimums over client-day quantities needs
  no new code to evaluate.

**The gate is now empty, and that is the measured answer rather than a deferral.** Until
`behavioural-support-v2` the definition was `active_5m_buckets >= 10 or flow_count >= 100`, and
every measurement of it said it decided nothing worth deciding:

| Quantity | p1 | p50 | p99 |
|---|---|---|---|
| `active_5m_buckets` | 288 | 288 | 288 |
| `flow_count` | 0 | 0 | 10,021 |
| `unique_services` | 0 | 0 | 79 |

The first percentile of `active_5m_buckets` was already the daily maximum, so that arm admitted
every address; the flow arm alone decided 0 to 2 admissions a day. Between them they excluded 1 to
4 addresses of roughly 12,200 (measured 2026-08-25 over the 37 retained days).

What they excluded is the argument for removing them. On 2026-08-09 the three excluded addresses
were:

    buckets=8  flows=2  services=1  up=0  down=38,548,743
    buckets=8  flows=2  services=1  up=0  down=52,052,545
    buckets=8  flows=0  services=0  up=60  down=604

Two of them pulled tens of megabytes through a single service in two flows. A gate whose whole
effect is to hide those is not a conservative default; it is a blind spot with a threshold in front
of it. `client_ip` is an observed address and not a device (`CASE_STUDY` §6), so "this address
looks too quiet to be a host" was never a question this data could answer.

**Removing the gate does not move any denominator.** Prevalence is counted over
`history.client_service_day` since `baseline-calibration-v3`, and those addresses already had
service rows there — 135 across the 37 retained days. The gate governed eligibility for detection
only. Dropping it makes those addresses detectable; it changes no rarity, no band and no baseline
population.

**The census stays, and is the part that earns its keep.** It reports what each run put in scope
and why. An empty definition makes every observed address supported, which is a claim a run should
still state explicitly rather than leave implied — and `compare_definitions` still evaluates any
candidate gate against real data, should one ever be justified.

**`behavioural-support-v3` admits addresses with at least one service row.** This is not the
retired gate's question — whether an address is too quiet to be a host — but whether any of its
traffic can be interpreted at all. Measured 2026-10-22/23 (`CASE_STUDY` §2, §3): 60-75% of
observed addresses carry nothing but unaddressed `Web Browsing` rows, with no server address, port
or domain, whose meaning is not established. Under v2 the transfer and fanout families scored them
on those bytes as "external" activity, and they made up the peer and calibration pools of the
lowest destination band: 6,801 of its 6,967 members on 2026-10-14. That contradicted the contract,
which said no detector scores them, and the drift gate, which leaves them ungated because they
move nothing. Both are now true. The two 2026-08-09 exclusions above that moved tens of megabytes
had a service row each, so v3 keeps them in scope; the third did not.

DNS is not gated here. `activity_1m` carries no DNS rows (`CASE_STUDY` §9), so an
address whose only traffic is DNS has no service row, and the DNS family scores its own population
of addresses that sent a query (`detectors/dns.py`).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from network_behaviour.aggregation import ClientDayRow

POPULATION_VERSION = "behavioural-support-v3"


class SupportArm(StrEnum):
    """A client-day quantity a support definition may set a floor on."""

    ACTIVE_5M_BUCKETS = "active_5m_buckets"
    FLOW_COUNT = "flow_count"
    UNIQUE_SERVICES = "unique_services"
    UNIQUE_SERVERS = "unique_servers"
    UP_BYTES = "up_bytes"


class SupportCombinator(StrEnum):
    ANY = "any"
    ALL = "all"


@dataclass(frozen=True, slots=True)
class SupportDefinition:
    """Minimums over client-day quantities, and how they combine into one decision."""

    minimums: tuple[tuple[SupportArm, int], ...]
    """Empty means no gate: every observed address is admitted.

    Handled by an explicit branch in `admits`, never by the vacuous truth of `all(())` — those two
    read identically at the call site and mean opposite things under `ANY`.
    """

    combinator: SupportCombinator = SupportCombinator.ANY
    version: str = POPULATION_VERSION

    @property
    def is_ungated(self) -> bool:
        return not self.minimums

    def __post_init__(self) -> None:
        arms = tuple(arm for arm, _ in self.minimums)
        if len(arms) != len(set(arms)):
            raise ValueError("a support definition names each arm at most once")
        if any(minimum < 0 for _, minimum in self.minimums):
            raise ValueError("a support minimum cannot be negative")
        if not self.version.strip():
            raise ValueError("a support definition needs a version identifier")

    def arm_results(self, row: ClientDayRow) -> tuple[bool, ...]:
        return self._arm_results(lambda name: getattr(row, name))

    def admits(self, row: ClientDayRow) -> bool:
        return self.admits_quantities(lambda name: getattr(row, name))

    def admits_quantities(self, quantity: Callable[[str], float]) -> bool:
        """The same decision over any client-day the caller can read a quantity from by name.

        Retained history reaches baselines as metric vectors rather than `ClientDayRow`s; one
        decision function keeps the pools and the detectors from disagreeing about who is in scope.
        """
        if self.is_ungated:
            return True
        results = self._arm_results(quantity)
        return any(results) if self.combinator is SupportCombinator.ANY else all(results)

    def _arm_results(self, quantity: Callable[[str], float]) -> tuple[bool, ...]:
        return tuple(quantity(arm.value) >= minimum for arm, minimum in self.minimums)

    def describe(self) -> str:
        """The definition as the registry states it, rendered from the object that applies it."""
        if self.is_ungated:
            return "every observed address"
        joiner = f" {self.combinator.value.replace('any', 'or').replace('all', 'and')} "
        return joiner.join(f"{arm.value} >= {minimum}" for arm, minimum in self.minimums)


CURRENT_SUPPORT_DEFINITION = SupportDefinition(((SupportArm.UNIQUE_SERVICES, 1),))
"""An address is in scope when at least one of its rows resolved to a service.

The addresses this admits are exactly the ones with a row in `history.client_service_day`, the
scored population `drift.population_step` gates. See the module docstring for why v3 differs from
the gate `behavioural-support-v2` removed.
"""

RETIRED_SUPPORT_DEFINITION_V2 = SupportDefinition((), version="behavioural-support-v2")
"""No gate: every observed address in scope. Kept so a day published under `primary-detectors-v3`
to `-v8` can be replayed with the definition it actually used.

Its own predecessor, `active_5m_buckets >= 10 or flow_count >= 100`, is
`RETIRED_SUPPORT_DEFINITION_V1` below — see the module docstring for what it excluded.
"""

RETIRED_SUPPORT_DEFINITION_V1 = SupportDefinition(
    (
        (SupportArm.ACTIVE_5M_BUCKETS, 10),
        (SupportArm.FLOW_COUNT, 100),
    ),
    SupportCombinator.ANY,
    version="behavioural-support-v1",
)


@dataclass(frozen=True, slots=True)
class ArmCensus:
    arm: str
    passed: int
    decided_alone: int
    """Admissions this arm alone carried. Zero means the arm changes no decision."""


@dataclass(frozen=True, slots=True)
class PopulationCensus:
    """Every observed address, counted in or out. Reported, never silently dropped."""

    day: str
    definition: str
    definition_version: str
    observed: int
    supported: int
    arms: tuple[ArmCensus, ...]

    @property
    def out_of_scope(self) -> int:
        return self.observed - self.supported

    @property
    def supported_fraction(self) -> float:
        return self.supported / self.observed if self.observed else 0.0

    def render(self) -> str:
        lines = [
            f"day {self.day}  definition `{self.definition}` ({self.definition_version})",
            f"observed {self.observed:,}  supported {self.supported:,} "
            f"({self.supported_fraction:.2%})  out of scope {self.out_of_scope:,}",
        ]
        if not self.arms:
            lines.append("  no gate — every observed address is in scope")
        for arm in self.arms:
            note = " — changes no decision" if not arm.decided_alone else ""
            lines.append(
                f"  {arm.arm:<20} passed {arm.passed:>8,}  "
                f"decided alone {arm.decided_alone:>8,}{note}"
            )
        return "\n".join(lines)


def take_census(
    day: str,
    rows: Sequence[ClientDayRow],
    definition: SupportDefinition = CURRENT_SUPPORT_DEFINITION,
) -> PopulationCensus:
    """Count every observed address in or out, and attribute each admission to an arm."""

    if definition.is_ungated:
        return PopulationCensus(
            day, definition.describe(), definition.version, len(rows), len(rows), ()
        )
    passed = [0] * len(definition.minimums)
    decided_alone = [0] * len(definition.minimums)
    supported = 0
    for row in rows:
        results = definition.arm_results(row)
        admitted = any(results) if definition.combinator is SupportCombinator.ANY else all(results)
        supported += admitted
        for index, result in enumerate(results):
            passed[index] += result
        if admitted and sum(results) == 1:
            # Exactly one arm carried this admission under ANY; under ALL every arm is load
            # bearing, so the count stays meaningful only for the disjunction.
            decided_alone[results.index(True)] += 1
    return PopulationCensus(
        day,
        definition.describe(),
        definition.version,
        len(rows),
        supported,
        tuple(
            ArmCensus(arm.value, passed[index], decided_alone[index])
            for index, (arm, _) in enumerate(definition.minimums)
        ),
    )


def compare_definitions(
    day: str,
    rows: Sequence[ClientDayRow],
    definitions: Iterable[SupportDefinition],
) -> tuple[PopulationCensus, ...]:
    """One census per candidate, so two definitions are compared on data before either is chosen."""

    return tuple(take_census(day, rows, definition) for definition in definitions)
