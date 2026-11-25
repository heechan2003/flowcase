"""Optional observation of multi-condition decisions. Never changes one.

`docs/EVALUATION.md` §5 requires, for any rule needing more than one condition, the realised
joint rate against the product of the marginals. That is unobservable from the published stream:
a unit failing a conjunction leaves either a diagnostic with no evidence attached or nothing at
all, so the denominator — every unit the rule was evaluated against — is not recoverable after
the fact.

The alternative to recording it here is a second implementation of every conjunction inside the
evaluation harness, which is the drift this repository is recovering from. So the engines call a
recorder at the exact site where they decide, and the harness reads what the engine actually did.

Two properties keep this safe to leave in the production path:

- **Write-only.** Nothing in `src/` reads a recorder. Passing one cannot change an output, and
  `tests/unit/test_instrumentation.py` pins byte-identical batches with and without one.
- **Identifier-free.** A `ConditionLog` accumulates counts keyed by the condition vector. No
  client address, service digest or domain enters it, so a log is safe to write to a bundle.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol


class Combinator(StrEnum):
    """How the recorded conditions combine into the decision the engine took."""

    ALL = "all"
    ANY = "any"


ConditionVector = tuple[tuple[str, bool], ...]
ObservationKey = tuple[str, Combinator, ConditionVector]


class ConditionRecorder(Protocol):
    """Write-only sink for condition outcomes at a decision site."""

    def record(self, rule: str, combinator: Combinator, /, **conditions: bool) -> None:
        """Record one unit that reached `rule` with these condition outcomes."""

    def exclude(self, rule: str, reason: str) -> None:
        """Record one unit that never reached `rule`, and why."""


@dataclass(slots=True)
class ConditionLog:
    """Counts only. Deterministic under a deterministic run; carries no identifier."""

    observations: Counter[ObservationKey] = field(default_factory=Counter)
    exclusions: Counter[tuple[str, str]] = field(default_factory=Counter)

    def record(self, rule: str, combinator: Combinator, /, **conditions: bool) -> None:
        self.observations[(rule, combinator, tuple(conditions.items()))] += 1

    def exclude(self, rule: str, reason: str) -> None:
        self.exclusions[(rule, reason)] += 1

    def rules(self) -> tuple[str, ...]:
        seen = {key[0] for key in self.observations} | {rule for rule, _ in self.exclusions}
        return tuple(sorted(seen))

    def evaluated(self, rule: str) -> int:
        """Units that reached `rule`. The denominator for every rate in §5."""
        return sum(count for key, count in self.observations.items() if key[0] == rule)

    def excluded(self, rule: str) -> int:
        """Units that never reached `rule`, so are in no marginal."""
        return sum(count for (name, _), count in self.exclusions.items() if name == rule)
