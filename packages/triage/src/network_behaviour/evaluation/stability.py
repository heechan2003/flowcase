"""§3 rank stability: would the same run tomorrow, on slightly different data, order the same?

Three perturbations, each answering a different version of the question:

- **Population resampling.** Drop a random share of hosts and re-score. This is a subsample, not a
  bootstrap with replacement, and the deviation from §3's wording is deliberate: `client_ip` is the
  join key for retained history *and* the denominator of every rarity strength, so a duplicated
  host is not representable — it would either collide with itself in history or need a fabricated
  label with fabricated history. The subsample answers the same question without inventing data.
- **Day hold-out.** Re-seed history without some days and re-score. Handled by the caller, which
  owns the connection; this module compares the outcomes.
- **Parameter perturbation.** Move one parameter within its stated precision and re-score.

Measured over the stream's own episode order, not a downstream queue. A Spearman correlation over
an ordering that is mostly ties is measuring the tie-break, and `CASE_STUDY` §12 says ~90% of
adjacent in-tier pairs tie on every substantive key. Report the tied share alongside the number, or
it reads as a flattering artefact.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from random import Random

from network_behaviour.evaluation.harness import DayEvaluator, RunOutcome, restrict_to_clients
from network_behaviour.evaluation.statistics import shared_order_correlation, summarize


@dataclass(frozen=True, slots=True)
class Comparison:
    """One perturbed run against the baseline."""

    label: str
    episode_spearman: float | None
    episode_overlap: int
    episode_count: int
    host_count: int
    tied_episode_share: float

    def render(self) -> str:
        return (
            f"  {self.label:<28} rho(episode) {_number(self.episode_spearman)}  "
            f"episodes {self.episode_count:,}  hosts {self.host_count:,}  "
            f"tied {self.tied_episode_share:.1%}"
        )


@dataclass(frozen=True, slots=True)
class StabilityReport:
    day: str
    seed: int
    baseline_episodes: int
    baseline_hosts: int
    baseline_tied_episode_share: float
    comparisons: tuple[Comparison, ...]

    def group(self, prefix: str) -> tuple[Comparison, ...]:
        return tuple(item for item in self.comparisons if item.label.startswith(prefix))

    def render(self) -> str:
        lines = [
            f"day {self.day}  seed {self.seed}",
            f"baseline: {self.baseline_episodes:,} episodes over {self.baseline_hosts:,} hosts",
            f"baseline episodes inside a tie group: {self.baseline_tied_episode_share:.1%} "
            "— that share is not ordered at all",
            "",
        ]
        if self.baseline_tied_episode_share > 0.5:
            lines[-1] = (
                "WARNING: most of the stream is tied, so the correlations below are largely "
                "measuring\nthe stable-digest tie-break reproducing itself, not an ordering "
                "that survived a perturbation.\nRead them with the tied share, never alone.\n"
            )
        lines.extend(item.render() for item in self.comparisons)
        for prefix in ("resample", "parameter", "holdout"):
            group = self.group(prefix)
            values = [item.episode_spearman for item in group if item.episode_spearman is not None]
            if values:
                low, median, high = summarize(values)
                lines.append(
                    f"\n{prefix}: episode rho min {low:.3f} median {median:.3f} max {high:.3f} "
                    f"over {len(group)} run(s)"
                )
        return "\n".join(lines)


def compare(baseline: RunOutcome, variant: RunOutcome) -> Comparison:
    episode_rho, episode_shared = shared_order_correlation(
        [str(item.episode_id) for item in baseline.episodes],
        [str(item.episode_id) for item in variant.episodes],
    )
    return Comparison(
        variant.label,
        episode_rho,
        episode_shared,
        variant.episode_count,
        variant.host_count,
        tied_episode_share(variant),
    )


def tied_episode_share(outcome: RunOutcome) -> float:
    """Share of episodes sitting in a `tie_group` with at least one other episode.

    Computed at the stream's own episode grain, which the publisher emits regardless of any
    downstream projection — `CASE_STUDY` §12: ~90% of adjacent in-tier pairs tie already.
    """

    counts: dict[int, int] = {}
    for episode in outcome.episodes:
        counts[episode.tie_group] = counts.get(episode.tie_group, 0) + 1
    total = len(outcome.episodes)
    if not total:
        return 0.0
    return sum(count for count in counts.values() if count > 1) / total


def resample_hosts(
    evaluator: DayEvaluator,
    *,
    seed: int,
    replicates: int = 10,
    keep_fraction: float = 0.8,
) -> tuple[RunOutcome, ...]:
    """Score the day `replicates` times on random subsamples of the host population."""

    if not 0 < keep_fraction < 1:
        raise ValueError("the kept fraction must sit strictly between zero and one")
    population = sorted({row.client_ip for row in evaluator.staged.client_rows})
    size = max(2, round(len(population) * keep_fraction))
    outcomes = []
    for index in range(replicates):
        rng = Random(seed + index)
        kept = frozenset(rng.sample(population, size))
        outcomes.append(evaluator.run(f"resample-{index}", transform=restrict_to_clients(kept)))
    return tuple(outcomes)


def perturb_parameters(
    evaluator: DayEvaluator,
    *,
    deltas: Sequence[float] = (-0.5, 0.5),
) -> tuple[RunOutcome, ...]:
    """Move each ranking strength threshold within its stated precision and re-score.

    The registry states these to one decimal place, so half a point is the smallest move that is
    not a rounding artefact. A ranking that reorders under it was never resting on the threshold.
    """

    outcomes = []
    base = evaluator.policies.ranking
    for field_name in ("moderate_strength", "strong_strength"):
        for delta in deltas:
            value = getattr(base, field_name) + delta
            try:
                ranking = replace(base, **{field_name: value})
            except ValueError:
                continue
            outcomes.append(
                evaluator.run(
                    f"parameter-{field_name}{delta:+}",
                    policies=replace(evaluator.policies, ranking=ranking),
                )
            )
    return tuple(outcomes)


def build_report(
    evaluator: DayEvaluator,
    variants: Sequence[RunOutcome],
    *,
    seed: int,
) -> StabilityReport:
    baseline = evaluator.baseline()
    return StabilityReport(
        str(evaluator.day),
        seed,
        baseline.episode_count,
        baseline.host_count,
        tied_episode_share(baseline),
        tuple(compare(baseline, item) for item in variants),
    )


def _number(value: float | None) -> str:
    return "  n/a" if value is None else f"{value:5.3f}"
