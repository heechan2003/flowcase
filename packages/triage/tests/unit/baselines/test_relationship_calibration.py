"""Where a relationship strength comes from — `baseline-calibration-v4`.

The detector tests pin what the engine does with a strength. These pin the property that makes
that strength mean anything: it is an empirical tail probability over the day's own relationship
population, on the same scale as every client metric strength, replacing a four-rung lookup ladder
that returned 100.0, 99.0, 98.0 or 97.5 on the same 0-100 scale as a prevalence.
"""

from __future__ import annotations

from dataclasses import replace

from network_behaviour.baselines.engine import _calibrate_relationships
from network_behaviour.baselines.models import (
    RelationshipBaselineContext,
    ServiceConfidence,
)


def _unit(
    index: int,
    *,
    prior_days: int = 0,
    days_since: int | None = None,
    prevalence: float = 0.5,
) -> RelationshipBaselineContext:
    new = days_since is None
    return RelationshipBaselineContext(
        f"10.20.1.{index}",
        f"{index:032x}",
        64500,
        ServiceConfidence.HIGH,
        prior_days,
        days_since,
        new,
        prior_days,
        days_since,
        new,
        prevalence,
        prevalence,
        prevalence,
        prevalence,
    )


def _population() -> tuple[RelationshipBaselineContext, ...]:
    """Twenty units: one rare first contact, and nineteen ordinary well-known ones."""
    rare_and_new = _unit(0, prevalence=0.001)
    ordinary = tuple(
        _unit(index, prior_days=30, days_since=1, prevalence=0.5 + index / 100)
        for index in range(1, 20)
    )
    return (rare_and_new, *ordinary)


def test_strengths_are_tail_probabilities_over_the_day() -> None:
    calibrated = _calibrate_relationships(_population())

    assert len(calibrated) == 20
    for item in calibrated:
        assert 0.0 <= item.novelty_strength <= 100.0
        assert 0.0 <= item.rarity_strength <= 100.0
        assert 0.0 <= item.joint_strength <= 100.0

    extreme = calibrated[0]
    assert extreme.joint_strength == max(item.joint_strength for item in calibrated)
    assert extreme.rarity_strength == max(item.rarity_strength for item in calibrated)


def test_never_contacted_destinations_share_one_novelty_and_cap_the_axis() -> None:
    """ "Never" has no degrees, and that ceiling is why novelty is not thresholded alone.

    On 2026-08-09, 9,381 of 125,862 units were first contacts, putting the ceiling of this axis
    at 96.27 — below `strength.moderate`. A rule that compared novelty alone against that
    threshold would admit nothing, which is what `CASE_STUDY.md`, evaluations records as measured.
    """
    population = (
        *(_unit(index) for index in range(4)),
        *(_unit(index, prior_days=10, days_since=2) for index in range(4, 20)),
    )
    calibrated = _calibrate_relationships(population)
    first_contacts = calibrated[:4]

    assert len({item.novelty_strength for item in first_contacts}) == 1
    ceiling = first_contacts[0].novelty_strength
    assert ceiling == max(item.novelty_strength for item in calibrated)
    # Four of twenty units tied at the top: the midpoint rank puts the ceiling at 1 - 4/40.
    assert ceiling == 90.0


def test_calibration_is_relative_so_one_unit_carries_no_strength() -> None:
    """A population of one is at its own midpoint. This is why fixtures set strengths directly."""

    only = _calibrate_relationships((_unit(0, prevalence=0.001),))[0]

    assert only.novelty_strength == 50.0
    assert only.rarity_strength == 50.0
    assert only.joint_strength == 50.0


def test_calibration_is_invariant_to_the_population_size_the_prevalence_was_over() -> None:
    """`CASE_STUDY` §2: the distinct-address count halved on 2026-08-11 and no gate reacted.

    Every uncalibrated strength is `100 * (1 - k/N)`, so halving `N` rescales all of them. A tail
    probability is a rank, so rescaling every prevalence by a constant cannot move it.
    """
    population = _population()
    halved = tuple(
        replace(
            item,
            historical_service_prevalence=item.historical_service_prevalence * 2,
            historical_route_prevalence=(item.historical_route_prevalence or 0.0) * 2,
            current_service_prevalence=item.current_service_prevalence * 2,
            current_route_prevalence=(item.current_route_prevalence or 0.0) * 2,
        )
        for item in population
    )

    before = [item.rarity_strength for item in _calibrate_relationships(population)]
    after = [item.rarity_strength for item in _calibrate_relationships(halved)]

    assert before == after


def test_calibration_is_deterministic_and_order_independent() -> None:
    """Reruns are byte-stable, and the pool is a set of values rather than a sequence."""
    population = _population()
    first = _calibrate_relationships(population)
    again = _calibrate_relationships(population)

    assert [item.joint_strength for item in first] == [item.joint_strength for item in again]

    reversed_input = tuple(reversed(population))
    reversed_output = {
        item.client_ip: item.joint_strength for item in _calibrate_relationships(reversed_input)
    }
    assert {item.client_ip: item.joint_strength for item in first} == reversed_output


def test_an_empty_day_calibrates_to_nothing() -> None:
    assert _calibrate_relationships(()) == ()
