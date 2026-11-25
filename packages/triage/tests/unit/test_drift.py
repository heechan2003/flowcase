"""The fail-closed gates on the source changing shape underneath a day.

Tier 0 invariant 5 named *population drift beyond tolerance* long before anything implemented it,
and the first implementation gated a population no detector scores. These tests exist so the
invariant, the population it protects and the code cannot separate again.
"""

from __future__ import annotations

from datetime import date

import pytest

from network_behaviour.drift import (
    COMPOSITION_TVD,
    DNS_POPULATION_STEP_FRACTION,
    POPULATION_STEP_FRACTION,
    DayShape,
    DriftAssessment,
    DriftCheck,
    DriftPolicy,
    assess,
    assess_dns_coverage,
    basis_counts,
    total_variation_distance,
)

DAY = date(2026, 9, 16)
SAME_WEEKDAY = date(2026, 9, 9)
YESTERDAY = date(2026, 9, 15)


def _shape(
    day: date,
    population: int,
    *,
    domain: int = 9_875,
    asn: int = 123,
    ip: int = 2,
    unaddressed_only: int | None = None,
) -> DayShape:
    return DayShape(
        day,
        population,
        (("application_asn", asn), ("domain", domain), ("server_ip", ip)),
        unaddressed_only,
    )


def _population(result: DriftAssessment) -> DriftCheck:
    return next(check for check in result.checks if check.name == "population_step")


def test_a_halving_of_the_scored_population_fails_closed() -> None:
    """The failure the gate exists for: half the addresses with a service row gone.

    Under `drift-gates-v1` this was invisible. About 7,000 addresses carrying only unaddressed rows
    held the gated count nearly constant, so 4,400 -> 2,200 scored addresses moved it about 19%.
    """

    result = assess(
        _shape(DAY, 2_200, unaddressed_only=7_000),
        _shape(SAME_WEEKDAY, 4_400),
        _shape(YESTERDAY, 4_300),
    )

    assert not result.passed
    reason = result.failure_reason()
    assert reason is not None
    assert "population_step" in reason
    assert "4,400 -> 2,200 addresses with a service row" in reason


def test_the_v1_seam_publishes_because_the_scored_population_did_not_step() -> None:
    """2026-09-13 -> 09-16: all observed 10,579 -> 5,987 (-43%), scored 3,498 -> 4,454.

    v1 aborted this day and was widened to 0.44 to admit it. Every address that vanished carried
    only unaddressed rows. Against the prior Wednesday the scored population barely moved.
    """

    result = assess(
        _shape(DAY, 4_454, unaddressed_only=1_533),
        _shape(SAME_WEEKDAY, 4_300),
        _shape(date(2026, 9, 13), 3_498),
    )

    assert result.passed
    assert "1,533 observed address(es) with no service row" in result.render()


def test_the_loudest_legitimate_same_weekday_move_still_publishes() -> None:
    """2026-10-04 -> 10-11, the rebound after the public-holiday weekend: 2,799 -> 3,663."""

    result = assess(
        _shape(date(2026, 10, 11), 3_663),
        _shape(date(2026, 10, 4), 2_799),
        _shape(date(2026, 10, 10), 2_816),
    )

    assert result.passed
    population = _population(result)
    assert population.measured is not None
    assert population.measured == pytest.approx(0.3087, abs=5e-4)
    assert population.measured < POPULATION_STEP_FRACTION


def test_the_week_is_not_drift() -> None:
    """A Saturday carries about 2,800 scored addresses and a Tuesday about 4,500.

    The population check compares weekday to weekday, so the weekly swing never reaches it; the
    caller supplies the same-weekday prior, and the render says which day it was.
    """

    saturday = date(2026, 10, 17)
    result = assess(
        _shape(saturday, 2_797),
        _shape(date(2026, 10, 10), 2_816),
        _shape(date(2026, 10, 16), 3_626),
    )

    assert result.passed
    assert result.population_gap_days == 7
    assert result.composition_gap_days == 1
    assert "2026-10-10 (same weekday, gap 7d)" in result.render()


def test_a_source_that_stops_resolving_domains_fails_closed_without_moving_the_population() -> None:
    """The failure the population gate cannot see: same address count, redefined services.

    On 2026-08-09 the `domain` basis carried 98.75% of service rows. An upstream change that
    stopped resolving names would move all of it to `server_ip` while every host stayed present,
    silently redefining what novelty and rarity are computed over.
    """

    current = DayShape(DAY, 4_400, (("application_asn", 123), ("server_ip", 9_877)))

    result = assess(current, _shape(SAME_WEEKDAY, 4_400), _shape(YESTERDAY, 4_400))

    assert not result.passed
    reason = result.failure_reason()
    assert reason is not None
    assert "composition_tvd" in reason


def test_composition_compares_against_the_most_recent_day_not_the_weekday() -> None:
    """The basis mix does not follow the week, so it keeps the nearest comparison."""

    current = DayShape(DAY, 4_400, (("application_asn", 123), ("server_ip", 9_877)))
    shifted_yesterday = DayShape(YESTERDAY, 4_300, (("application_asn", 123), ("server_ip", 9_877)))

    result = assess(current, _shape(SAME_WEEKDAY, 4_400), shifted_yesterday)

    assert result.passed


def test_the_loudest_legitimate_composition_move_still_publishes() -> None:
    """Measured max TVD over 36 comparisons was 0.00281, against a tolerance of 0.05."""

    result = assess(
        _shape(DAY, 4_400, domain=9_850, asn=148, ip=2),
        _shape(SAME_WEEKDAY, 4_400),
        _shape(YESTERDAY, 4_300, domain=9_875, asn=123, ip=2),
    )

    assert result.passed
    composition = next(check for check in result.checks if check.name == "composition_tvd")
    assert composition.measured is not None
    assert composition.measured < COMPOSITION_TVD


def test_the_first_day_a_deployment_publishes_has_nothing_to_drift_from() -> None:
    """Failing closed on the absence of a prior day would make the first run impossible."""

    result = assess(_shape(DAY, 4_400), None, None)

    assert result.passed
    assert result.population_gap_days is None
    assert result.composition_gap_days is None
    assert all(check.measured is None for check in result.checks)
    assert "no prior published day" in result.render()


def test_a_first_week_day_compares_composition_but_has_no_weekday_to_compare_population() -> None:
    result = assess(_shape(DAY, 4_400), None, _shape(YESTERDAY, 4_300))

    assert result.passed
    assert _population(result).measured is None
    assert "no earlier day with the same UTC weekday" in result.render()


def test_a_prior_day_with_no_population_fails_rather_than_dividing_by_it() -> None:
    """A published day recording no scored host is already broken; it must not become a crash."""

    result = assess(_shape(DAY, 4_400), DayShape(SAME_WEEKDAY, 0, ()), _shape(YESTERDAY, 4_300))

    assert not result.passed
    assert "recorded no population" in str(result.failure_reason())


def test_a_day_with_no_service_rows_fails_rather_than_comparing_nothing() -> None:
    result = assess(DayShape(DAY, 0, ()), None, _shape(YESTERDAY, 4_300))

    assert not result.passed
    assert "no service rows" in str(result.failure_reason())


def test_gaps_are_reported_and_not_compensated_for() -> None:
    """Retained history is not contiguous. 2026-09-06 compares against 2026-08-09, 28 days back.

    Every same-weekday pair across a gap in retained history moved at most 5.4%, so there is no
    measured basis for widening the tolerance across one. The gap is carried so a reader can weigh
    the comparison, and that is all it does.
    """

    result = assess(
        _shape(date(2026, 9, 6), 3_334),
        _shape(date(2026, 8, 9), 3_523),
        _shape(date(2026, 9, 5), 2_765),
    )

    assert result.population_gap_days == 28
    assert "gap 28d" in result.render()
    assert result.passed


def test_the_distance_treats_a_vanished_basis_as_maximal_movement() -> None:
    assert total_variation_distance({"domain": 1.0}, {"server_ip": 1.0}) == pytest.approx(1.0)
    assert total_variation_distance({"domain": 1.0}, {"domain": 1.0}) == 0.0


def test_counts_are_tallied_deterministically() -> None:
    assert basis_counts(["domain", "asn", "domain"]) == (("asn", 1), ("domain", 2))
    assert basis_counts([]) == ()


def test_a_policy_states_tolerances_that_could_actually_fire() -> None:
    """A tolerance of zero or one is a gate that always fires or never does. Neither is a gate."""

    assert DriftPolicy().population_step_fraction == POPULATION_STEP_FRACTION
    with pytest.raises(ValueError, match="population step tolerance"):
        DriftPolicy(population_step_fraction=0.0)
    with pytest.raises(ValueError, match="composition tolerance"):
        DriftPolicy(composition_tvd=1.5)
    with pytest.raises(ValueError, match="version identifier"):
        DriftPolicy(version="  ")
    with pytest.raises(ValueError, match="unaddressed-only"):
        DayShape(DAY, 1, (), unaddressed_only=-1)


def test_dns_coverage_that_moves_beyond_tolerance_disables_dns_and_nothing_else() -> None:
    """DNS is optional context. A moved DNS population turns the family off; the day publishes."""

    coverage = assess_dns_coverage(DAY, 150, (SAME_WEEKDAY, 320))

    assert not coverage.dns_enabled
    assert "320 -> 150 DNS clients" in coverage.check.detail
    assert "DNS disabled for this day" in coverage.render()


def test_dns_coverage_within_the_week_keeps_dns() -> None:
    """2026-10-14 and 2026-10-21 both carried 324 query-sending clients."""

    coverage = assess_dns_coverage(date(2026, 10, 21), 324, (date(2026, 10, 14), 324))

    assert coverage.dns_enabled
    assert coverage.check.measured == 0.0
    assert "gap 7d" in coverage.render()


def test_dns_coverage_with_no_same_weekday_day_keeps_dns_and_says_so() -> None:
    coverage = assess_dns_coverage(DAY, 300, None)

    assert coverage.dns_enabled
    assert coverage.check.measured is None
    assert "no earlier DNS day" in coverage.render()


def test_the_dns_tolerance_is_a_tolerance() -> None:
    assert DriftPolicy().dns_population_step_fraction == DNS_POPULATION_STEP_FRACTION
    with pytest.raises(ValueError, match="DNS population step tolerance"):
        DriftPolicy(dns_population_step_fraction=0.0)
