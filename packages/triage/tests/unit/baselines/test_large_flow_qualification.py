"""What makes a large flow corroborating evidence — `baseline-calibration-v5`.

Under the retired rule a large flow corroborated an episode by existing, which on 2026-08-09 was
true of 26.01% of eligible relationship units and, per `CASE_STUDY` §8, of 80% of active
addresses. These pin the replacement: a tail probability against the pool of large flows the same
host has already made, so "large" is measured against that host rather than against a fixed
1 MB the source table has already filtered on.
"""

from __future__ import annotations

from network_behaviour.baselines.engine import _large_flow_strengths, _LargeFlowReference
from network_behaviour.baselines.models import BaselinePolicy
from network_behaviour.detectors.models import CORROBORATION_STRENGTH

POLICY = BaselinePolicy()


def _reference(count: int = 100) -> _LargeFlowReference:
    """A host whose large flows are ordinary: 1 MB to 100 MB, one second to one hour."""
    sizes = tuple(float(1_000_000 + index * 1_000_000) for index in range(count))
    durations = tuple(float(1 + index * 36) for index in range(count))
    return _LargeFlowReference(sizes, durations)


def test_a_flow_at_the_top_of_the_hosts_own_history_qualifies_on_either_axis() -> None:
    reference = _reference()

    # Ten gigabytes in five seconds, then two megabytes held open for a day.
    big_size, big_duration, big = _large_flow_strengths(1, 10_000_000_000.0, 5.0, reference, POLICY)
    slow_size, slow_duration, slow = _large_flow_strengths(
        1, 2_000_000.0, 86_400.0, reference, POLICY
    )

    assert big_size > CORROBORATION_STRENGTH > big_duration
    assert slow_duration > CORROBORATION_STRENGTH > slow_size
    # The combined strength takes the more extreme axis: size and duration are alternative ways
    # for one transfer to be unusual, and requiring both would demand a flow be simultaneously
    # the host's biggest and its longest.
    assert big == big_size
    assert slow == slow_duration


def test_a_flow_typical_for_the_host_does_not_qualify_however_many_bytes_it_moved() -> None:
    # 50 MB and ten minutes: a large flow by the source table's 1 MB filter and by any absolute
    # reading, and the median of what this host does. This is the case the retired rule promoted.
    *_, ordinary = _large_flow_strengths(3, 50_000_000.0, 600.0, _reference(), POLICY)

    assert ordinary < CORROBORATION_STRENGTH


def test_no_large_flow_scores_zero_rather_than_a_percentile_of_nothing() -> None:
    assert _large_flow_strengths(0, 0.0, 0.0, _reference(), POLICY) == (0.0, 0.0, 0.0)


def test_a_host_with_too_little_of_its_own_history_fails_closed() -> None:
    """A midpoint rank over n tops out at (n - 0.5)/n, so a short pool cannot reach the tail.

    Below the floor the answer is zero rather than a strength the pool cannot support: the flow
    still reaches the stream as context, and it does not promote a tier.
    """
    short = _reference(POLICY.large_flow_reference_min_units - 1)

    assert _large_flow_strengths(1, 10_000_000_000.0, 86_400.0, short, POLICY) == (0.0, 0.0, 0.0)
    assert _large_flow_strengths(1, 10_000_000_000.0, 86_400.0, None, POLICY) == (0.0, 0.0, 0.0)


def test_the_floor_keeps_the_moderate_tail_reachable() -> None:
    """The floor is arithmetic, not taste.

    A midpoint rank ties: a flow matching the largest the host has made scores (n - 0.5)/n, so a
    pool of fewer than 20 cannot place it in a 2.5% tail at all, and the configured 40 leaves it
    two units of resolution. `bands.min_cohort` (`baseline-calibration-v6`) applies the same
    guard to peer bands, at the same value and for the same reason (`CASE_STUDY` §4).
    """
    units = POLICY.large_flow_reference_min_units
    at_floor = _reference(units)
    *_, matching_the_largest = _large_flow_strengths(
        1, at_floor.sizes[-1], at_floor.durations[-1], at_floor, POLICY
    )

    assert matching_the_largest == 100.0 * (1 - 0.5 / units) >= CORROBORATION_STRENGTH
    assert CORROBORATION_STRENGTH > 100.0 * (1 - 0.5 / 19), "19 cannot reach the tail"
