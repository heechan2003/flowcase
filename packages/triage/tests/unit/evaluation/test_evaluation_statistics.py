from __future__ import annotations

import pytest

from network_behaviour.evaluation.statistics import (
    average_ranks,
    jaccard,
    shared_order_correlation,
    spearman,
    summarize,
)


def test_ties_share_a_midpoint_rank_rather_than_an_arbitrary_order() -> None:
    assert average_ranks([5.0, 5.0, 1.0]) == (2.5, 2.5, 1.0)


def test_spearman_is_one_for_an_identical_order_and_minus_one_for_a_reversal() -> None:
    assert spearman([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == pytest.approx(1.0)
    assert spearman([1.0, 2.0, 3.0], [3.0, 2.0, 1.0]) == pytest.approx(-1.0)


def test_a_constant_side_has_no_correlation_rather_than_a_misleading_zero() -> None:
    assert spearman([1.0, 1.0, 1.0], [1.0, 2.0, 3.0]) is None
    assert spearman([1.0], [1.0]) is None


def test_jaccard_of_two_empty_sets_is_undefined_not_perfect_agreement() -> None:
    assert jaccard(frozenset(), frozenset()) is None
    assert jaccard(frozenset({1, 2}), frozenset({2, 3})) == pytest.approx(1 / 3)


def test_correlation_is_taken_over_the_shared_members_and_reports_how_many() -> None:
    value, shared = shared_order_correlation(["a", "b", "c", "d"], ["a", "b", "d"])

    assert shared == 3
    assert value == pytest.approx(1.0)


def test_a_single_shared_member_yields_no_correlation() -> None:
    assert shared_order_correlation(["a", "b"], ["a"]) == (None, 1)


def test_summarize_reports_the_spread_rather_than_a_mean() -> None:
    assert summarize([3.0, 1.0, 2.0]) == (1.0, 2.0, 3.0)
    with pytest.raises(ValueError, match="empty"):
        summarize([])
