"""Thresholds two engines must agree on, pinned where a change would otherwise pass quietly."""

from __future__ import annotations

from network_behaviour.detectors.models import CORROBORATION_STRENGTH, DetectorPolicy
from network_behaviour.ranking.models import RankingPolicy


def test_both_engines_qualify_a_large_flow_at_the_same_threshold() -> None:
    """The detector records what corroborated; the ranking engine acts on it.

    They read separate policy objects, so nothing but this pins them together. If they drift,
    `docs/EVALUATION.md` §5 reports a `large_flow_qualified` rate for a decision the tier ladder
    is no longer taking — the exact class of gap between description and behaviour this
    repository is recovering from.
    """
    assert DetectorPolicy().corroboration_strength == RankingPolicy().corroboration_strength
    assert DetectorPolicy().corroboration_strength == CORROBORATION_STRENGTH


def test_corroboration_is_the_moderate_tail_of_the_hosts_own_large_flows() -> None:
    """One threshold value, one meaning: the top 2.5% of a calibrated population.

    `strength.moderate` selects the top 2.5% of the day's relationship units; this selects the
    top 2.5% of the large flows one host has made. Different populations, same statement, so the
    number is deliberately the same and is not independently tunable without saying why.
    """
    assert DetectorPolicy().moderate_strength == CORROBORATION_STRENGTH
