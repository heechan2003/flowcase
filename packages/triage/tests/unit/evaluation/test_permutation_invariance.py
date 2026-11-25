"""§2 classifies a condition as carrying no host-specific information. This pins how."""

from __future__ import annotations

from network_behaviour.evaluation.permutation import INVARIANCE_TOLERANCE, RuleRate


def rate(observed: float | None, permuted: float | None) -> RuleRate:
    return RuleRate("rule", "condition", observed, permuted)


def test_an_unchanged_rate_is_invariant() -> None:
    """`relationship_eligibility.rarity_moderate`: 6.71% observed, 6.71% permuted."""

    assert rate(0.0671, 0.0671).is_invariant


def test_a_small_absolute_move_is_not_invariant() -> None:
    """0.58% to 0.43% is a quarter of itself.

    An absolute tolerance loose enough to ignore 0.15 percentage points would call this
    unchanged, which is why the test is relative. `tier_confidence_cap.history_cold_or_limited`
    measured exactly this on 2026-08-09 and does respond to the host label.
    """

    assert not rate(0.0058, 0.0043).is_invariant


def test_the_smallest_real_movement_stays_outside_the_tolerance() -> None:
    """`transfer_eligibility.strong_strength`: 0.76% to 1.06%, a relative 39%."""

    assert not rate(0.0076, 0.0106).is_invariant
    assert abs(0.0106 - 0.0076) / 0.0076 > INVARIANCE_TOLERANCE


def test_zero_is_invariant_only_against_zero() -> None:
    assert rate(0.0, 0.0).is_invariant
    assert not rate(0.0, 0.01).is_invariant


def test_a_missing_rate_is_never_invariant() -> None:
    """A condition the permuted run never evaluated is unknown, not unchanged."""

    assert not rate(None, 0.5).is_invariant
    assert not rate(0.5, None).is_invariant
