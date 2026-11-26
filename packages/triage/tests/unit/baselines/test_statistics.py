from math import isfinite, log1p
from random import Random

import pytest

from network_behaviour.baselines.models import (
    BaselinePolicy,
    HistoryConfidence,
    ResidualMethod,
)
from network_behaviour.baselines.statistics import (
    empirical_percentile,
    empirical_percentile_sorted,
    positive_residual,
    quantile,
    robust_summary,
)


@pytest.mark.parametrize(
    ("days", "expected"),
    [
        (0, HistoryConfidence.COLD),
        (7, HistoryConfidence.COLD),
        (8, HistoryConfidence.LIMITED),
        (14, HistoryConfidence.LIMITED),
        (15, HistoryConfidence.NORMAL),
        (30, HistoryConfidence.NORMAL),
        (31, HistoryConfidence.MATURE),
    ],
)
def test_history_confidence_boundaries(days: int, expected: HistoryConfidence) -> None:
    assert HistoryConfidence.from_active_days(days) is expected


def test_robust_summary_uses_mad_then_iqr_then_ratio_fallbacks() -> None:
    mad = robust_summary((1.0, 2.0, 4.0, 8.0, 16.0))
    iqr = robust_summary((0.0, 0.0, 0.0, 1.0, 2.0))
    ratio = robust_summary((5.0, 5.0, 5.0, 5.0))

    assert mad is not None and mad.method is ResidualMethod.MAD
    assert iqr is not None and iqr.method is ResidualMethod.IQR
    assert ratio is not None and ratio.method is ResidualMethod.RATIO_TO_MEDIAN
    residual = positive_residual(10.0, ratio)
    assert residual is not None and isfinite(residual) and residual > 0


def test_missing_values_and_empirical_ties_are_deterministic() -> None:
    summary = robust_summary((None, 1.0, None, 3.0))

    assert summary is not None and summary.count == 2
    assert robust_summary((None, None)) is None
    assert positive_residual(None, summary) is None
    assert empirical_percentile(2.0, (1.0, 2.0, 2.0, 3.0)) == 0.5
    assert empirical_percentile_sorted(2.5, (1.0, 2.0, 2.0, 3.0)) == 0.75
    assert empirical_percentile(2.0, ()) is None
    assert quantile((0.0, 10.0), 0.25) == 2.5


def test_statistics_and_policy_reject_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        robust_summary((-1.0,))
    with pytest.raises(ValueError, match="inconsistent"):
        BaselinePolicy(recent_active_days=31)
    with pytest.raises(ValueError, match="at least 20"):
        BaselinePolicy(min_cohort=19)
    with pytest.raises(ValueError, match="cannot be negative"):
        HistoryConfidence.from_active_days(-1)


def _old_quantile(values: tuple[float, ...], probability: float) -> float:
    """The implementation the sorted helper replaced, kept as an oracle."""
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _old_summary(values: tuple[float | None, ...]) -> tuple[object, ...] | None:
    clean = tuple(value for value in values if value is not None)
    if not clean:
        return None
    logged = tuple(log1p(value) for value in clean)
    median_logged = _old_quantile(logged, 0.5)
    mad = _old_quantile(tuple(abs(value - median_logged) for value in logged), 0.5)
    q25, q75 = _old_quantile(logged, 0.25), _old_quantile(logged, 0.75)
    return (len(clean), median_logged, mad, q25, q75, _old_quantile(clean, 0.5))


def test_robust_summary_matches_the_unsorted_oracle_exactly() -> None:
    rng = Random(20261126)
    cases: list[tuple[float | None, ...]] = [
        (),
        (None,),
        (None, None),
        (0.0,),
        (5.0,),
        (3.0, 3.0, 3.0),
        (0.0, 0.0, 1.0),
        (1.0, None, 2.0, None, 1e12),
    ]
    for _ in range(500):
        size = rng.randint(1, 60)
        cases.append(
            tuple(
                None
                if rng.random() < 0.1
                else rng.choice(
                    [float(rng.randint(0, 5)), rng.uniform(0, 1e9), rng.expovariate(1e-3)]
                )
                for _ in range(size)
            )
        )
    for values in cases:
        summary = robust_summary(values)
        expected = _old_summary(values)
        if expected is None:
            assert summary is None
            continue
        assert summary is not None
        assert (
            summary.count,
            summary.median_log1p,
            summary.mad_log1p,
            summary.q25_log1p,
            summary.q75_log1p,
            summary.median_raw,
        ) == expected
