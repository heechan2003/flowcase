from math import isfinite

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
