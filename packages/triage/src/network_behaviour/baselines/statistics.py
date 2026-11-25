"""Deterministic robust statistics for positive behavioural measures."""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from math import log1p

from network_behaviour.baselines.models import ResidualMethod, RobustSummary, validate_measure


def quantile(values: tuple[float, ...], probability: float) -> float:
    """Linear type-7 quantile with an explicit stable implementation."""
    if not values:
        raise ValueError("quantile requires at least one value")
    if not 0 <= probability <= 1:
        raise ValueError("quantile probability must be between zero and one")
    ordered = sorted(validate_measure(value) for value in values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def robust_summary(values: tuple[float | None, ...]) -> RobustSummary | None:
    clean = tuple(validate_measure(value) for value in values if value is not None)
    if not clean:
        return None
    logged = tuple(log1p(value) for value in clean)
    median_logged = quantile(logged, 0.5)
    deviations = tuple(abs(value - median_logged) for value in logged)
    mad = quantile(deviations, 0.5)
    q25 = quantile(logged, 0.25)
    q75 = quantile(logged, 0.75)
    if mad > 0:
        method = ResidualMethod.MAD
    elif q75 > q25:
        method = ResidualMethod.IQR
    else:
        method = ResidualMethod.RATIO_TO_MEDIAN
    return RobustSummary(
        len(clean),
        median_logged,
        mad,
        q25,
        q75,
        quantile(clean, 0.5),
        method,
    )


def positive_residual(value: float | None, summary: RobustSummary | None) -> float | None:
    """Return an upper-tail residual using the versioned MAD/IQR/ratio fallback order."""
    if value is None or summary is None:
        return None
    current = validate_measure(value)
    logged_delta = log1p(current) - summary.median_log1p
    if summary.method is ResidualMethod.MAD:
        # 1.4826 is the conventional normal-consistency scale for MAD.
        return logged_delta / (1.4826 * summary.mad_log1p)
    if summary.method is ResidualMethod.IQR:
        return logged_delta / (summary.q75_log1p - summary.q25_log1p)
    return (current + 1.0) / (summary.median_raw + 1.0) - 1.0


def empirical_percentile(value: float | None, population: tuple[float, ...]) -> float | None:
    """Return a deterministic empirical midpoint rank so broad ties cannot rank as tails."""
    if value is None or not population:
        return None
    return empirical_percentile_sorted(value, tuple(sorted(population)))


def empirical_percentile_sorted(value: float | None, population: tuple[float, ...]) -> float | None:
    """Return the midpoint rank for an already sorted population in logarithmic time."""

    if value is None or not population:
        return None
    below = bisect_left(population, value)
    tied = bisect_right(population, value) - below
    return (below + 0.5 * tied) / len(population)
