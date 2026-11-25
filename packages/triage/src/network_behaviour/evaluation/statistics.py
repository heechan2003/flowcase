"""Small deterministic statistics. No new dependency, and no hidden tie handling.

Every function here is used by a bundle section, so each states what it does with ties: an
ordering that is ~90% tied (`CASE_STUDY` §12) will score very differently under average ranks
than under the file order, and reporting the second as though it were the first would flatter the
ranking.
"""

from __future__ import annotations

from collections.abc import Hashable, Sequence
from math import sqrt


def average_ranks(values: Sequence[float]) -> tuple[float, ...]:
    """Midpoint ranks, so tied values share one rank rather than an arbitrary order."""

    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    position = 0
    while position < len(order):
        end = position
        while end + 1 < len(order) and values[order[end + 1]] == values[order[position]]:
            end += 1
        shared = (position + end) / 2 + 1
        for index in order[position : end + 1]:
            ranks[index] = shared
        position = end + 1
    return tuple(ranks)


def spearman(left: Sequence[float], right: Sequence[float]) -> float | None:
    """Rank correlation over paired values. `None` when either side has no variation."""

    if len(left) != len(right):
        raise ValueError("paired sequences must have equal length")
    if len(left) < 2:
        return None
    return pearson(average_ranks(left), average_ranks(right))


def pearson(left: Sequence[float], right: Sequence[float]) -> float | None:
    if len(left) != len(right):
        raise ValueError("paired sequences must have equal length")
    count = len(left)
    if count < 2:
        return None
    mean_left = sum(left) / count
    mean_right = sum(right) / count
    covariance = sum((a - mean_left) * (b - mean_right) for a, b in zip(left, right, strict=True))
    variance_left = sum((a - mean_left) ** 2 for a in left)
    variance_right = sum((b - mean_right) ** 2 for b in right)
    if variance_left == 0 or variance_right == 0:
        return None
    return covariance / sqrt(variance_left * variance_right)


def jaccard(left: frozenset[Hashable], right: frozenset[Hashable]) -> float | None:
    """Overlap of two sets. `None` when both are empty, which is not an agreement."""

    union = left | right
    if not union:
        return None
    return len(left & right) / len(union)


def shared_order_correlation(
    left: Sequence[Hashable],
    right: Sequence[Hashable],
) -> tuple[float | None, int]:
    """Spearman over the items both orderings contain, and how many that was.

    Resampling drops hosts, so the two orderings are rarely over the same population. Correlating
    only the shared members keeps the statistic defined; the count says how much it rests on.
    """

    left_position = {item: index for index, item in enumerate(left)}
    right_position = {item: index for index, item in enumerate(right)}
    shared = sorted(
        set(left_position) & set(right_position),
        key=lambda item: (left_position[item], right_position[item]),
    )
    if len(shared) < 2:
        return None, len(shared)
    return (
        spearman(
            [float(left_position[item]) for item in shared],
            [float(right_position[item]) for item in shared],
        ),
        len(shared),
    )


def summarize(values: Sequence[float]) -> tuple[float, float, float]:
    """Minimum, median and maximum. Reported instead of a mean, which hides a bimodal spread."""

    if not values:
        raise ValueError("cannot summarize an empty sample")
    ordered = sorted(values)
    middle = len(ordered) // 2
    median = ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2
    return ordered[0], median, ordered[-1]
