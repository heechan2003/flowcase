"""What a review host did after its contact, and whether the address still looks like the same
device: computed from the live source's per-day destinations (phase 3) and retained name use.

Shown in the case file, never decided on. A destination is new when the host had exchanged no
traffic with it earlier in the source window and, for a name, had not used it on any retained day
before the first match day. Nothing here thresholds a host: the numbers are written out for a
reader.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime

from ioc_report.feed import Case
from ioc_report.history import NameUse
from ioc_report.live import DestinationDay
from ioc_report.rules import ESTABLISHED_MIN_ADDRESSES, ESTABLISHED_MIN_DAYS

# CASE_STUDY §8: long_flows's own floor, the size K5 already calls a transfer.
UPLOAD_BYTES = 1_000_000


@dataclass(frozen=True, slots=True)
class NewDestination:
    name: str
    """A registered domain, or "AS<number>" for traffic that carried no name."""
    named: bool
    first_minute: datetime
    active_minutes: int
    up_bytes: int
    down_bytes: int
    established: bool | None
    """CASE_STUDY §15 on the campus's use before the first match; None when not known."""
    campus_before: int | None
    """Campus addresses that used the name in the window before the first match."""


@dataclass(frozen=True, slots=True)
class Continuity:
    """Whether the address's named destinations after the match look like those before it."""

    span_days: int
    """k: the active days compared on each side."""
    overlap_after: float
    """Jaccard of the named destinations of the k active days before and after the match."""
    overlap_before: float | None
    """The same between the two k-day spans before the match, when there are 2k such days."""
    habitual_missing: tuple[str, ...]
    """Named on every active day before the match and on no active day after it."""
    silent_after: int
    """Days after the last match day with no traffic to or from a known remote address."""
    days_after: int


@dataclass(frozen=True, slots=True)
class AfterView:
    first_day: date
    last_day: date
    days: int
    new: tuple[NewDestination, ...]
    """First seen after the first match, in order of first minute."""
    continuity: Continuity | None


def view(
    case: Case,
    rows: Sequence[DestinationDay],
    days: Sequence[date],
    names: Mapping[tuple[str, date, str], NameUse],
) -> AfterView | None:
    if not days or not rows:
        return None
    cutoff = case.days[0]
    # The contact itself is not something the host did after it.
    own = {row.root_domain for row in case.rows if row.root_domain}
    first_seen: dict[str, DestinationDay] = {}
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for row in sorted(rows, key=lambda r: r.first_minute):
        key = _key(row)
        first_seen.setdefault(key, row)
        total = totals[key]
        total[0] += row.active_minutes
        total[1] += row.up_bytes
        total[2] += row.down_bytes
    new = []
    for key, row in first_seen.items():
        if row.first_minute < case.first:
            continue
        if row.root_domain and (row.root_domain in own or case.names_flagged(row.root_domain)):
            continue
        use = names.get((case.host, cutoff, row.root_domain)) if row.root_domain else None
        if use is not None and use.host_first_day is not None and use.host_first_day < cutoff:
            continue
        minutes, up, down = totals[key]
        new.append(
            NewDestination(
                name=key,
                named=bool(row.root_domain),
                first_minute=row.first_minute,
                active_minutes=minutes,
                up_bytes=up,
                down_bytes=down,
                established=(
                    use.prior_addresses >= ESTABLISHED_MIN_ADDRESSES
                    and use.prior_days >= ESTABLISHED_MIN_DAYS
                    if use is not None
                    else None
                ),
                campus_before=use.prior_addresses if use is not None else None,
            )
        )
    ordered = sorted(days)
    return AfterView(
        first_day=ordered[0],
        last_day=ordered[-1],
        days=len(ordered),
        new=tuple(sorted(new, key=lambda d: (d.first_minute, d.name))),
        continuity=_continuity(case, rows, ordered),
    )


def _key(row: DestinationDay) -> str:
    return row.root_domain or f"AS{row.network or '?'}"


def _continuity(
    case: Case, rows: Sequence[DestinationDay], days: Sequence[date]
) -> Continuity | None:
    named: dict[date, set[str]] = defaultdict(set)
    active: set[date] = set()
    for row in rows:
        active.add(row.day)
        if row.root_domain:
            named[row.day].add(row.root_domain)
    before = [day for day in days if day < case.days[0] and named[day]]
    after = [day for day in days if day > case.days[-1] and named[day]]
    later = [day for day in days if day > case.days[-1]]
    span = min(len(before), len(after))
    if span == 0:
        return None
    recent = _union(named, before[-span:])
    following = _union(named, after[:span])
    earlier = _union(named, before[-2 * span : -span]) if len(before) >= 2 * span else None
    habitual = set.intersection(*(named[day] for day in before)) if len(before) >= 2 else set()
    seen_after = _union(named, after)
    return Continuity(
        span_days=span,
        overlap_after=_jaccard(recent, following),
        overlap_before=_jaccard(earlier, recent) if earlier is not None else None,
        habitual_missing=tuple(sorted(habitual - seen_after)),
        silent_after=sum(1 for day in later if day not in active),
        days_after=len(later),
    )


def _union(named: Mapping[date, set[str]], days: Sequence[date]) -> set[str]:
    found: set[str] = set()
    for day in days:
        found |= named.get(day, set())
    return found


def _jaccard(left: set[str], right: set[str]) -> float:
    joined = left | right
    return len(left & right) / len(joined) if joined else 0.0
