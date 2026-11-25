"""Build evidence for rule tests without a store or a source: every input is stated in the test."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from ioc_report.contact import Evidence, build_evidence
from ioc_report.feed import Case, Feed, load_feed
from ioc_report.history import (
    CaseHistory,
    Episode,
    HostServiceDay,
    Prior,
    ServiceHistory,
    sni_service,
)
from ioc_report.live import LiveContext
from ioc_report.registration import NameAge
from ioc_report.rules import (
    ESTABLISHED_MIN_ADDRESSES,
    ESTABLISHED_MIN_DAYS,
    Decision,
    decide,
)
from tests.conftest import write_feed

SKIPPED = LiveContext(status="skipped")
FIRST_MATCH = date(2026, 9, 15)


def load(tmp_path: Path, records: Sequence[dict[str, Any]]) -> tuple[Feed, Case]:
    feed = load_feed(write_feed(tmp_path, list(records)))
    return feed, feed.cases[0]


def established(
    name: str,
    server: str = "1.1.1.1",
    *,
    addresses: int = ESTABLISHED_MIN_ADDRESSES,
    days: int = ESTABLISHED_MIN_DAYS,
    asns: frozenset[int] = frozenset({13335}),
    match_rows: tuple[HostServiceDay, ...] = (),
) -> ServiceHistory:
    """A name's retained history: by default exactly at the established threshold."""
    key = sni_service(server, name)
    assert key is not None
    window_start = FIRST_MATCH - timedelta(days=90)
    return ServiceHistory(
        key=key,
        campus_addresses=addresses,
        campus_days=days,
        prior=Prior(window_start, FIRST_MATCH, 90, addresses, days, window_start, asns),
        host_first_day=None,
        host_days_before=0,
        host_days_on_match=0,
        host_days_after=0,
        match_rows=match_rows,
    )


def history(
    services: Sequence[ServiceHistory] = (), episodes: Sequence[Episode] = ()
) -> CaseHistory:
    return CaseHistory((), (), (), tuple(services), tuple(episodes))


def evidence(
    feed: Feed,
    case: Case,
    *,
    live: LiveContext = SKIPPED,
    retained: CaseHistory | None = None,
    registrations: Mapping[str, NameAge] | None = None,
) -> Evidence:
    return build_evidence(case, feed, live, retained or history(), registrations)


def decision(
    feed: Feed,
    case: Case,
    *,
    live: LiveContext = SKIPPED,
    retained: CaseHistory | None = None,
    registrations: Mapping[str, NameAge] | None = None,
) -> Decision:
    return decide(
        evidence(feed, case, live=live, retained=retained, registrations=registrations),
        feed.domain_indicators,
    )
