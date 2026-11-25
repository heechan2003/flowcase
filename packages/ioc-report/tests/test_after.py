"""After the contact: what was new to the host, whether the address still looks like the same
device, and how the context lines rank what the host did around the contact."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from ioc_report.after import view
from ioc_report.casefile import after_contact, next_steps, render_case_file
from ioc_report.feed import Case
from ioc_report.history import Coverage, HistoryContext, NameUse
from ioc_report.live import ContextRow, DestinationDay, LiveContext, LiveSession
from ioc_report.rules import ESTABLISHED_MIN_ADDRESSES, ESTABLISHED_MIN_DAYS, decide
from tests.builders import evidence, load
from tests.conftest import minute_row, record

DAY = date(2026, 10, 15)
HOST = "192.0.2.10"


def _case(tmp_path: Path) -> tuple[Any, Case]:
    rows = [minute_row("2026-10-15 03:06:00", sni="lure.example.com", root="example.com")]
    return load(tmp_path, [record(rows, indicator="lure.example.com")])


def _at(day: date, hour: int, minute: int = 0) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=UTC)


def _row(
    day: date, name: str, hour: int = 9, *, up: int = 100, network: str = ""
) -> DestinationDay:
    return DestinationDay(day, name, network, _at(day, hour), 3, up, 2000)


def _habitual(cutoff: date) -> NameUse:
    return NameUse(cutoff - timedelta(days=30), ESTABLISHED_MIN_ADDRESSES, ESTABLISHED_MIN_DAYS)


def _never_used() -> NameUse:
    return NameUse(None, 0, 0)


def test_only_destinations_new_after_the_first_match_are_listed(tmp_path: Path) -> None:
    _feed, case = _case(tmp_path)
    days = [DAY + timedelta(days=offset) for offset in range(-2, 3)]
    rows = [
        _row(DAY - timedelta(days=1), "seen-before.example"),
        _row(DAY + timedelta(days=1), "seen-before.example"),
        _row(DAY, "newsite.example", hour=4),
        _row(DAY, "retained-before.example", hour=5),
        _row(DAY, "", hour=6, up=2_500_000, network="64500"),
        _row(DAY, "earlier-same-day.example", hour=2),
        _row(DAY, "example.com", hour=4, up=11_000_000),
    ]
    names = {
        (case.host, DAY, "newsite.example"): _never_used(),
        (case.host, DAY, "retained-before.example"): _habitual(DAY),
    }

    found = view(case, rows, days, names)

    assert found is not None
    assert [(d.name, d.named) for d in found.new] == [
        ("newsite.example", True),
        ("AS64500", False),
    ]
    assert found.new[0].established is False and found.new[0].campus_before == 0
    assert found.new[1].up_bytes == 2_500_000


def test_continuity_compares_equal_spans_and_names_what_vanished(tmp_path: Path) -> None:
    _feed, case = _case(tmp_path)
    before = [DAY - timedelta(days=n) for n in range(6, 0, -1)]
    after = [DAY + timedelta(days=n) for n in range(1, 5)]
    rows = [_row(day, name) for day in before for name in ("dropbox.com", "grammarly.com", "a.com")]
    rows += [_row(day, name) for day in after[:3] for name in ("whatsapp.net", "a.com")]

    found = view(case, rows, [*before, DAY, *after], {})

    assert found is not None and found.continuity is not None
    continuity = found.continuity
    assert continuity.span_days == 3
    assert continuity.overlap_after == 1 / 4
    assert continuity.overlap_before == 1.0
    assert continuity.habitual_missing == ("dropbox.com", "grammarly.com")
    assert (continuity.silent_after, continuity.days_after) == (1, 4)


def test_no_phase_three_means_no_after_contact_lines(tmp_path: Path) -> None:
    feed, case = _case(tmp_path)
    found = evidence(feed, case)
    result = decide(found, feed.domain_indicators)
    context = HistoryContext(Path("x"), Coverage(frozenset(), frozenset()), {})

    text = render_case_file(found, result, LiveContext(status="skipped"), context)

    assert "after the contact" not in text and "continuity" not in text
    assert "still holds that device" not in next_steps(found, result)[0]


def test_after_contact_and_continuity_lines_are_written_when_read(tmp_path: Path) -> None:
    feed, case = _case(tmp_path)
    before = [DAY - timedelta(days=n) for n in range(4, 0, -1)]
    after = [DAY + timedelta(days=n) for n in range(1, 3)]
    rows = [_row(day, "habit.example") for day in before]
    rows += [_row(DAY + timedelta(days=1), "newsite.example", up=1_500_000)]
    live = LiveContext(
        status="queried",
        days_queried=(DAY,),
        destinations={HOST: tuple(rows)},
        destination_days=(*before, DAY, *after),
    )
    found = evidence(feed, case, live=live)
    result = decide(found, feed.domain_indicators)
    context = HistoryContext(
        Path("x"),
        Coverage(frozenset(), frozenset()),
        {},
        names={(case.host, DAY, "newsite.example"): _never_used()},
    )

    text = render_case_file(found, result, live, context)

    assert "[Live source, after the contact]" in text
    assert "the first, newsite.example" in text
    assert "no campus use in the 90 days before" in text
    assert (
        "uploads of 1 MB or more to destinations new to this host (CASE_STUDY §8): "
        "newsite.example" in text
    )
    assert "[Live source, continuity]" in text and "habit.example" in text
    steps = next_steps(found, result, after_contact(found, live, context))
    assert "To judge whether the address still holds that device" in steps[0]


def test_context_lines_put_a_brief_new_visit_ahead_of_habitual_services(tmp_path: Path) -> None:
    feed, case = _case(tmp_path)
    start = _at(DAY, 3, 5)
    habitual = [ContextRow(start, f"habit{n}.example", False, 5, 1, 10, 50_000) for n in range(15)]
    brief = ContextRow(start, "spa.example", False, 1, 1, 10, 7_000_000)
    flagged = ContextRow(start, "example.com", True, 4, 1, 10, 11_000_000)
    live = LiveContext(
        status="queried",
        days_queried=(DAY,),
        host_context={HOST: (*habitual, brief, flagged)},
    )
    names = {(case.host, DAY, f"habit{n}.example"): _habitual(DAY) for n in range(15)}
    names[(case.host, DAY, "spa.example")] = _never_used()
    context = HistoryContext(Path("x"), Coverage(frozenset(), frozenset()), {}, names=names)
    found = evidence(feed, case, live=live)

    text = render_case_file(found, decide(found, feed.domain_indicators), live, context)

    (line,) = [
        entry for entry in text.splitlines() if entry.startswith("[Live source] host's traffic")
    ]
    assert line.index("example.com (flagged address)") < line.index(
        "spa.example (new to this host)"
    )
    assert "15 habitual service(s)" in line and "habit0.example" not in line


def test_without_retained_lookups_a_window_reads_as_before(tmp_path: Path) -> None:
    feed, case = _case(tmp_path)
    start = _at(DAY, 3, 5)
    rows = tuple(ContextRow(start, f"site{n}.example", False, 20 - n, 1, 10, 50) for n in range(20))
    live = LiveContext(status="queried", days_queried=(DAY,), host_context={HOST: rows})
    context = HistoryContext(Path("x"), Coverage(frozenset(), frozenset()), {})
    found = evidence(feed, case, live=live)

    text = render_case_file(found, decide(found, feed.domain_indicators), live, context)

    (line,) = [
        entry for entry in text.splitlines() if entry.startswith("[Live source] host's traffic")
    ]
    assert "site0.example" in line and "site14.example" in line and "site15.example" not in line
    assert "5 more not listed" in line


@dataclass
class _Result:
    column_names: Sequence[str]
    result_rows: Sequence[Sequence[Any]]
    query_id: str | None = "q"
    summary: Mapping[str, Any] = field(default_factory=lambda: {"read_rows": 1, "read_bytes": 1})

    @property
    def row_count(self) -> int:
        return len(self.result_rows)


class _Destinations:
    def __init__(self) -> None:
        self.calls: list[Mapping[str, Any]] = []

    def query(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
        external_data: object = None,
    ) -> _Result:
        self.calls.append(dict(parameters or {}))
        assert "AS network" in query
        return _Result(
            (
                "client_ip",
                "root_domain",
                "network",
                "first_minute",
                "active_minutes",
                "sent_bytes",
                "received_bytes",
            ),
            [(HOST, "example.org", "", datetime(2026, 10, 15, 9, 0), 2, 10, 20)],
        )

    def query_row_block_stream(self, *args: object, **kwargs: object) -> Any:
        raise NotImplementedError

    def close(self) -> None:
        pass


def test_phase_three_reads_each_horizon_day_once_for_every_review_host(tmp_path: Path) -> None:
    _feed, case = _case(tmp_path)
    other = replace(case, host="192.0.2.11", source_host="192.0.2.11")
    client = _Destinations()
    live = LiveContext(status="queried", latest_day=date(2026, 10, 21), days_queried=(DAY,))

    read = LiveSession(client).add_destinations(live, [case, other])

    assert len(client.calls) == 14 and len(read.destination_days) == 14
    assert all(call["hosts"] == [HOST, "192.0.2.11"] for call in client.calls)
    assert read.destinations is not None
    (first, *_rest) = read.destinations[HOST]
    assert first.root_domain == "example.org" and first.first_minute.tzinfo is not None


def test_phase_three_skips_cases_whose_contact_left_the_horizon(tmp_path: Path) -> None:
    _feed, case = _case(tmp_path)
    client = _Destinations()
    live = LiveContext(status="queried", latest_day=date(2026, 11, 20), days_queried=())

    read = LiveSession(client).add_destinations(live, [case])

    assert client.calls == [] and read.destinations == {}
