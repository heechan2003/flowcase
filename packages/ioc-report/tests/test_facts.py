"""The notable facts code writes for a review case, read from an H-47037a-shaped synthetic case: a
lure visit with a large download, names new to the host just before it, a new destination a minute
after it, an upload to another new one, a silent day, and later re-queried days with no contact."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from ioc_report.casefile import FLAGGED_TAG, NEW_TAG, UNESTABLISHED_TAG, render_case_file
from ioc_report.contact import Evidence
from ioc_report.facts import case_facts
from ioc_report.feed import Feed
from ioc_report.history import Coverage, HistoryContext, NameUse
from ioc_report.live import ContextRow, DestinationDay, LiveContext, PairContact
from ioc_report.rules import (
    ESTABLISHED_MIN_ADDRESSES,
    ESTABLISHED_MIN_DAYS,
    REVIEW,
    Decision,
    decide,
)
from tests.builders import SKIPPED, evidence, load
from tests.conftest import minute_row, record

DAY = date(2026, 10, 15)
HOST = "192.0.2.10"
SERVER = "1.1.1.1"
VERDICT_WORDS = ("compromised", "infected", "malicious", "benign")


def at(day: date, hour: int, minute: int = 0) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=UTC)


@dataclass(frozen=True)
class Shaped:
    feed: Feed
    evidence: Evidence
    decision: Decision
    live: LiveContext
    history: HistoryContext


def shaped(
    tmp_path: Path,
    *,
    lead_in: tuple[str, str] = ("singair.example", "changi.example"),
    next_new: str = "natureland.example",
) -> Shaped:
    """`lead_in` and `next_new` are the names a renderer test replaces with hostile ones."""
    feed, case = load(
        tmp_path,
        [
            record(
                [
                    minute_row(
                        "2026-10-15 03:06:00",
                        sni="lure.example.com",
                        root="example.com",
                        down=11_000_000,
                    )
                ],
                indicator="lure.example.com",
                threat_type="payload_delivery",
                malware="js.clickfix",
            )
        ],
    )
    contact = PairContact(
        DAY,
        SERVER,
        6,
        443,
        "lure.example.com",
        "example.com",
        "",
        "13335",
        1,
        (int(at(DAY, 3, 6).timestamp()) // 60,),
        1000,
        11_000_000,
        1,
    )
    context = (
        ContextRow(at(DAY, 3, 0), lead_in[0], False, 2, 1, 900, 60_000),
        ContextRow(at(DAY, 3, 0), lead_in[1], False, 1, 1, 400, 30_000),
        ContextRow(at(DAY, 3, 0), "habit.example", False, 5, 1, 100, 5_000),
        ContextRow(at(DAY, 3, 5), "example.com", True, 1, 1, 1000, 11_000_000),
        ContextRow(at(DAY, 3, 5), next_new, False, 2, 1, 500, 80_000),
        ContextRow(at(DAY, 3, 10), "habit.example", False, 5, 1, 100, 5_000),
    )
    before = [DAY - timedelta(days=n) for n in range(4, 0, -1)]
    after = [DAY + timedelta(days=n) for n in range(1, 4)]
    habits = ("habit.example", "mail.example", "news.example")
    destinations = [
        DestinationDay(day, name, "", at(day, 9), 3, 100, 2000) for day in before for name in habits
    ]
    destinations += [
        DestinationDay(DAY, "habit.example", "", at(DAY, 2), 3, 100, 2000),
        DestinationDay(DAY, "example.com", "", at(DAY, 3, 6), 1, 1000, 11_000_000),
        DestinationDay(DAY, next_new, "", at(DAY, 3, 7), 2, 500, 80_000),
        DestinationDay(after[0], "habit.example", "", at(after[0], 9), 3, 100, 2000),
        DestinationDay(after[0], "newcloud.example", "", at(after[0], 10), 4, 2_500_000, 9000),
        DestinationDay(after[2], "habit.example", "", at(after[2], 9), 3, 100, 2000),
    ]
    live = LiveContext(
        status="queried",
        days_queried=(DAY, *after[:2]),
        contacts={(HOST, SERVER): (contact,)},
        host_context={HOST: context},
        context_days=(DAY,),
        destinations={HOST: tuple(destinations)},
        destination_days=(*before, DAY, *after),
    )
    never = NameUse(None, 0, 0)
    habitual = NameUse(DAY - timedelta(days=60), ESTABLISHED_MIN_ADDRESSES, ESTABLISHED_MIN_DAYS)
    names = {
        (case.host, DAY, lead_in[0]): never,
        (case.host, DAY, lead_in[1]): NameUse(DAY - timedelta(days=200), 2, 1),
        (case.host, DAY, next_new): never,
        (case.host, DAY, "newcloud.example"): never,
        (case.host, DAY, "habit.example"): habitual,
    }
    history = HistoryContext(Path("x"), Coverage(frozenset(), frozenset()), {}, names=names)
    found = evidence(feed, case, live=live)
    return Shaped(feed, found, decide(found, feed.domain_indicators), live, history)


def _text(tmp_path: Path) -> tuple[Shaped, list[str]]:
    case = shaped(tmp_path)
    facts = case_facts(case.evidence, case.decision, case.live, case.history)
    return case, [fact.text for fact in facts.notable]


def test_the_shaped_case_is_kept_for_review(tmp_path: Path) -> None:
    case = shaped(tmp_path)

    assert case.decision.disposition == REVIEW


def test_the_lead_in_names_what_was_new_just_before_the_contact(tmp_path: Path) -> None:
    _case, notable = _text(tmp_path)

    (line,) = [text for text in notable if text.startswith("Just before the contact")]
    assert "from 2026-10-15 03:00 UTC" in line and "2 name(s)" in line
    assert "singair.example" in line and "changi.example" in line
    assert "habit.example" not in line


def test_after_the_contact_names_the_next_new_destination_and_its_delay(tmp_path: Path) -> None:
    _case, notable = _text(tmp_path)

    (line,) = [text for text in notable if text.startswith("Read ")]
    assert "the next destination new to this host was natureland.example, 1.0 min later" in line
    assert "2 new named destination(s)" in line
    assert "(CASE_STUDY §8): newcloud.example 2.5 MB" in line


def test_later_re_queried_days_without_contact_say_so(tmp_path: Path) -> None:
    _case, notable = _text(tmp_path)

    (line,) = [text for text in notable if text.startswith("No contact with the flagged")]
    assert "(2026-10-16..2026-10-17)" in line


def test_continuity_compares_the_spans_around_the_match(tmp_path: Path) -> None:
    _case, notable = _text(tmp_path)

    (line,) = [text for text in notable if text.startswith("Named destinations shared")]
    assert ": 0.25 (1.00 between two spans before it)" in line
    assert "no traffic with a known remote address on 1 of 3 later day(s)" in line


def test_the_contact_fact_reads_the_live_copy_once(tmp_path: Path) -> None:
    case, notable = _text(tmp_path)
    facts = case_facts(case.evidence, case.decision, case.live, case.history)

    assert notable[0].startswith("The host's contact with the flagged address:")
    assert "1 minute(s) on 2026-10-15" in notable[0] and "11.0 MB received" in notable[0]
    assert facts.notable[0].source == "Live source"
    (row,) = facts.timeline
    assert row.source == "Live source, also in the IOC feed" and row.received == 11_000_000


def test_windows_and_day_points_carry_what_the_charts_draw(tmp_path: Path) -> None:
    case = shaped(tmp_path)
    facts = case_facts(case.evidence, case.decision, case.live, case.history)

    assert [window.position for window in facts.windows] == ["before", "contact", "after"]
    before, contact, after = facts.windows
    assert [tag for _, tag in before.rows] == [NEW_TAG, UNESTABLISHED_TAG]
    assert before.habitual == 1 and after.habitual == 1 and not after.rows
    assert [tag for _, tag in contact.rows] == [FLAGGED_TAG, NEW_TAG]
    by_day = {point.day: point for point in facts.days}
    assert [day for day, point in by_day.items() if point.match] == [DAY]
    assert [day for day, point in by_day.items() if point.silent] == [DAY + timedelta(days=2)]
    assert (by_day[DAY].destinations, by_day[DAY].new) == (3, 1)
    assert (by_day[DAY + timedelta(days=1)].destinations, by_day[DAY + timedelta(days=1)].new) == (
        2,
        1,
    )


def test_steps_are_grouped_by_the_system_that_can_settle_them(tmp_path: Path) -> None:
    case = shaped(tmp_path)
    facts = case_facts(case.evidence, case.decision, case.live, case.history)

    systems = [step.system for step in facts.steps]
    assert systems and systems[0] == "device"
    assert all(step.text for step in facts.steps)


def test_no_fact_is_a_verdict_on_the_host(tmp_path: Path) -> None:
    case, notable = _text(tmp_path)
    facts = case_facts(case.evidence, case.decision, case.live, case.history)
    written = " ".join([*notable, *(step.text for step in facts.steps), *facts.coverage]).lower()

    assert not [word for word in VERDICT_WORDS if word in written]


def test_without_live_data_there_is_nothing_to_chart(tmp_path: Path) -> None:
    feed, case = load(tmp_path, [record([minute_row("2026-10-15 03:06:00", sni="x.example.com")])])
    found = evidence(feed, case)
    history = HistoryContext(Path("x"), Coverage(frozenset(), frozenset()), {})

    facts = case_facts(found, decide(found, feed.domain_indicators), SKIPPED, history)

    assert facts.windows == () and facts.days == () and facts.after is None
    assert facts.notable[0].source == "IOC feed"
    assert facts.notable[0].text.startswith("The host's contact with the flagged address:")


def test_the_case_file_the_model_reads_is_unchanged_by_the_facts(tmp_path: Path) -> None:
    case = shaped(tmp_path)
    before = render_case_file(case.evidence, case.decision, case.live, case.history)

    case_facts(case.evidence, case.decision, case.live, case.history)

    assert render_case_file(case.evidence, case.decision, case.live, case.history) == before


def test_a_window_of_only_habitual_services_reads_cleanly(tmp_path: Path) -> None:
    case = shaped(tmp_path)

    text = render_case_file(case.evidence, case.decision, case.live, case.history)

    (line,) = [entry for entry in text.splitlines() if "03:10-03:15 UTC" in entry]
    assert line.endswith(
        "UTC: 1 habitual service(s): used by this host before and established on campus."
    )
