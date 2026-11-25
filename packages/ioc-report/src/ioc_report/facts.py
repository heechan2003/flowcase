"""The notable facts of a review case, written by code from what the decision and its context
already hold: the case's reading in a few sentences, and the rows the report's tables and charts
draw. Pure, shown only and never decided on. A fact says what was observed and where it came from;
it never says what the host is. The only numbers are the constants the rules already cite.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from ioc_report.after import UPLOAD_BYTES, AfterView
from ioc_report.casefile import (
    MAX_CONTEXT_WINDOWS,
    NEW_TAG,
    UNESTABLISHED_TAG,
    NextStep,
    after_contact,
    caveats,
    combined_status,
    next_step_items,
    rank_context,
    source_label,
)
from ioc_report.contact import Contact, Evidence, FlowContact
from ioc_report.history import HistoryContext, indicator_service
from ioc_report.knowledge import name_facts
from ioc_report.live import CONTEXT_WINDOW_SECONDS, ContextRow, LiveContext
from ioc_report.rules import (
    ESTABLISHED_MIN_ADDRESSES,
    ESTABLISHED_MIN_DAYS,
    SHARED_MIN_DOMAINS,
    Decision,
    Judged,
)
from ioc_report.text import day_list, duration, minute, size, when

# Output bounds, not thresholds: how many names a sentence lists before it counts the rest.
LISTED_NAMES = 6


@dataclass(frozen=True, slots=True)
class Fact:
    source: str
    """The same source labels the case file uses."""
    text: str


@dataclass(frozen=True, slots=True)
class TimelineRow:
    kind: str
    """"contact" or "long flows"."""
    source: str
    first: datetime
    last: datetime
    what: str
    minutes: int | None
    flows: int
    received: int
    sent: int
    longest_sec: float | None
    status: str


@dataclass(frozen=True, slots=True)
class Window:
    """One five-minute window around the contact, its destinations ranked as the case file ranks
    them (`casefile.rank_context`)."""

    start: datetime
    position: str
    """"before", "contact" or "after", against the first matched minute."""
    rows: tuple[tuple[ContextRow, str], ...]
    habitual: int


@dataclass(frozen=True, slots=True)
class DayPoint:
    """One day the live source read for the after-contact view."""

    day: date
    destinations: int
    """Named destinations the host exchanged traffic with that day, in either direction."""
    new: int
    """Of them, new to this host after the first match (`after.view`)."""
    silent: bool
    match: bool


@dataclass(frozen=True, slots=True)
class CaseFacts:
    notable: tuple[Fact, ...]
    timeline: tuple[TimelineRow, ...]
    windows: tuple[Window, ...]
    after: AfterView | None
    days: tuple[DayPoint, ...]
    steps: tuple[NextStep, ...]
    coverage: tuple[str, ...]


def case_facts(
    evidence: Evidence, decision: Decision, live: LiveContext, history: HistoryContext
) -> CaseFacts:
    after = after_contact(evidence, live, history)
    windows = _windows(evidence, live, history)
    return CaseFacts(
        notable=(*story(evidence, live, history), *_whole_host(evidence)),
        timeline=_timeline(evidence, decision),
        windows=windows,
        after=after,
        days=_days(evidence, live, after),
        steps=next_step_items(evidence, decision, after),
        coverage=tuple(caveat.text for caveat in caveats(evidence, decision)),
    )


def story(evidence: Evidence, live: LiveContext, history: HistoryContext) -> tuple[Fact, ...]:
    """What happened with the flagged address, in order: the contact, the flagged name's standing,
    what came just before it and after it, later contact and continuity. The whole host is left
    out, for the digest to describe the host on its own."""
    after = after_contact(evidence, live, history)
    windows = _windows(evidence, live, history)
    return (
        *_contact(evidence),
        *_standing(evidence),
        *_lead_in(windows),
        *_after(evidence, after),
        *_later_contact(evidence),
        *_continuity(evidence, after),
    )


def _visible_contacts(evidence: Evidence) -> list[Contact]:
    return [
        contact
        for index, contact in enumerate(evidence.contacts)
        if not evidence.hidden_contact(index)
    ]


def _visible_flows(evidence: Evidence) -> list[FlowContact]:
    shown = [flow for index, flow in enumerate(evidence.flows) if not evidence.hidden_flow(index)]
    shown += [
        flow
        for position, flow in enumerate(evidence.other_flows)
        if position not in evidence.other_flow_duplicates
    ]
    return shown


def _contact(evidence: Evidence) -> list[Fact]:
    contacts = _visible_contacts(evidence)
    if not contacts:
        return []
    source = "Live source" if any(c.source == "live" for c in contacts) else "IOC feed"
    minutes = sorted({m for contact in contacts for m in contact.minutes})
    days = day_list(m.date() for m in minutes)
    received = sum(contact.down_bytes for contact in contacts)
    sent = sum(contact.up_bytes for contact in contacts)
    what = contacts[0].label if len(contacts) == 1 else f"{len(contacts)} kinds of contact"
    facts = [
        Fact(
            source,
            f"The host's contact with the flagged address: {what}, {len(minutes)} minute(s) on "
            f"{days}, first {when(minutes[0])}, last {minute(minutes[-1])} UTC; "
            f"{size(received)} received, {size(sent)} sent.",
        )
    ]
    flows = _visible_flows(evidence)
    if flows:
        count = sum(flow.flows for flow in flows)
        longest = max(flow.longest_sec for flow in flows)
        facts.append(
            Fact(
                source,
                f"{count} long flow(s) of about 1 MB or more with it, the longest "
                f"{duration(longest)}, {size(sum(flow.down_bytes for flow in flows))} received "
                f"and {size(sum(flow.up_bytes for flow in flows))} sent in all.",
            )
        )
    return facts


def _standing(evidence: Evidence) -> list[Fact]:
    case = evidence.case
    facts = []
    own = indicator_service(case)
    service = evidence.history.service(own.service_id_hex) if own is not None else None
    if service is not None and service.prior is not None and not service.prior.retained_days:
        facts.append(
            Fact(
                "Retained history",
                f"No day before the first match is retained, so {service.domain}'s campus standing "
                "(CASE_STUDY §15) cannot be judged.",
            )
        )
    elif service is not None and service.prior is not None:
        prior = service.prior
        established = (
            prior.addresses >= ESTABLISHED_MIN_ADDRESSES and prior.days >= ESTABLISHED_MIN_DAYS
        )
        facts.append(
            Fact(
                "Retained history",
                f"{service.domain} in the {prior.retained_days} retained day(s) before the first "
                f"match: {prior.addresses} campus address(es) on {prior.days} day(s); "
                f"established ({ESTABLISHED_MIN_ADDRESSES}+ addresses on {ESTABLISHED_MIN_DAYS}+ "
                f"days, CASE_STUDY §15): {'yes' if established else 'no'}.",
            )
        )
    for server, sharing in evidence.addresses.items():
        shared = sharing.most_domains >= SHARED_MIN_DOMAINS
        network = sharing.shared_by_design
        facts.append(
            Fact(
                "Measured, CASE_STUDY §14",
                f"{server} carried at most {sharing.most_domains} registered domain(s)"
                + (
                    ": shared hosting"
                    if shared
                    else f", and is on {network.name}'s network, whose sites share its addresses "
                    "by design: shared hosting"
                    if network is not None
                    else f": not shown to be shared ({SHARED_MIN_DOMAINS}+ would be)"
                )
                + ".",
            )
        )
    registered = name_facts(case.indicator).registered if case.is_domain else None
    if registered is not None and evidence.registrations is not None:
        age = evidence.registrations.get(registered)
        days = age.days_before(case.first) if age is not None else None
        if age is not None and age.registered is not None and days is not None:
            facts.append(
                Fact(
                    "RDAP",
                    f"{registered} was registered {age.registered:%Y-%m-%d}, {days:.0f} day(s) "
                    "before the first match.",
                )
            )
    return facts


def _windows(evidence: Evidence, live: LiveContext, history: HistoryContext) -> tuple[Window, ...]:
    if live.host_context is None:
        return ()
    case = evidence.case
    rows = live.host_context.get(case.source_host, ())
    starts = sorted({row.window_start for row in rows if row.window_start.date() in case.days})
    span = timedelta(seconds=CONTEXT_WINDOW_SECONDS)
    found = []
    for start in starts[:MAX_CONTEXT_WINDOWS]:
        ranked, habitual = rank_context(
            [row for row in rows if row.window_start == start], case, history
        )
        position = (
            "before"
            if start + span <= case.first
            else "contact"
            if start <= case.first
            else "after"
        )
        found.append(Window(start, position, tuple(ranked), habitual))
    return tuple(found)


def _names(names: list[str]) -> str:
    listed = ", ".join(names[:LISTED_NAMES])
    more = len(names) - LISTED_NAMES
    return listed + (f" and {more} more" if more > 0 else "")


def _lead_in(windows: tuple[Window, ...]) -> list[Fact]:
    before = [window for window in windows if window.position == "before"]
    if not before:
        return []
    new = list(
        dict.fromkeys(
            row.root_domain
            for window in before
            for row, tag in window.rows
            if tag in (NEW_TAG, UNESTABLISHED_TAG) and row.root_domain
        )
    )
    start = minute(before[0].start)
    if not new:
        return [
            Fact(
                "Live source",
                f"In the window before the contact (from {start} UTC) the host used no name "
                "new to it or unestablished on campus.",
            )
        ]
    return [
        Fact(
            "Live source",
            f"Just before the contact (from {start} UTC) the host first used {len(new)} name(s) "
            f"new to it or unestablished on campus: {_names(new)}.",
        )
    ]


def _after(evidence: Evidence, after: AfterView | None) -> list[Fact]:
    if after is None:
        return []
    case = evidence.case
    named = [d for d in after.new if d.named]
    nameless = [d for d in after.new if not d.named]
    uploads = [d for d in after.new if d.up_bytes >= UPLOAD_BYTES]
    span = f"{after.first_day} to {after.last_day}"
    if named:
        first = named[0]
        lead = (
            f"after the first match the next destination new to this host was {first.name}, "
            f"{duration((first.first_minute - case.first).total_seconds())} later"
        )
    else:
        lead = "no named destination was new to this host after the first match"
    upload_text = (
        "; ".join(f"{d.name} {size(d.up_bytes)}" for d in uploads[:LISTED_NAMES])
        if uploads
        else "none"
    )
    return [
        Fact(
            "Live source",
            f"Read {span} ({after.days} day(s)): {lead}; {len(named)} new named destination(s) "
            f"and {len(nameless)} network(s) with no name in all; uploads of 1 MB or more to new "
            f"destinations (CASE_STUDY §8): {upload_text}.",
        )
    ]


def _later_contact(evidence: Evidence) -> list[Fact]:
    case = evidence.case
    if evidence.live_status != "queried":
        return []
    later_days = [day for day in evidence.live_days if day > case.days[-1]]
    later = sorted(
        {
            day
            for contact in evidence.contacts
            if contact.source == "live"
            for day in contact.days
            if day > case.days[-1]
        }
    )
    if later:
        return [
            Fact(
                "Live source",
                f"The host was in contact with the flagged address(es) again on {day_list(later)}.",
            )
        ]
    if later_days:
        return [
            Fact(
                "Live source",
                "No contact with the flagged address(es) on the re-queried day(s) after the "
                f"match ({day_list(later_days)}); matched on the address, so a moved name would "
                "not show.",
            )
        ]
    return []


def _continuity(evidence: Evidence, after: AfterView | None) -> list[Fact]:
    found = after.continuity if after is not None else None
    if found is None:
        return []
    before = (
        f" ({found.overlap_before:.2f} between two spans before it)"
        if found.overlap_before is not None
        else ""
    )
    whole = evidence.history.whole_host
    retained = (
        f" (retained history: {whole.retained_days - whole.addressed_days} of "
        f"{whole.retained_days} days)"
        if whole is not None and whole.retained_days
        else ""
    )
    return [
        Fact(
            "Live source",
            f"Named destinations shared by the {found.span_days} active day(s) before and after "
            f"the match: {found.overlap_after:.2f}{before}; no traffic with a known remote "
            f"address on {found.silent_after} of {found.days_after} later day(s){retained}.",
        )
    ]


def _whole_host(evidence: Evidence) -> list[Fact]:
    whole = evidence.history.whole_host
    if whole is None or whole.first_day is None:
        return []
    facts = [
        Fact(
            "Retained history",
            f"{whole.first_day} to {whole.last_day}: {whole.retained_days} retained day(s), "
            f"traffic with a known remote address on {whole.addressed_days}; "
            f"{whole.services_since_match} service(s) first used on or after "
            f"{evidence.case.days[0]}.",
        )
    ]
    if whole.episode_counts:
        total = sum(n for _, _, n in whole.episode_counts)
        other = (
            f", {whole.other_episode_count} other than relationship"
            if whole.other_episode_count
            else ", all relationship"
        )
        earlier = sum(count for _, count in whole.superseded)
        marked = (
            f"; {earlier} of them published before the triage repo corrected their family "
            "(DNS before primary-detectors-v8, transfer and fanout before -v9)"
            if earlier
            else ""
        )
        facts.append(
            Fact(
                "Published triage stream",
                f"{total} episode(s) on {whole.episode_days} day(s){other}{marked}.",
            )
        )
    return facts


def _timeline(evidence: Evidence, decision: Decision) -> tuple[TimelineRow, ...]:
    rows: list[TimelineRow] = []
    contact_copies: dict[int, list[int]] = defaultdict(list)
    for feed, copy in evidence.contact_duplicates.items():
        contact_copies[copy].append(feed)
    flow_copies: dict[int, list[int]] = defaultdict(list)
    for feed, copy in evidence.flow_duplicates.items():
        flow_copies[copy].append(feed)
    for index, judged in enumerate(decision.contacts):
        if evidence.hidden_contact(index):
            continue
        contact = judged.item
        assert isinstance(contact, Contact)
        rows.append(
            TimelineRow(
                kind="contact",
                source=_bare(source_label(contact, evidence, copy=index in contact_copies)),
                first=contact.minutes[0],
                last=contact.minutes[-1],
                what=contact.label,
                minutes=len(contact.minutes),
                flows=contact.flows,
                received=contact.down_bytes,
                sent=contact.up_bytes,
                longest_sec=None,
                status=combined_status(
                    judged, _judged(decision.contacts, contact_copies[index]), contact=True
                ),
            )
        )
    for index, judged in enumerate(decision.flows):
        if evidence.hidden_flow(index):
            continue
        flow = judged.item
        assert isinstance(flow, FlowContact)
        rows.append(
            TimelineRow(
                kind="long flows",
                source=_bare(source_label(flow, evidence, copy=index in flow_copies)),
                first=flow.start,
                last=flow.finish,
                what=flow.text,
                minutes=None,
                flows=flow.flows,
                received=flow.down_bytes,
                sent=flow.up_bytes,
                longest_sec=flow.longest_sec,
                status=combined_status(
                    judged, _judged(decision.flows, flow_copies[index]), contact=False
                ),
            )
        )
    return tuple(sorted(rows, key=lambda row: (row.first, row.kind)))


def _judged(items: tuple[Judged, ...], indexes: list[int]) -> list[Judged]:
    return [items[index] for index in indexes]


def _bare(label: str) -> str:
    return label.strip("[]")


def _days(evidence: Evidence, live: LiveContext, after: AfterView | None) -> tuple[DayPoint, ...]:
    if after is None or live.destinations is None:
        return ()
    case = evidence.case
    rows = live.destinations.get(case.source_host, ())
    named: dict[date, set[str]] = defaultdict(set)
    active: set[date] = set()
    for row in rows:
        active.add(row.day)
        if row.root_domain:
            named[row.day].add(row.root_domain)
    new: dict[date, int] = defaultdict(int)
    for destination in after.new:
        if destination.named:
            new[destination.first_minute.date()] += 1
    return tuple(
        DayPoint(
            day=day,
            destinations=len(named.get(day, ())),
            new=new.get(day, 0),
            silent=day not in active,
            match=day in case.days,
        )
        for day in sorted(live.destination_days)
    )
