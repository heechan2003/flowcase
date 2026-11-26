"""The case file, the next steps and the ledger line: all written by code from measured facts.

A review case gets the full case file. Every fact is one line that names its source, and the model
reads exactly that text. An explained case gets one ledger line with the rule that cleared it and
the numbers behind it. Every coverage gap is written out, because a gap read as silence is the
commonest way to clear a case wrongly.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from ioc_report.after import UPLOAD_BYTES, AfterView, Continuity, NewDestination
from ioc_report.after import view as after_view
from ioc_report.contact import Contact, Evidence, FlowContact, bitmap_timing
from ioc_report.feed import HELD_OPEN_SECONDS, Case
from ioc_report.history import HistoryContext, ServiceHistory, indicator_service, sni_service
from ioc_report.knowledge import (
    THREATFOX,
    is_platform,
    name_facts,
    other_list_background,
    service_for,
)
from ioc_report.live import ContextRow, LiveContext, after_days, after_rows
from ioc_report.rules import (
    ESTABLISHED_MIN_ADDRESSES,
    ESTABLISHED_MIN_DAYS,
    EXPLAINED,
    SHARED_MIN_DOMAINS,
    Decision,
    Judged,
    registration,
)
from ioc_report.text import day_list
from ioc_report.text import day_list as _day_list
from ioc_report.text import duration as _duration
from ioc_report.text import minute as _minute
from ioc_report.text import network as _network
from ioc_report.text import size as _bytes
from ioc_report.text import transport as _transport
from ioc_report.text import when as _when

MAX_NAMES = 6
MAX_CONTEXT_WINDOWS = 3
# Output bounds, not thresholds: how many destinations a context or after-contact line lists.
MAX_CONTEXT_LISTED = 15
MAX_AFTER_LISTED = 8
LOOKUP_BEFORE = timedelta(minutes=15)
LOOKUP_AFTER = timedelta(minutes=60)


@dataclass(frozen=True, slots=True)
class Caveat:
    """Something an explained verdict could not check, or the weakest ground it rests on."""

    code: str
    """`live`, `stream`, `retained` or `e3-name`."""
    text: str


@dataclass(frozen=True, slots=True)
class Observed:
    """Shapes as measured. The model may describe these only where they are true."""

    held_open: bool
    regular: bool
    large_transfer: bool
    """Any long flow: long_flows holds transfers of about 1 MB or more (CASE_STUDY §8)."""


def observed_shapes(evidence: Evidence) -> Observed:
    flows = (*evidence.flows, *evidence.other_flows)
    rows = [row for service in evidence.history.services for row in service.match_rows]
    return Observed(
        held_open=any(flow.held_open_flows for flow in flows),
        regular=any(day.regular for day in evidence.pair_days)
        or any(bitmap_timing(row).regular for row in rows),
        large_transfer=bool(flows),
    )


def render_case_file(
    evidence: Evidence,
    decision: Decision,
    live: LiveContext,
    history: HistoryContext,
    *,
    blind: bool = False,
) -> str:
    """`blind` leaves out the decision and every per-contact rule outcome: the facts a second
    opinion must reach its own verdict from."""
    case = evidence.case
    lines = [f"Indicator: {case.indicator} ({case.indicator_type}). Host: {case.host}."]
    if not blind:
        lines += _decision(decision)
    lines += _listing(evidence, decision)
    lines += _contacts(evidence, decision, blind=blind)
    lines += _flows(evidence, decision, blind=blind)
    lines += _timing(evidence)
    lines += _addresses(evidence)
    lines += _names(evidence, history)
    lines += _stream(evidence)
    lines += _whole_host(evidence)
    lines += _host(evidence, live, history)
    lines += _after(evidence, live, history)
    lines += _coverage(case, evidence, live, history)
    lines.append(_measured(observed_shapes(evidence)))
    return "\n".join(lines)


def caveats(evidence: Evidence, decision: Decision) -> tuple[Caveat, ...]:
    """What the decision could not check: the live re-query, the stream (K3), the retained
    5-minute schedule check (K4), and E3 resting on a name of unknown age. A case with none was
    checked by every rule the deployment has."""
    case = evidence.case
    found: list[Caveat] = []
    if evidence.live_status != "queried":
        reason = {
            "skipped": "the live source was not queried (--no-live)",
            "unavailable": "the live source was unavailable",
        }.get(evidence.live_status, f"the live source was {evidence.live_status}")
        found.append(Caveat("live", f"{reason}: the contacts are the feed's own minutes"))
    elif expired := [day for day in case.days if day not in evidence.live_days]:
        found.append(
            Caveat(
                "live",
                f"minute detail for {day_list(expired)} had expired: the contacts on those days "
                "are the feed's own minutes",
            )
        )
    if unpublished := evidence.history.match_days_unpublished:
        found.append(
            Caveat(
                "stream",
                f"no published triage stream for {day_list(unpublished)}: K3 could not be checked",
            )
        )
    if not_retained := evidence.history.match_days_not_retained:
        found.append(
            Caveat(
                "retained",
                f"{day_list(not_retained)} not retained: the 5-minute schedule check (K4) could "
                "not run",
            )
        )
    for judged in decision.contacts:
        contact = judged.item
        if judged.rules != ("E3",) or not isinstance(contact, Contact):
            continue
        age = registration(contact.sni, evidence)
        if age is not None and age.days_before(case.first) is not None:
            continue
        domain = name_facts(contact.sni).registered or contact.sni
        if evidence.registrations is None:
            why = "its registration date was not looked up (NAME_LOOKUP=rdap)"
        elif age is not None and age.registered is not None:
            why = "it was registered again after the match, so its age then is unknown"
        elif age is not None and age.unknown_reason:
            why = f"its registration date is unknown: {age.unknown_reason}"
        else:
            why = "its registration date is unknown"
        key = sni_service(contact.server_ip, contact.sni)
        service = evidence.history.service(key.service_id_hex) if key is not None else None
        prior = service.prior if service is not None else None
        campus = (
            f"; no campus host used it in the {prior.retained_days} retained days before the "
            "first match"
            if prior is not None and prior.retained_days and prior.addresses == 0
            else ""
        )
        found.append(
            Caveat("e3-name", f"E3 alone explains {contact.label}: {domain}: {why}{campus}")
        )
    return tuple(found)


@dataclass(frozen=True, slots=True)
class NextStep:
    system: str
    """Where to look: device, endpoint, triage stream, proxy, resolver or mail."""
    text: str


def next_steps(
    evidence: Evidence, decision: Decision, after: AfterView | None = None
) -> tuple[str, ...]:
    """What to look up, where and when: the flow records end at the address, and what settles a
    review case (the device, the process, the URL) sits in other systems."""
    return tuple(step.text for step in next_step_items(evidence, decision, after))


def next_step_items(
    evidence: Evidence, decision: Decision, after: AfterView | None = None
) -> tuple[NextStep, ...]:
    """`next_steps`, each with the system it is looked up in."""
    case = evidence.case
    known = other_list_background(case.listing.source, case.listing.malware)
    family_check = (
        decision.family.check
        if decision.family is not None
        else known.check
        if known is not None
        else None
    )
    first = _when(case.first)
    window = _window(case)
    continuity = after.continuity if after is not None else None
    changed = (
        f" To judge whether the address still holds that device: its named destinations after "
        f"the match overlap those before it by {continuity.overlap_after:.2f}"
        + (
            f", against {continuity.overlap_before:.2f} between two spans before it"
            if continuity.overlap_before is not None
            else ""
        )
        + ", and it had no traffic with a known remote address on "
        f"{continuity.silent_after} of {continuity.days_after} "
        "later day(s) (see [Live source, continuity])."
        if continuity is not None
        else ""
    )
    steps: list[NextStep] = [
        NextStep(
            "device",
            f"Identify the device: the address lease (DHCP, network access control or VPN logs) "
            f"for {case.host} {window}. An address is not a device (CASE_STUDY §6).{changed}",
        )
    ]
    rules = decision.keeping_rules
    if "K1" in rules:
        steps.append(
            NextStep(
                "endpoint",
                family_check
                or f"Check the endpoint record around {first} for the process that reached "
                f"{case.indicator} and anything it fetched or started.",
            )
        )
    if "K2" in rules:
        steps.append(
            NextStep(
                "endpoint",
                f"Find the process on the host that connected to the tunnel at {first} and what "
                "it reached through it.",
            )
        )
    if "K3" in rules:
        steps.append(
            NextStep(
                "triage stream",
                "Read the triage stream's episode for this host on the same destination (see "
                "[Published triage stream]) beside this match.",
            )
        )
    if "K4" in rules:
        steps.append(
            NextStep(
                "endpoint",
                "Find which process makes the scheduled contact listed under K4; a schedule this "
                "regular is a program, not a person.",
            )
        )
    if "K5" in rules:
        steps.append(
            NextStep(
                "endpoint",
                f"Find what the host downloaded from {', '.join(case.server_ips)} (proxy, browser "
                "or endpoint file events) and whether it ran.",
            )
        )
    distinct: dict[str, Judged] = {}
    for judged in decision.unexplained:
        distinct.setdefault(_item_text(judged.item), judged)
    # One step for every unexplained item: the first names where to start, the count the rest. The
    # case card groups the reasons; a step per contact repeated them.
    if distinct:
        text, judged = next(iter(distinct.items()))
        when = _when(_first_time(judged.item))
        lead = (
            f"Identify the process behind {text}"
            if len(distinct) == 1
            else f"Identify the process behind the {len(distinct)} contacts and flows no rule "
            f"explains, starting with {text}"
        )
        if case.listing.inbound:
            steps.append(
                NextStep(
                    "endpoint",
                    f"Check the host's own logs for what the remote side asked for in {text} at "
                    f"{when}.",
                )
            )
        else:
            steps.append(NextStep("endpoint", f"{lead} at {when}: {judged.gap}."))
    if decision.unexplained and family_check and family_check not in {s.text for s in steps}:
        steps.append(NextStep("endpoint", family_check))
    if case.is_domain:
        steps.append(
            NextStep(
                "web gateway",
                f"Web gateway or proxy logs for requests to {case.indicator} {window}: the full "
                "URL, the user agent and any file served (name, size, hash).",
            )
        )
        steps.append(
            NextStep(
                "resolver",
                f"Resolver logs for the device's queries for {case.indicator} {window}; flow "
                "records carry no query names (CASE_STUDY §9).",
            )
        )
        if case.listing.threat_type == "payload_delivery":
            steps.append(
                NextStep(
                    "mail",
                    f"Mail gateway: messages to the device's user in the 24 hours before {first} "
                    f"that link to {case.indicator}.",
                )
            )
    distinct_steps: dict[str, NextStep] = {}
    for step in steps:
        distinct_steps.setdefault(step.text, step)
    return tuple(distinct_steps.values())


def ledger_line(evidence: Evidence, decision: Decision) -> str:
    """What cleared an explained case, with the numbers behind it."""
    if decision.disposition != EXPLAINED:
        raise ValueError("only an explained case has a ledger line")
    counts: Counter[str] = Counter()
    texts: dict[str, str] = {}
    shown = [
        judged
        for index, judged in enumerate(decision.contacts)
        if not evidence.hidden_contact(index)
    ] + [judged for index, judged in enumerate(decision.flows) if not evidence.hidden_flow(index)]
    for judged in shown:
        for finding in judged.explained_by:
            counts[finding.rule] += 1
            if isinstance(judged.item, Contact):
                texts.setdefault(finding.rule, finding.text)
    parts = [
        f"{rule} x{counts[rule]}" + (f": {texts[rule]}" if rule in texts else "")
        for rule in sorted(counts)
    ]
    return "; ".join(parts)


def _decision(decision: Decision) -> list[str]:
    source = "[Decision, by code]"
    lines = [
        f"{source} {decision.disposition}: "
        + (
            "kept by " + ", ".join(decision.keeping_rules)
            if decision.kept_by
            else "not every contact is explained"
        )
        + "."
    ]
    lines.extend(f"{source} {finding.rule}: {finding.text}." for finding in decision.kept_by)
    lines.extend(
        f"{source} not explained: {_item_text(judged.item)}: {judged.gap}."
        for judged in decision.unexplained
    )
    lines.extend(f"{source} {note}" for note in decision.notes)
    # The same traffic judged from the feed and from the live re-query reads identically.
    return list(dict.fromkeys(lines))


def _listing(evidence: Evidence, decision: Decision) -> list[str]:
    case = evidence.case
    claim = case.listing
    confidence = "not given" if claim.confidence is None else str(claim.confidence)
    hosts = case.other_hosts_same_indicator + 1
    spread = (
        f"; across all {hosts} of them, the flagged address(es) carried "
        f"{case.domains_same_indicator} different registered domain(s)"
        if hosts > 1
        else ""
    )
    lines = [
        f"[{claim.source}, about the indicator only] "
        f"{'malware' if claim.source == THREATFOX.source else 'listed under'} {claim.malware}; "
        "threat type "
        f"{claim.threat_type}; confidence {confidence}.",
        f"[IOC feed] other hosts in this feed that matched the same indicator: "
        f"{case.other_hosts_same_indicator}{spread}.",
    ]
    if case.other_indicators:
        lines.append(
            "[IOC feed] this host also matched: "
            + ", ".join(f"{indicator} ({malware})" for indicator, malware in case.other_indicators)
            + "."
        )
    family = decision.family
    background = "[Knowledge, background not evidence]"
    if family is not None:
        lines.append(f"{background} {family.name}: {family.background}")
    elif (known := other_list_background(claim.source, claim.malware)) is not None:
        lines.append(f"{background} {known.name}: {known.background}")
    else:
        lines.append(f"{background} no cited profile for {claim.malware}.")
    registered = name_facts(case.indicator).registered if case.is_domain else None
    if (
        registered is not None
        and evidence.registrations is not None
        and registered in evidence.registrations
    ):
        lines.append(
            f"[RDAP, about the indicator only] {registered}"
            f"{_registered(registered, evidence).replace(' (RDAP)', '')}."
        )
    if case.is_domain and (service := service_for(case.indicator)) is not None:
        lines.append(
            f"{background} {case.indicator} is {service.name}; its own client uses "
            + ", ".join(f"{port}/{_transport(t)}" for port, t in service.client_ports)
            + "."
        )
    return lines


def source_label(item: Contact | FlowContact, evidence: Evidence, *, copy: bool) -> str:
    """Where a contact or flow comes from. A feed item on a day the live source re-read is not
    "not re-queried"; a live item that holds a feed item in full says so, and that feed item is
    not listed again."""
    if item.source == "live":
        return "[Live source, also in the IOC feed]" if copy else "[Live source]"
    days = item.days if isinstance(item, Contact) else (item.day,)
    if evidence.live_status == "queried" and all(day in evidence.live_days for day in days):
        return "[IOC feed, not matched by the live re-query]"
    return "[IOC feed, not re-queried]"


def combined_status(judged: Judged, others: Iterable[Judged], *, contact: bool) -> str:
    """One status for traffic judged twice (feed and live): the stricter of the two."""
    for item in (judged, *others):
        if not item.explained:
            return f"not explained: {item.gap}"
    if contact:
        return "explained by " + "; ".join(f"{f.rule} ({f.text})" for f in judged.explained_by)
    return "explained by " + ", ".join(judged.rules)


def _contacts(evidence: Evidence, decision: Decision, *, blind: bool = False) -> list[str]:
    lines = []
    copies: dict[int, list[int]] = {}
    for feed, live in evidence.contact_duplicates.items():
        copies.setdefault(live, []).append(feed)
    for index, judged in enumerate(decision.contacts):
        if evidence.hidden_contact(index):
            continue
        contact = judged.item
        assert isinstance(contact, Contact)
        source = source_label(contact, evidence, copy=index in copies)
        status = combined_status(
            judged, (decision.contacts[feed] for feed in copies.get(index, ())), contact=True
        )
        lines.append(
            f"{source} contact {contact.label}: {len(contact.minutes)} minute(s) on "
            f"{_day_list(contact.days)}, first {_minute(contact.minutes[0])}, last "
            f"{_minute(contact.minutes[-1])} UTC; {_bytes(contact.down_bytes)} received, "
            f"{_bytes(contact.up_bytes)} sent; {contact.flows} flow(s) counted."
            + ("" if blind else f" {status}.")
        )
    return lines


def _flows(evidence: Evidence, decision: Decision, *, blind: bool = False) -> list[str]:
    lines = []
    copies: dict[int, list[int]] = {}
    for feed, live in evidence.flow_duplicates.items():
        copies.setdefault(live, []).append(feed)
    for index, judged in enumerate(decision.flows):
        if evidence.hidden_flow(index):
            continue
        flow = judged.item
        assert isinstance(flow, FlowContact)
        source = source_label(flow, evidence, copy=index in copies)
        status = combined_status(
            judged, (decision.flows[feed] for feed in copies.get(index, ())), contact=False
        )
        lines.append(
            f"{source} long flow(s) {_flow_text(flow)}." + ("" if blind else f" {status}.")
        )
    if not decision.flows:
        source = (
            "[IOC feed and live source]"
            if evidence.live_status == "queried"
            and all(day in evidence.live_days for day in evidence.case.days)
            else "[IOC feed, not re-queried]"
        )
        lines.append(
            f"{source} no long flows with the flagged address(es). "
            "long_flows only holds transfers of about 1 MB or more, so short contacts "
            "never appear there."
        )
    for position, flow in enumerate(evidence.other_flows):
        if position in evidence.other_flow_duplicates:
            continue
        lines.append(
            f"[Live source] long flow(s) on a day without minute detail, not attributed: "
            f"{_flow_text(flow)}."
        )
    return lines


def _flow_text(flow: FlowContact) -> str:
    label = f", source type {flow.label}" if flow.label else ""
    return (
        f"{flow.text}: {flow.flows} flow(s) from {_minute(flow.start)} to {_minute(flow.finish)} "
        f"UTC, longest {_duration(flow.longest_sec)}, {flow.held_open_flows} held open "
        f"{_duration(HELD_OPEN_SECONDS)} or more, {_bytes(flow.down_bytes)} received, "
        f"{_bytes(flow.up_bytes)} sent{label}"
    )


def _timing(evidence: Evidence) -> list[str]:
    lines = []
    for day in evidence.pair_days:
        shape = (
            "scheduled low-volume" if day.scheduled else "regular" if day.regular else "not regular"
        )
        gap = (
            f", mean gap {day.mean_gap_minutes:.1f} min, CV {day.cv:.2f}"
            if day.mean_gap_minutes is not None and day.cv is not None
            else ""
        )
        lines.append(
            f"[Timing, minute grain, CASE_STUDY §10] {day.server_ip} on {day.day}: "
            f"{day.minutes} minute(s) in {day.runs} run(s) over {day.span_hours:.1f} h{gap}, "
            f"{_bytes(day.total_bytes)} in all: {shape}."
        )
    for service in evidence.history.services:
        for row in service.match_rows:
            timing = bitmap_timing(row)
            gap = (
                f", mean gap {timing.mean_gap_minutes:.0f} min, CV {timing.cv:.2f}"
                if timing.mean_gap_minutes is not None and timing.cv is not None
                else ""
            )
            shape = (
                "beacon shape" if timing.beacon else "regular" if timing.regular else "not regular"
            )
            lines.append(
                f"[Timing, retained 5-minute buckets, CASE_STUDY §13] {service.domain} on "
                f"{timing.day}: {timing.active_buckets} bucket(s) over {timing.span_hours:.1f} h"
                f"{gap}, {_bytes(row.up_bytes + row.down_bytes)}, {timing.fanin} campus row(s) "
                f"for this service that day: {shape}."
            )
    return lines


def _addresses(evidence: Evidence) -> list[str]:
    lines = []
    networks = {
        row.server_ip: _network(row.asn, row.asn_org, row.country) for row in evidence.case.rows
    }
    for server, sharing in evidence.addresses.items():
        lines.append(
            f"[IOC feed] {server}: network {networks.get(server) or 'unknown'}; carried "
            f"{sharing.feed_domains} registered domain(s) across every record in this feed."
        )
        for day in sharing.live_days:
            lines.append(
                f"[Live source] {server} on {day.day}: {day.campus_clients} campus host(s) "
                f"exchanged traffic with it, {day.registered_domains} registered domain(s), "
                f"{day.ech_clients} host(s) with ECH, {day.udp_clients} over UDP; network(s) "
                f"{', '.join(f'AS{asn}' for asn in day.asns) or 'unknown'}."
            )
        by_count = sharing.most_domains >= SHARED_MIN_DOMAINS
        network = sharing.shared_by_design
        shared = (
            "shared hosting"
            if by_count
            else "not shown by this count"
            if network is not None
            else "not shown to be shared"
        )
        lines.append(
            f"[Measured, CASE_STUDY §14] {server}: at most {sharing.most_domains} registered "
            f"domain(s) observed; {SHARED_MIN_DOMAINS} or more is shared hosting: {shared}."
        )
        if network is not None and not by_count:
            lines.append(
                f"[Knowledge, public network fact] {server} is on {network.name}'s network "
                f"(AS{network.asn}), whose sites share its addresses by design: shared hosting."
            )
    return lines


def _names(evidence: Evidence, history: HistoryContext) -> list[str]:
    case = evidence.case
    lines = []
    own = indicator_service(case)
    retained = len(history.coverage.retained_days)
    services = sorted(
        evidence.history.services,
        key=lambda s: (
            s.service_id_hex != (own.service_id_hex if own else ""),
            s.key.basis,
            s.domain,
        ),
    )
    shown = 0
    for service in services:
        if shown >= MAX_NAMES and service.key.basis == "domain":
            continue
        shown += 1
        lines.append(
            _service_line(
                service, own is not None and own.service_id_hex == service.service_id_hex, retained
            )
        )
    names = sorted(
        {name for contact in evidence.contacts for name in (contact.sni, contact.dns) if name}
    )
    for name in names[:MAX_NAMES]:
        facts = name_facts(name)
        kind = facts.category or (
            "a tenant of a shared platform" if facts.platform_tenant else "an ordinary name"
        )
        lines.append(
            f"[Name] {name}: registered domain {facts.registered or 'none'}"
            f"{_registered(facts.registered, evidence)}; {kind}; leftmost label "
            f"{facts.label_length} characters, {facts.digit_ratio:.0%} digits, entropy "
            f"{facts.entropy:.2f} bits."
        )
    if len(names) > MAX_NAMES:
        lines.append(f"[Name] {len(names) - MAX_NAMES} more name(s) not listed.")
    return lines


def _registered(domain: str | None, evidence: Evidence) -> str:
    if domain is None:
        return ""
    if evidence.registrations is None:
        return ", registration not looked up"
    age = evidence.registrations.get(domain)
    if age is None:
        return ""
    days = age.days_before(evidence.case.first)
    if days is not None and age.registered is not None:
        return (
            f", registered {age.registered:%Y-%m-%d}, {days:.0f} day(s) before the first match "
            "(RDAP)"
        )
    if age.registered is not None:
        return ", registered again after the first match (RDAP): its age then is unknown"
    return f", registration date unknown: {age.unknown_reason or 'no answer'}"


def _service_line(service: ServiceHistory, indicator: bool, retained: int) -> str:
    source = "[Retained history]"
    unnamed = service.key.basis == "server_ip"
    what = (
        f"the flagged domain {service.domain}"
        if indicator
        else f"contact with {service.domain} that carried no name"
        if unnamed
        else f"the name {service.domain}"
    )
    if service.host_first_day is None:
        host = "this host never used it on a retained day"
    else:
        host = (
            f"this host first used it on {service.host_first_day}; "
            f"{service.host_days_before} retained day(s) before the match, "
            f"{service.host_days_on_match} on match days, {service.host_days_after} after"
        )
    prior = service.prior
    before = ""
    if unnamed:
        # History files named traffic under the name, so this count is only the unnamed part.
        before = (
            "; traffic to this address that carried a name is kept under that name instead, so "
            "this count says nothing about how many hosts used the address"
        )
    elif prior is not None:
        established = (
            prior.addresses >= ESTABLISHED_MIN_ADDRESSES and prior.days >= ESTABLISHED_MIN_DAYS
        )
        verdict = "yes" if established else "no"
        if is_platform(service.domain):
            # The rules never establish a tenant by its platform's popularity (rules._name_problem).
            verdict = "not applicable: a shared platform whose names are separate tenants"
        networks = ", ".join(f"AS{asn}" for asn in sorted(prior.asn_ids)[:5]) or "none"
        before = (
            f"; in the {prior.retained_days} retained day(s) before the first match: "
            f"{prior.addresses} campus address(es) on {prior.days} day(s), first seen "
            f"{prior.first_day or 'never'}, served from {networks}; established "
            f"({ESTABLISHED_MIN_ADDRESSES}+ addresses on {ESTABLISHED_MIN_DAYS}+ days, "
            f"CASE_STUDY §15): {verdict}"
        )
    return (
        f"{source} {what} (history keeps hashed services, not names): used by "
        f"{service.campus_addresses} campus address(es) on {service.campus_days} of {retained} "
        f"retained days{before}; {host}."
    )


def _stream(evidence: Evidence) -> list[str]:
    stream = "[Published triage stream]"
    record = evidence.history
    case = evidence.case
    lines = []
    if record.match_days_unpublished:
        lines.append(
            f"{stream} match day(s) never published: {_day_list(record.match_days_unpublished)}."
        )
    if record.episodes:
        families = Counter(episode.family for episode in record.episodes)
        best = min(episode.tier for episode in record.episodes)
        lines.append(
            f"{stream} this host had {len(record.episodes)} episode(s) on match days, any "
            f"service: {', '.join(f'{name} {count}' for name, count in sorted(families.items()))}; "
            f"best tier {best}."
        )
    elif len(record.match_days_unpublished) < len(case.days):
        lines.append(f"{stream} this host had no episode on the published match day(s).")
    same = record.same_service_episodes
    if same:
        lines.append(
            f"{stream} on a destination of this case: "
            + "; ".join(
                f"{e.day} {e.family} {e.tier} on {e.service_domain or 'a hashed service'}"
                for e in same
            )
            + "."
        )
    elif record.episodes:
        lines.append(f"{stream} none of those episodes is on a destination of this case.")
    earlier = Counter(episode.family for episode in record.episodes if episode.superseded)
    if earlier:
        lines.append(f"{stream} of those, {_superseded_text(earlier.items())}.")
    return lines


def _superseded_text(counts: Iterable[tuple[str, int]]) -> str:
    """Episodes published before the triage repo corrected their family's population
    (`history.CORRECTED_IN`). Published days are never re-scored, so they keep the old one."""
    found = dict(counts)
    parts = []
    if dns := found.get("dns", 0):
        parts.append(
            f"{dns} DNS episode(s) were published before primary-detectors-v8, which also scored "
            "DNS servers and addresses that only received a response (CASE_STUDY §9)"
        )
    if moved := found.get("transfer", 0) + found.get("fanout", 0):
        parts.append(
            f"{moved} transfer or fanout episode(s) were published before primary-detectors-v9, "
            "whose peers were mostly addresses with no service row (CASE_STUDY §3)"
        )
    return "; ".join(parts)


FLAGGED_TAG = "flagged address"
NEW_TAG = "new to this host"
UNESTABLISHED_TAG = "not established on campus"


def rank_context(
    rows: Iterable[ContextRow], case: Case, history: HistoryContext
) -> tuple[list[tuple[ContextRow, str]], int]:
    """One window's destinations, the ones that tell the story first: the flagged address, then
    names new to this host, then names the campus had not established (CASE_STUDY §15), then
    names history cannot place (tag ""). A name this host already used and the campus had
    established is habitual and only counted. Without the retained lookups the order is v1's."""
    if not history.names:
        return [(row, FLAGGED_TAG if row.flagged else "") for row in rows], 0
    ranked: list[tuple[int, ContextRow, str]] = []
    habitual = 0
    for row in rows:
        use = history.names.get((case.host, case.days[0], row.root_domain))
        if row.flagged:
            ranked.append((0, row, FLAGGED_TAG))
        elif use is None:
            ranked.append((3, row, ""))
        elif use.host_first_day is None or use.host_first_day >= case.days[0]:
            ranked.append((1, row, NEW_TAG))
        elif not (
            use.prior_addresses >= ESTABLISHED_MIN_ADDRESSES
            and use.prior_days >= ESTABLISHED_MIN_DAYS
        ):
            ranked.append((2, row, UNESTABLISHED_TAG))
        else:
            habitual += 1
    return [(row, tag) for _, row, tag in sorted(ranked, key=lambda item: item[0])], habitual


def _context(rows: list[ContextRow], case: Case, history: HistoryContext) -> str:
    listed, habitual = rank_context(rows, case, history)
    shown = listed[:MAX_CONTEXT_LISTED]
    rest = len(listed) - len(shown)
    parts = [
        f"{row.root_domain or 'no name'}"
        + (f" ({tag})" if tag else "")
        + f" {row.active_minutes} min, {row.addresses} address(es), "
        f"{_bytes(row.down_bytes)} received"
        for row, tag in shown
    ]
    if rest:
        parts.append(f"{rest} more not listed")
    if habitual:
        parts.append(
            f"{habitual} habitual service(s): used by this host before and established on campus"
        )
    return "; ".join(parts)


def _whole_host(evidence: Evidence) -> list[str]:
    whole = evidence.history.whole_host
    if whole is None or whole.first_day is None:
        return []
    case = evidence.case
    retained = "[Retained history, whole host]"
    lines = [
        f"{retained} {whole.first_day} to {whole.last_day}: {whole.retained_days} retained "
        f"day(s), with traffic to or from a known remote address on {whole.addressed_days}."
    ]
    stream = "[Published triage stream, whole host]"
    if whole.episode_counts:
        counts = ", ".join(f"{family} {tier} {n}" for family, tier, n in whole.episode_counts)
        if whole.other_episodes:
            listed = "; ".join(
                f"{e.day} {e.family} {e.tier} on {e.service_domain or 'a hashed service'}"
                for e in whole.other_episodes
            )
            more = whole.other_episode_count - len(whole.other_episodes)
            other = f"; other than relationship, latest first: {listed}" + (
                f"; {more} more" if more > 0 else ""
            )
        else:
            other = "; none other than relationship"
        total = sum(n for _, _, n in whole.episode_counts)
        lines.append(
            f"{stream} {total} episode(s) on {whole.episode_days} day(s), any service: "
            f"{counts}{other}."
        )
    else:
        lines.append(f"{stream} no episode on any published day.")
    if whole.superseded:
        lines.append(f"{stream} of these, {_superseded_text(whole.superseded)}.")
    names = ", ".join(whole.names_since_match)
    lines.append(
        f"{retained} services this host first used on or after {case.days[0]}: "
        f"{whole.services_since_match}"
        + (f"; those the stream named, earliest first: {names}" if names else "")
        + "."
    )
    return lines


def after_contact(
    evidence: Evidence, live: LiveContext, history: HistoryContext
) -> AfterView | None:
    """The view after the contact (`after.view`), when phase 3 read this host."""
    if live.destinations is None:
        return None
    case = evidence.case
    return after_view(case, after_rows(live, case), after_days(live, case), history.names)


def _after(evidence: Evidence, live: LiveContext, history: HistoryContext) -> list[str]:
    found = after_contact(evidence, live, history)
    if found is None:
        return []
    case = evidence.case
    source = "[Live source, after the contact]"
    span = f"{found.first_day} to {found.last_day} ({found.days} day(s) read)"
    named = [d for d in found.new if d.named]
    nameless = [d for d in found.new if not d.named]
    lines = []
    if named:
        first = named[0]
        later = (first.first_minute - case.first).total_seconds()
        lines.append(
            f"{source} {span}: {len(named)} named destination(s) new to this host after the "
            f"first match; the first, {first.name}, at {_minute(first.first_minute)} UTC, "
            f"{_duration(later)} after it."
        )
        lines.append(
            f"{source} new named destinations, earliest first: "
            + "; ".join(_new_text(d) for d in named[:MAX_AFTER_LISTED])
            + (
                f"; {len(named) - MAX_AFTER_LISTED} more not listed"
                if len(named) > MAX_AFTER_LISTED
                else ""
            )
            + "."
        )
    else:
        lines.append(
            f"{source} {span}: no named destination new to this host after the first match."
        )
    lines.append(
        f"{source} traffic with no name to a network new to this host after the first match: "
        + (
            "; ".join(
                f"{d.name} from {_minute(d.first_minute)} UTC, {_bytes(d.up_bytes)} sent"
                for d in nameless[:MAX_AFTER_LISTED]
            )
            or "none"
        )
        + "."
    )
    uploads = [d for d in found.new if d.up_bytes >= UPLOAD_BYTES]
    lines.append(
        f"{source} uploads of 1 MB or more to destinations new to this host (CASE_STUDY §8): "
        + ("; ".join(f"{d.name} {_bytes(d.up_bytes)}" for d in uploads) or "none")
        + "."
    )
    if (continuity := found.continuity) is not None:
        lines.append(_continuity(continuity, evidence))
    return lines


def _new_text(destination: NewDestination) -> str:
    standing = (
        ""
        if destination.established is None
        else ", established on campus"
        if destination.established
        else ", no campus use in the 90 days before"
        if destination.campus_before == 0
        else ", not established on campus"
    )
    return (
        f"{destination.name} ({_minute(destination.first_minute)} UTC, "
        f"{destination.active_minutes} min, {_bytes(destination.down_bytes)} received, "
        f"{_bytes(destination.up_bytes)} sent{standing})"
    )


def _continuity(continuity: Continuity, evidence: Evidence) -> str:
    before = (
        f"; between the two {continuity.span_days}-day spans before it: "
        f"{continuity.overlap_before:.2f}"
        if continuity.overlap_before is not None
        else ""
    )
    missing = (
        ", ".join(continuity.habitual_missing[:MAX_AFTER_LISTED])
        + (
            f" and {len(continuity.habitual_missing) - MAX_AFTER_LISTED} more"
            if len(continuity.habitual_missing) > MAX_AFTER_LISTED
            else ""
        )
        if continuity.habitual_missing
        else "none"
    )
    whole = evidence.history.whole_host
    retained = (
        f" (retained history: {whole.retained_days - whole.addressed_days} of "
        f"{whole.retained_days} days)"
        if whole is not None and whole.retained_days
        else ""
    )
    return (
        f"[Live source, continuity] named destinations shared by the {continuity.span_days} "
        f"active day(s) before and after the match (Jaccard): {continuity.overlap_after:.2f}"
        f"{before}. Named on every active day before and on none after: {missing}. Days after "
        "the last match day with no traffic to or from a known remote address: "
        f"{continuity.silent_after} of {continuity.days_after}{retained}."
    )


def _host(evidence: Evidence, live: LiveContext, history: HistoryContext) -> list[str]:
    lines = []
    for day in evidence.history.host_days:
        campus = (
            f"campus addresses with a service row: median {day.campus_p50_services:.0f}, "
            f"p90 {day.campus_p90_services:.0f}, p99 {day.campus_p99_services:.0f}"
            if day.campus_p50_services is not None
            and day.campus_p90_services is not None
            and day.campus_p99_services is not None
            else "no campus address had a service row that day"
        )
        lines.append(
            f"[Retained history] host on {day.day}: {day.unique_services} distinct services "
            f"({campus}), {day.unique_servers} distinct addresses, "
            f"{_bytes(day.total_bytes)} in all, {day.large_flow_count} long flow(s)."
        )
    case = evidence.case
    if live.host_context is None:
        return lines
    rows = live.host_context.get(case.source_host, ())
    windows = sorted({row.window_start for row in rows if row.window_start.date() in case.days})
    if not windows:
        lines.append(
            "[Live source] no minute detail around the contact: its day is outside the source's "
            "retention, or the host exchanged nothing else."
        )
    for start in windows[:MAX_CONTEXT_WINDOWS]:
        found = [row for row in rows if row.window_start == start]
        lines.append(
            f"[Live source] host's traffic {start:%Y-%m-%d %H:%M}-"
            f"{start + timedelta(minutes=5):%H:%M} UTC: {_context(found, case, history)}."
        )
    return lines


def _coverage(
    case: Case, evidence: Evidence, live: LiveContext, history: HistoryContext
) -> list[str]:
    lines = []
    if live.status == "skipped":
        lines.append("[Live source] not queried for this run.")
    elif live.status != "queried":
        lines.append(
            f"[Live source] unavailable ({live.error}). This is missing data, not absence of "
            "activity."
        )
    else:
        expired = [day for day in case.days if day in live.days_expired]
        if expired:
            lines.append(
                f"[Live source] minute detail for match day(s) {_day_list(expired)} has expired: "
                f"the source keeps about {live.retention_days} days."
            )
        queried = [day for day in live.days_queried if day in case.days or day == live.latest_day]
        seen = {
            day for contact in evidence.contacts if contact.source == "live" for day in contact.days
        }
        silent = [day for day in queried if day not in seen]
        if silent:
            lines.append(
                f"[Live source] no contact with the flagged address(es) on {_day_list(silent)}."
            )
        lines.append(
            "[Live source] live contact is matched on the flagged address(es) above; a domain "
            "that moved to a new address would not appear."
        )
    record = evidence.history
    coverage = history.coverage
    held = (
        f"{len(coverage.retained_days)} day(s) retained between {coverage.first_day} and "
        f"{coverage.last_day}"
        if coverage.retained_days
        else "no day is retained"
    )
    lines.append(
        f"[Retained history] {held}; match day(s) retained: "
        f"{_day_list(record.match_days_retained) or 'none'}; not retained: "
        f"{_day_list(record.match_days_not_retained) or 'none'}."
    )
    return lines


def _measured(observed: Observed) -> str:
    """The three readings the model's answer is checked against, stated outright."""
    return (
        f"[Measured, from the lines above] held-open connection ({_duration(HELD_OPEN_SECONDS)} "
        f"or more): {_yes(observed.held_open)}; regular schedule: {_yes(observed.regular)}; "
        f"transfer of about 1 MB or more: {_yes(observed.large_transfer)}."
    )


_MEASURED = re.compile(
    r"held-open connection \(.*?\): (yes|no); regular schedule: (yes|no); "
    r"transfer of about 1 MB or more: (yes|no)"
)


def observed_from_case_file(text: str) -> Observed:
    """The readings `_measured` wrote, back from a saved case file. Without that line nothing
    counts as observed, so a held-open or scheduled claim still fails the checks."""
    found = _MEASURED.search(text)
    if found is None:
        return Observed(held_open=False, regular=False, large_transfer=False)
    held_open, regular, large_transfer = (reading == "yes" for reading in found.groups())
    return Observed(held_open, regular, large_transfer)


def _item_text(item: Contact | FlowContact) -> str:
    if isinstance(item, Contact):
        return f"contact {item.label}"
    return f"long flow(s) {item.text}"


def _first_time(item: Contact | FlowContact) -> datetime:
    return item.minutes[0] if isinstance(item, Contact) else item.start


def _window(case: Case) -> str:
    """From shortly before the first matched minute to an hour after the last one that day."""
    first_day = [minute for minute in case.minutes if minute.date() == case.days[0]]
    start, end = case.first - LOOKUP_BEFORE, first_day[-1] + LOOKUP_AFTER
    text = f"from {_when(start)} to {_when(end)}"
    if len(case.days) > 1:
        text += f", and on the later match day(s) {day_list(case.days[1:])}"
    return text


def _yes(value: bool) -> str:
    return "yes" if value else "no"
