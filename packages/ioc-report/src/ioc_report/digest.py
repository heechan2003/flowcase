"""A case in a few grouped lines: what the threat is, what the host is, what happened, what code
decided and what the blind model said. Written by code from what the decision already holds.

The digest is what the local model reads to write a case's overview, and what the report shows
when no model ran. Every line names its source, as the case file's lines do, and no line states
a verdict on the host. Contacts the rules could not explain are grouped by why, so a case with a
hundred contacts reads as its two or three reasons rather than a hundred lines.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ioc_report.after import UPLOAD_BYTES
from ioc_report.casefile import after_contact, caveats
from ioc_report.contact import Contact, Evidence, FlowContact
from ioc_report.facts import story
from ioc_report.history import HistoryContext, ServingAddress
from ioc_report.knowledge import other_list_background
from ioc_report.live import LiveContext
from ioc_report.rules import (
    ECH_HIDDEN,
    EXPLAINED,
    FLOW_OVERLAPS_UNEXPLAINED,
    FLOW_UNATTRIBUTED,
    INBOUND_LISTING,
    NETWORK_NOT_SEEN,
    NEW_NAME,
    NO_HISTORY,
    NO_PROFILE,
    NO_REGISTERED_DOMAIN,
    NO_RULE,
    NO_SNI,
    NOT_C2_LISTING,
    NOT_ESTABLISHED,
    NOT_SHARED,
    OPERATOR_NAME,
    OTHER_INDICATOR,
    OTHER_LISTING,
    OWN_DOMAIN,
    PLATFORM_TENANT,
    RECORDS_DISAGREE,
    REVIEW,
    UNKNOWN_NETWORK,
    Decision,
    Finding,
    Judged,
)
from ioc_report.shadow import ShadowVerdict
from ioc_report.text import day_list, minute, network, size, when

# Output bounds, not thresholds: how much a digest line lists before it counts the rest.
LISTED = 6
LISTED_SIGNALS = 6
LISTED_NAMES = 8
LISTED_DOWNLOADS = 3

# What each gap kind means, in the words a group line uses.
KIND_LABEL = {
    NOT_C2_LISTING: "a payload-delivery listing, so the family's protocol says nothing",
    OTHER_LISTING: "the listing names no malware channel, so the family's protocol says nothing",
    INBOUND_LISTING: (
        "the list names addresses that connect in, so the name is likely the host's own site"
    ),
    NO_PROFILE: "the family has no cited C2 profile",
    RECORDS_DISAGREE: "the records disagree on the family",
    NO_REGISTERED_DOMAIN: "the name has no registered domain",
    OWN_DOMAIN: "the name is under the flagged domain",
    OPERATOR_NAME: "a dynamic-DNS or tunnel name the operator chooses",
    OTHER_INDICATOR: "the name is another indicator in the feed",
    PLATFORM_TENANT: "one tenant of a shared platform",
    NEW_NAME: "the name was registered under 32 days before the match",
    NO_SNI: "no TLS name, so no site can be named",
    ECH_HIDDEN: "ECH hides the site",
    NO_HISTORY: "no retained day before the match",
    NOT_ESTABLISHED: "a name the campus had not established",
    UNKNOWN_NETWORK: "the serving network is unknown",
    NETWORK_NOT_SEEN: "campus never saw the name served from that network",
    NOT_SHARED: "the address is not shown to be shared hosting",
    FLOW_OVERLAPS_UNEXPLAINED: "a long flow overlapping an unexplained contact",
    FLOW_UNATTRIBUTED: "a long flow no minute contact overlaps",
    NO_RULE: "no rule applies",
}

# Short rule names for group labels and verdict lines.
RULE_SHORT = {
    "E1": "UDP contact",
    "E2": "ECH browser traffic",
    "E3": "TLS to another site",
    "E4": "an established shared site",
    "E5": "the host's own tunnel client",
    "E6": "inbound traffic the host did not answer",
    "K1": "the host named the flagged domain",
    "K2": "a tunnel reached as a visitor",
    "K3": "a stream episode on the flagged destination",
    "K4": "a scheduled low-volume contact",
    "K5": "a transfer of 1 MB or more",
    "unexplained": "a contact no rule explains",
}

SECTIONS = ("Threat", "Host", "What happened", "Decision", "Model verdict")


@dataclass(frozen=True, slots=True)
class Line:
    source: str
    text: str

    def render(self) -> str:
        return f"[{self.source}] {self.text}"


@dataclass(frozen=True, slots=True)
class CaseDigest:
    threat: tuple[Line, ...]
    host: tuple[Line, ...]
    happened: tuple[Line, ...]
    decision: tuple[Line, ...]
    verdict: tuple[Line, ...]

    def sections(self) -> tuple[tuple[str, tuple[Line, ...]], ...]:
        return tuple(
            zip(
                SECTIONS,
                (self.threat, self.host, self.happened, self.decision, self.verdict),
                strict=True,
            )
        )

    def text(self) -> str:
        """What the writer reads: the sections in order, one sourced line each."""
        return "\n".join(
            f"{title}:\n" + "\n".join(f"- {line.render()}" for line in lines)
            for title, lines in self.sections()
            if lines
        )


def case_digest(
    evidence: Evidence,
    decision: Decision,
    live: LiveContext,
    history: HistoryContext,
    shadow: ShadowVerdict | None = None,
    serving: ServingAddress | None = None,
) -> CaseDigest:
    """`serving` is passed only on a list tied to an advisory (`knowledge.Listing.advisories`), so
    no ThreatFox digest changes."""
    return CaseDigest(
        threat=tuple(_threat(evidence, decision)),
        host=(*_host(evidence, live), *_serving(serving)),
        happened=(
            *_direction(evidence),
            *(Line(fact.source, fact.text) for fact in story(evidence, live, history)),
            *_new_downloads(evidence, live, history),
            *_kinds(evidence),
        ),
        decision=tuple(decision_lines(evidence, decision)),
        verdict=tuple(_verdict(decision, shadow)),
    )


# --- threat ---------------------------------------------------------------------------------------


def _threat(evidence: Evidence, decision: Decision) -> list[Line]:
    case = evidence.case
    claim = case.listing
    # ThreatFox's confidence rates the indicator and never decides anything, so the digest leaves
    # it out: the facts box and the case file still show it.
    lines = [
        Line(
            f"{claim.source}, about the indicator only",
            f"{case.indicator} ({case.indicator_type}) is listed as {claim.malware}, threat type "
            f"{claim.threat_type}.",
        )
    ]
    if decision.family is not None:
        lines.append(
            Line(
                "Knowledge, background not evidence",
                f"{decision.family.name}: {decision.family.background}",
            )
        )
    elif (known := other_list_background(claim.source, claim.malware)) is not None:
        lines.append(
            Line("Knowledge, background not evidence", f"{known.name}: {known.background}")
        )
    else:
        lines.append(
            Line(
                "Knowledge, background not evidence",
                f"no cited profile describes {claim.malware}.",
            )
        )
    networks: dict[str, str] = {}
    for row in case.rows:
        networks.setdefault(row.server_ip, network(row.asn, row.asn_org, row.country))
    for server in case.server_ips:
        lines.append(
            Line(
                "IOC feed",
                f"the flagged address {server} is in "
                f"{networks.get(server) or 'an unknown network'}.",
            )
        )
    if case.other_hosts_same_indicator:
        lines.append(
            Line(
                "IOC feed",
                f"{case.other_hosts_same_indicator} other host(s) in this feed matched the same "
                "indicator.",
            )
        )
    return lines


# --- host -----------------------------------------------------------------------------------------


def _serving(serving: ServingAddress | None) -> list[Line]:
    if serving is None:
        return []
    span = (
        f"on {serving.first_day}"
        if serving.days == 1
        else f"on {serving.days} day(s) from {serving.first_day} to {serving.last_day}"
    )
    return [
        Line(
            "Retained history, CASE_STUDY §17",
            f"the address served a named site to many outside networks {span}, with up to "
            f"{serving.peak_remotes} outside addresses on one day.",
        )
    ]


def _host(evidence: Evidence, live: LiveContext) -> list[Line]:
    lines = []
    whole = evidence.history.whole_host
    if whole is not None and whole.first_day is not None:
        lines.append(
            Line(
                "Retained history",
                f"the address appears on {whole.retained_days} retained day(s) from "
                f"{whole.first_day} to {whole.last_day}, with traffic to or from a known remote "
                f"address on {whole.addressed_days}.",
            )
        )
        if whole.signals:
            listed = "; ".join(
                f"{use.name} on {use.days} day(s), {use.recent_days} of them in the 30 days "
                "before the match"
                for use in whole.signals[:LISTED_SIGNALS]
            )
            lines.append(
                Line(
                    "Retained history, cited knowledge",
                    f"products with a known purpose this address used: {listed}. Each is a "
                    "domain the product owns; a browser visit to it looks the same.",
                )
            )
        else:
            lines.append(
                Line(
                    "Retained history, cited knowledge",
                    "none of the products with a known purpose appears on its retained days.",
                )
            )
    for day in evidence.history.host_days[:1]:
        campus = (
            f"campus addresses with a service row had a median of "
            f"{day.campus_p50_services:.0f} and a 90th percentile of "
            f"{day.campus_p90_services:.0f}"
            if day.campus_p50_services is not None and day.campus_p90_services is not None
            else "no campus figure exists for that day"
        )
        lines.append(
            Line(
                "Retained history",
                f"on {day.day} it used {day.unique_services} distinct services ({campus}) and "
                f"moved {size(day.total_bytes)}.",
            )
        )
    if whole is not None and whole.episode_counts:
        families: Counter[str] = Counter()
        for family, _tier, count in whole.episode_counts:
            families[family] += count
        total = sum(families.values())
        earlier = sum(count for _, count in whole.superseded)
        marked = (
            f"; {earlier} of them were published before the triage repo corrected their "
            "family's population (DNS before primary-detectors-v8, transfer and fanout before "
            "-v9)"
            if earlier
            else ""
        )
        lines.append(
            Line(
                "Published triage stream",
                f"{total} episode(s) on {whole.episode_days} day(s): "
                + ", ".join(f"{family} {count}" for family, count in families.most_common())
                + f"{marked}.",
            )
        )
    habitual = _habitual(evidence, live)
    if habitual:
        lines.append(habitual)
    if not lines:
        lines.append(Line("Retained history", "nothing about this address is retained."))
    return lines


def _habitual(evidence: Evidence, live: LiveContext) -> Line | None:
    """The names the address used on the most days phase 3 read: review cases only."""
    if live.destinations is None or not live.destination_days:
        return None
    rows = live.destinations.get(evidence.case.source_host, ())
    days: dict[str, set[object]] = defaultdict(set)
    for row in rows:
        if row.root_domain:
            days[row.root_domain].add(row.day)
    if not days:
        return None
    ranked = sorted(days.items(), key=lambda item: (-len(item[1]), item[0]))[:LISTED_NAMES]
    listed = ", ".join(f"{name} ({len(seen)})" for name, seen in ranked)
    return Line(
        "Live source",
        f"names it used on the most of the {len(live.destination_days)} day(s) read, with the "
        f"number of days: {listed}.",
    )


def _direction(evidence: Evidence) -> list[Line]:
    """On a list of addresses that connect in, which way to read the contact. No minute row says
    who opened it; CASE_STUDY §7 measures a remote port of 1024 or more on the long flows the
    remote side opened, and almost never on those the campus side opened."""
    case = evidence.case
    if not case.listing.inbound:
        return []
    text = "This list names addresses that connect in to their targets."
    if evidence.contacts and all(contact.port >= 1024 for contact in evidence.contacts):
        text += (
            " No flow record says who opened this contact. Its remote port of 1024 or more "
            "fits the remote side opening it; if so, the TLS name is this host's own site and "
            "what the host sent is its answer."
        )
    return [Line("Listing, CASE_STUDY §7", text)]


def _new_downloads(evidence: Evidence, live: LiveContext, history: HistoryContext) -> list[Line]:
    """On a list of addresses that connect in, a server's next question is what it fetched later.
    Shown only, on the 1 MB floor long_flows uses (CASE_STUDY §8). The records cannot link
    any of it to the listed address, and the line says so."""
    if not evidence.case.listing.inbound:
        return []
    after = after_contact(evidence, live, history)
    if after is None:
        return []
    large = sorted(
        (found for found in after.new if found.down_bytes >= UPLOAD_BYTES),
        key=lambda found: -found.down_bytes,
    )
    if not large:
        return [
            Line("Live source", "No destination new to this host sent it 1 MB or more afterwards.")
        ]
    listed = "; ".join(
        f"{found.name} sent it {size(found.down_bytes)} from {minute(found.first_minute)} UTC"
        + (", a name in routine campus use" if found.established else "")
        for found in large[:LISTED_DOWNLOADS]
    )
    return [
        Line(
            "Live source",
            f"{len(large)} destination(s) new to this host sent it 1 MB or more, "
            f"{size(sum(found.down_bytes for found in large))} in all. The largest: {listed}. "
            "Flow records cannot link this to the listed address or say what it carried.",
        )
    ]


def _kinds(evidence: Evidence) -> list[Line]:
    """Each kind of contact on its own, when there are several: what the contact line counts."""
    shown = [
        contact
        for index, contact in enumerate(evidence.contacts)
        if not evidence.hidden_contact(index)
    ]
    if len(shown) < 2:
        return []
    kinds = [
        f"{contact.label}, {len(contact.minutes)} minute(s), {size(contact.down_bytes)} received"
        for contact in shown[:LISTED]
    ]
    more = len(shown) - LISTED
    return [
        Line(
            "IOC feed and live source",
            "the kinds of contact: "
            + "; ".join(kinds)
            + (f"; and {more} more" if more > 0 else "")
            + ".",
        )
    ]


# --- decision -------------------------------------------------------------------------------------


def decision_lines(evidence: Evidence, decision: Decision) -> list[Line]:
    """What code decided, in groups: each keep rule once, each reason for an unexplained item
    once with how many items it covers, each explaining rule once with its count."""
    source = "Decision, by code"
    if decision.disposition == EXPLAINED:
        lines = [
            Line(
                source,
                "explained: every contact with the flagged address has an ordinary "
                "reason the rules can name.",
            )
        ]
    else:
        kept = ", ".join(
            f"{rule} ({RULE_SHORT.get(rule, rule)})" for rule in decision.keeping_rules
        )
        lines = [
            Line(
                source,
                f"review: kept by {kept}." if kept else "review: not every contact is explained.",
            )
        ]
    lines += [Line(source, text) for text in _kept(evidence, decision.kept_by)]
    lines += [Line(source, text) for text in _unexplained(evidence, decision)]
    lines += [Line(source, text) for text in _explaining(evidence, decision)]
    lines += [Line("Decision, by code", note) for note in decision.notes]
    seen = set()
    for caveat in caveats(evidence, decision):
        if caveat.text in seen:
            continue
        seen.add(caveat.text)
        lines.append(Line("Coverage", f"{caveat.text}."))
    return lines


def _kept(evidence: Evidence, findings: Sequence[Finding]) -> list[str]:
    case = evidence.case
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_rule[finding.rule].append(finding)
    lines = []
    for rule, found in by_rule.items():
        if rule == "K1":
            names = sorted(
                {
                    name
                    for contact in evidence.contacts
                    for name in contact.names
                    if case.names_flagged(name)
                }
            )
            visit = found[0].text.partition("; ")[2]
            lines.append(
                f"K1: the host's traffic named the flagged domain on {len(found)} kind(s) of "
                f"contact ({_listed(names)}); {visit}."
            )
        elif len(found) == 1:
            lines.append(f"{rule}: {found[0].text}.")
        else:
            lines.append(f"{rule} on {len(found)} items; the first: {found[0].text}.")
    return lines


def _unexplained(evidence: Evidence, decision: Decision) -> list[str]:
    groups: dict[tuple[str, ...], list[Judged]] = defaultdict(list)
    for judged in _visible(evidence, decision.unexplained, decision):
        kinds = tuple(dict.fromkeys(gap.kind for gap in judged.gaps)) or (NO_RULE,)
        groups[kinds].append(judged)
    lines = []
    for kinds, members in sorted(groups.items(), key=lambda item: -len(item[1])):
        contacts = [m.item for m in members if isinstance(m.item, Contact)]
        flows = [m.item for m in members if isinstance(m.item, FlowContact)]
        what = (
            (f"{len(contacts)} contact(s)" if contacts else "")
            + (" and " if contacts and flows else "")
            + (f"{len(flows)} long flow(s)" if flows else "")
        )
        servers = sorted({c.server_ip for c in contacts} | {f.server_ip for f in flows})
        names = sorted({name for contact in contacts for name in contact.names})
        reasons = "; ".join(KIND_LABEL.get(kind, kind) for kind in kinds)
        named = f" Names: {_listed(names)}." if names else ""
        lines.append(
            f"Not explained: {what} with {_listed(servers)} ({reasons}).{named} The first in "
            f"full: {members[0].gap}."
        )
    return lines


def _explaining(evidence: Evidence, decision: Decision) -> list[str]:
    counts: Counter[str] = Counter()
    texts: dict[str, str] = {}
    for judged in _visible(evidence, (*decision.contacts, *decision.flows), decision):
        for finding in judged.explained_by:
            counts[finding.rule] += 1
            if isinstance(judged.item, Contact):
                texts.setdefault(finding.rule, finding.text)
    return [
        f"{rule} explains {counts[rule]} item(s)" + (f": {texts[rule]}." if rule in texts else ".")
        for rule in sorted(counts)
    ]


def _visible(evidence: Evidence, items: Iterable[Judged], decision: Decision) -> list[Judged]:
    """The traffic once: a feed copy the live re-query holds in full is left out."""
    hidden = {id(decision.contacts[index]) for index in evidence.contact_duplicates} | {
        id(decision.flows[index]) for index in evidence.flow_duplicates
    }
    return [judged for judged in items if id(judged) not in hidden]


def _listed(values: Sequence[str]) -> str:
    shown = ", ".join(values[:LISTED])
    more = len(values) - LISTED
    return shown + (f" and {more} more" if more > 0 else "")


# --- model verdict --------------------------------------------------------------------------------


def _verdict(decision: Decision, shadow: ShadowVerdict | None) -> list[Line]:
    if shadow is None:
        return [Line("Model verdict", "no blind verdict was asked for in this run.")]
    source = f"Model verdict, blind, {shadow.model}"
    votes = Counter(sample.verdict for sample in shadow.samples)
    tally = ", ".join(f"{verdict} {count}" for verdict, count in votes.most_common()) or "none"
    agrees = shadow.agrees(decision.disposition)
    relation = (
        "it agrees with the code"
        if agrees
        else "it disagrees with the code"
        if agrees is False
        else "its samples split, so it gives no verdict"
    )
    lines = [
        Line(
            source,
            f"read the case file without the decision: {tally} of "
            f"{len(shadow.samples) + len(shadow.errors)} sample(s)"
            f"{', unanimous' if shadow.unanimous else ''}; {relation}. It is never applied.",
        )
    ]
    if shadow.samples:
        lines.append(Line(source, f"its first reasoning: {shadow.samples[0].reasoning}"))
    return lines


# --- groups and the feed --------------------------------------------------------------------------


def group_key(evidence: Evidence, decision: Decision) -> tuple[str, str, str, tuple[str, ...]]:
    claim = evidence.case.listing
    family = decision.family.name if decision.family is not None else claim.malware
    return (family, claim.threat_type, decision.disposition, decision.rules)


def group_label(key: tuple[str, str, str, tuple[str, ...]]) -> str:
    family, threat_type, disposition, rules = key
    reasons = ", ".join(RULE_SHORT.get(rule, rule) for rule in rules)
    verb = "kept for review by" if disposition == REVIEW else "explained by"
    return f"{family} ({threat_type}): {verb} {reasons}"


def case_line(evidence: Evidence, decision: Decision, shadow: ShadowVerdict | None) -> str:
    """One case in one line, for the group and feed digests. No host address: a group's text names
    its cases by number."""
    case = evidence.case
    caveat_codes = sorted({caveat.code for caveat in caveats(evidence, decision)})
    model = f"; blind model {shadow.majority or 'split'}" if shadow is not None else ""
    return (
        f"{case.indicator}: first match {when(case.first)}, "
        f"{len(case.minutes)} matched minute(s) on {day_list(case.days)}; code "
        f"{decision.disposition} ({', '.join(decision.rules)})"
        + (f"; caveats {', '.join(caveat_codes)}" if caveat_codes else "")
        + model
    )


def shared_facts(members: Sequence[tuple[Evidence, Decision]]) -> list[str]:
    """What a group's cases have in common, counted by code."""
    hosts = {evidence.case.host for evidence, _ in members}
    indicators = {evidence.case.indicator for evidence, _ in members}
    networks: Counter[str] = Counter()
    for evidence, _ in members:
        for server in evidence.case.server_ips:
            name = next(
                (
                    network(row.asn, row.asn_org, row.country)
                    for row in evidence.case.rows
                    if row.server_ip == server
                ),
                "",
            )
            networks[name or "unknown network"] += 1
    first = min(evidence.case.first for evidence, _ in members)
    last = max(evidence.case.first for evidence, _ in members)
    return [
        f"{len(members)} case(s): {len(hosts)} host(s), {len(indicators)} indicator(s); first "
        f"matches from {when(first)} to {when(last)}.",
        "flagged addresses by network: "
        + ", ".join(f"{name} {count}" for name, count in networks.most_common() if count)
        + ".",
    ]
