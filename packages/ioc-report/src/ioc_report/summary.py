"""What both renderers say about a run, computed once: the case results, their order, coverage, rule
and indicator counts, and the shadow-verdict tallies. No formatting beyond plain sentences, so the
Markdown and the HTML report cannot disagree about a number."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from ioc_report.casefile import Caveat, Observed, caveats, observed_shapes
from ioc_report.contact import Contact, Evidence
from ioc_report.digest import (
    RULE_SHORT,
    CaseDigest,
    Line,
    case_line,
    group_key,
    group_label,
    shared_facts,
)
from ioc_report.feed import Case, Feed, ListingClaim
from ioc_report.history import HistoryContext
from ioc_report.knowledge import THREATFOX, name_facts
from ioc_report.live import LiveContext
from ioc_report.narrative import NOT_WRITTEN, Narrative
from ioc_report.rules import (
    ESTABLISHED_MIN_ADDRESSES,
    ESTABLISHED_MIN_DAYS,
    EXPLAINED,
    REVIEW,
    SHARED_MIN_DOMAINS,
    Decision,
    Judged,
)
from ioc_report.shadow import ShadowVerdict
from ioc_report.text import day_list

_CASE_STUDY_SCHEDULE = "CASE_STUDY §10, §13"
RULES = (
    ("E1", "UDP, and the family's C2 channel is TCP only (cited profile; botnet_cc)", "knowledge"),
    ("E2", "ECH outer name: only browsers send ECH; the family is a native program", "knowledge"),
    (
        "E3",
        "TLS to another site no operator chose, not newly registered; the family's C2 has no TLS",
        "knowledge, CASE_STUDY §16",
    ),
    (
        "E4",
        f"established site ({ESTABLISHED_MIN_ADDRESSES}+ campus addresses on "
        f"{ESTABLISHED_MIN_DAYS}+ days before the match), served from its usual network, on an "
        f"address carrying {SHARED_MIN_DOMAINS}+ registered domains or on a network that shares "
        "its addresses by design",
        "CASE_STUDY §14, §15; knowledge",
    ),
    ("E5", "a tunnelling service's own client port: the host runs the tunnel client", "knowledge"),
    ("E6", "the host sent nothing: inbound traffic it did not answer", "feed"),
    ("K1", "the host's traffic named the flagged domain (lure and payload visits too)", "feed"),
    ("K2", "a tunnelling service reached on another port: a visitor", "knowledge"),
    ("K3", "a triage-stream episode on the flagged destination itself", "stream"),
    (
        "K4",
        "scheduled low-volume contact not explained as an established site",
        _CASE_STUDY_SCHEDULE,
    ),
    (
        "K5",
        "payload delivery: 1 MB or more not explained as an established site",
        "CASE_STUDY §8",
    ),
)
RULE_MEANING = {rule: meaning for rule, meaning, _ in RULES}


@dataclass(frozen=True, slots=True)
class CaseResult:
    evidence: Evidence
    decision: Decision
    case_file: str | None = None
    """Every fact with its source: what the blind verdict reads, folded into the report."""
    overview: Narrative = NOT_WRITTEN
    """The case's overview in four parts, by the writer; code's text stands when it is empty."""
    next_steps: tuple[str, ...] = ()
    shadow: ShadowVerdict | None = None
    """The model's blind second opinion, when the run asked for one. Never applied."""
    digest: CaseDigest | None = None
    """What the writer read, and the source of code's own overview text."""

    @property
    def disposition(self) -> str:
        return self.decision.disposition

    @property
    def caveats(self) -> tuple[Caveat, ...]:
        return caveats(self.evidence, self.decision)


def ordered(results: list[CaseResult]) -> list[CaseResult]:
    """Review first, then explained cases with caveats, then the fully checked ones, each by first
    matched minute. Investigation order, not a risk ranking."""
    return sorted(
        results,
        key=lambda result: (
            result.disposition != REVIEW,
            not result.caveats,
            result.evidence.case.first,
            result.evidence.case.indicator,
        ),
    )


def requeried(result: CaseResult) -> str:
    """Whether the live source re-read every match day: fully, partly or none."""
    evidence = result.evidence
    if evidence.live_status != "queried":
        return "none"
    days = evidence.case.days
    queried = sum(1 for day in days if day in evidence.live_days)
    return "fully" if queried == len(days) else "partly" if queried else "none"


def indicator_age(result: CaseResult) -> str:
    evidence = result.evidence
    case = evidence.case
    if not case.is_domain:
        return "—"
    if evidence.registrations is None:
        return "not looked up"
    domain = name_facts(case.indicator).registered
    age = evidence.registrations.get(domain) if domain is not None else None
    days = age.days_before(case.first) if age is not None else None
    if age is None or age.registered is None or days is None:
        return "unknown"
    return f"{age.registered:%Y-%m-%d}, {days:.0f} day(s) before"


def listing_line(case: Case) -> str:
    """When ThreatFox first and last saw the indicator, against the first match. Shown only.

    The feed's own `threatfox.first_seen_utc`/`last_seen_utc` are the matched flow's start and
    finish (IOC_Processor `agent/evidence.py`), so ThreatFox's dates come only from the hand-filled
    metadata file; without it the line says so rather than passing the match time off as a listing.
    Another list has no such file.
    """
    if case.listing.source != THREATFOX.source:
        return f"{case.listing.source}'s listing dates are not in the feed."
    if case.threatfox_first_seen is None:
        window = ""
        if case.matched_first is not None:
            end = f" to {case.matched_last:%Y-%m-%d %H:%M}" if case.matched_last else ""
            window = (
                ": its first_seen/last_seen are the matched flow's start and finish "
                f"({case.matched_first:%Y-%m-%d %H:%M}{end} UTC)"
            )
        return (
            f"ThreatFox's listing dates are not in the feed{window}. Add them to "
            "data/ioc_metadata.json to show them here."
        )
    hours = (case.first - case.threatfox_first_seen).total_seconds() / 3600
    span = f"{abs(hours):.0f} h" if abs(hours) < 48 else f"{abs(hours) / 24:.0f} day(s)"
    relation = f"{span} before the first match" if hours >= 0 else f"{span} after the first match"
    last = (
        f"; last seen {case.threatfox_last_seen:%Y-%m-%d %H:%M} UTC"
        if case.threatfox_last_seen
        else ""
    )
    return (
        f"ThreatFox first saw the indicator {case.threatfox_first_seen:%Y-%m-%d %H:%M} UTC, "
        f"{relation}{last} (from data/ioc_metadata.json)."
    )


@dataclass(frozen=True, slots=True)
class CoverageItem:
    label: str
    text: str
    details: tuple[str, ...] = ()


def coverage_items(
    feed: Feed, results: list[CaseResult], live: LiveContext, history: HistoryContext
) -> list[CoverageItem]:
    created = (
        f"records created {feed.created_first} to {feed.created_last}"
        if feed.created_first
        else "no creation times"
    )
    files = ", ".join(path.name for path in feed.paths)
    items = [
        CoverageItem(
            "Feed",
            f"{files}; {created}; {len(feed.rejected)} record(s) rejected.",
            tuple(f"rejected {item.match_id}: {item.reason}" for item in feed.rejected),
        )
    ]
    if live.status == "queried":
        items.append(
            CoverageItem(
                "Live source",
                f"minute detail queried for {day_list(live.days_queried)}; expired for "
                f"{day_list(live.days_expired) or 'none'}; long flows from "
                + (f"{live.long_flow_window.start:%Y-%m-%d}" if live.long_flow_window else "?")
                + " onwards; context around review contacts for "
                + (day_list(live.context_days) or "no day")
                + (
                    "; destinations for the after-contact view on "
                    + day_list(live.destination_days)
                    if live.destination_days
                    else ""
                )
                + ".",
                (live.error,) if live.error else (),
            )
        )
        counts = Counter(requeried(result) for result in results)
        items.append(
            CoverageItem(
                "Live re-query",
                f"every match day re-queried for {counts['fully']} of {len(results)} case(s), "
                f"some for {counts['partly']}, none for {counts['none']}. The source keeps minute "
                "detail about 15 days: run a feed the day it arrives.",
            )
        )
    elif live.status == "skipped":
        items.append(CoverageItem("Live source", "not queried (--no-live)."))
    else:
        items.append(CoverageItem("Live source", f"unavailable ({live.error})."))
    coverage = history.coverage
    held = (
        f"{len(coverage.retained_days)} day(s), {coverage.first_day} to {coverage.last_day}; "
        f"not retained: {day_list(coverage.gaps) or 'none'}"
        if coverage.retained_days
        else "no day is retained"
    )
    items.append(
        CoverageItem(
            "Retained history",
            f"{held}. Published stream days: {len(coverage.published_days)}. Opened read-only.",
        )
    )
    if live.audits:
        rows = sum(audit.read_rows for audit in live.audits)
        size = sum(audit.read_bytes for audit in live.audits)
        seconds = sum(audit.elapsed_seconds for audit in live.audits)
        items.append(
            CoverageItem(
                "Query footprint",
                f"{len(live.audits)} ClickHouse quer(ies), {rows:,} rows and {size / 1e9:.2f} GB "
                f"read in {seconds:.0f} s; aggregate-only, read-only.",
            )
        )
    return items


def rule_counts(results: list[CaseResult]) -> Counter[str]:
    """Cases each rule decided: explaining rules for explained cases, keeping rules for review
    ones, and "unexplained" for review cases with a contact no rule explains."""
    counts: Counter[str] = Counter()
    for result in results:
        decision = result.decision
        rules = (
            decision.explaining_rules
            if decision.disposition == EXPLAINED
            else decision.keeping_rules
        )
        counts.update(rules)
        if decision.disposition == REVIEW and decision.unexplained:
            counts["unexplained"] += 1
    return counts


@dataclass(frozen=True, slots=True)
class IndicatorRow:
    indicator: str
    claim: ListingClaim
    hosts: int
    review: int
    explained: int


def indicator_rows(results: list[CaseResult]) -> list[IndicatorRow]:
    grouped: dict[str, list[CaseResult]] = defaultdict(list)
    for result in results:
        grouped[result.evidence.case.indicator].append(result)
    rows = []
    for indicator, members in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        review = sum(1 for member in members if member.disposition == REVIEW)
        rows.append(
            IndicatorRow(
                indicator,
                members[0].evidence.case.listing,
                len(members),
                review,
                len(members) - review,
            )
        )
    return rows


def shadow_counts(results: list[CaseResult]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for result in results:
        if result.shadow is None:
            continue
        agrees = result.shadow.agrees(result.disposition)
        stable = "stable" if result.shadow.unanimous else "unstable"
        if agrees is None:
            counts["split"] += 1
        else:
            counts[f"{'agrees' if agrees else 'disagrees'}, {stable}"] += 1
    return counts


def shadow_worth_a_look(results: list[CaseResult]) -> list[CaseResult]:
    """Cases whose shadow verdict disagrees with code or is not unanimous."""
    return [
        result
        for result in results
        if result.shadow is not None
        and not (result.shadow.agrees(result.disposition) is True and result.shadow.unanimous)
    ]


def judged_text(judged: Judged) -> str:
    item = judged.item
    return f"contact {item.label}" if isinstance(item, Contact) else f"long flow(s) {item.text}"


@dataclass(frozen=True, slots=True)
class CaseGroup:
    """Cases code decided the same way for the same reasons, on the same family."""

    key: tuple[str, str, str, tuple[str, ...]]
    label: str
    numbers: tuple[int, ...]
    """The cases' numbers in report order."""
    results: tuple[CaseResult, ...]
    narrative: Narrative = NOT_WRITTEN

    @property
    def disposition(self) -> str:
        return self.key[2]


def case_groups(results: list[CaseResult]) -> list[CaseGroup]:
    """`results` in report order. Review groups first, then the largest."""
    members: dict[tuple[str, str, str, tuple[str, ...]], list[tuple[int, CaseResult]]] = (
        defaultdict(list)
    )
    for number, result in enumerate(results, 1):
        members[group_key(result.evidence, result.decision)].append((number, result))
    groups = [
        CaseGroup(
            key,
            group_label(key),
            tuple(number for number, _ in found),
            tuple(result for _, result in found),
        )
        for key, found in members.items()
    ]
    return sorted(groups, key=lambda g: (g.disposition != REVIEW, -len(g.results), g.numbers[0]))


def observed_union(results: tuple[CaseResult, ...] | list[CaseResult]) -> Observed:
    """The shapes any of the cases showed: what a paragraph about all of them may describe."""
    shapes = [observed_shapes(result.evidence) for result in results]
    return Observed(
        held_open=any(shape.held_open for shape in shapes),
        regular=any(shape.regular for shape in shapes),
        large_transfer=any(shape.large_transfer for shape in shapes),
    )


def group_digest(group: CaseGroup) -> str:
    """What the writer reads for a group: code facts only, cases named by number, not host."""
    first = group.results[0]
    lines = [
        f"Group: {group.label}.",
        *(
            f"- {fact}"
            for fact in shared_facts(
                [(result.evidence, result.decision) for result in group.results]
            )
        ),
    ]
    if first.digest is not None:
        lines += [f"- {line.render()}" for line in first.digest.threat[1:2]]
    lines.append("What each deciding rule means, by code:")
    lines += [f"- {rule}: {RULE_MEANING.get(rule, rule)}" for rule in group.key[3]]
    lines.append("Cases:")
    for number, result in zip(group.numbers, group.results, strict=True):
        contacts = [
            contact.label
            for index, contact in enumerate(result.evidence.contacts)
            if not result.evidence.hidden_contact(index)
        ]
        shown = "; ".join(contacts[:3]) + (
            f"; and {len(contacts) - 3} more" if len(contacts) > 3 else ""
        )
        lines.append(
            f"- case {number}: "
            + case_line(result.evidence, result.decision, result.shadow)
            + (f". Its contacts: {shown}" if shown else "")
        )
    return "\n".join(lines)


def feed_digest(
    feed: Feed,
    results: list[CaseResult],
    groups: list[CaseGroup],
    live: LiveContext,
    history: HistoryContext,
) -> str:
    """What the writer reads for the executive summary: totals, groups and gaps, by code."""
    review = [result for result in results if result.disposition == REVIEW]
    caveated = Counter(code for result in results for code in {c.code for c in result.caveats})
    lines = [
        f"Feed: {len(results)} case(s) from {feed.record_count} record(s): {feed.hosts} host(s), "
        f"{feed.indicators} indicator(s); {len(review)} kept for review, "
        f"{len(results) - len(review)} explained.",
        "Groups:",
        *(
            f"- {group.label}: {len(group.results)} case(s) "
            f"({', '.join(f'case {n}' for n in group.numbers)})."
            for group in groups
        ),
        "What could not be checked:",
        *(f"- {item.label}: {item.text}" for item in coverage_items(feed, results, live, history)),
        *(
            f"- explained cases with a {code} caveat: {count}"
            for code, count in sorted(caveated.items())
        ),
    ]
    if counts := shadow_counts(results):
        lines.append(
            "Blind model verdicts: "
            + ", ".join(f"{key} {value}" for key, value in sorted(counts.items()))
            + "."
        )
    return "\n".join(lines)


def case_text(result: CaseResult, part: str) -> str:
    """One part of a case's overview: the writer's, or code's own from the digest."""
    if result.overview.fields.get(part):
        return result.overview.fields[part]
    digest = result.digest
    if digest is None:
        return ""

    def texts(lines: Sequence[Line], count: int) -> str:
        return " ".join(line.text for line in lines[:count])

    if part == "threat":
        return texts(digest.threat, 2)
    if part == "host":
        return texts(digest.host, 2)
    if part == "what_happened":
        return texts(digest.happened, 1) or "No contact detail survives for this case."
    decision = result.decision
    reasons = ", ".join(RULE_SHORT.get(rule, rule) for rule in decision.rules)
    reading = (
        f"Code kept it for review: {reasons}."
        if decision.disposition == REVIEW
        else f"Code explained every contact: {reasons}."
    )
    if gaps := len({caveat.text for caveat in result.caveats}):
        reading += f" {gaps} check(s) could not run; see what it could not check."
    verdict = texts(digest.verdict, 1)
    return f"{reading} {verdict[:1].upper()}{verdict[1:]}"


def group_text(group: CaseGroup) -> str:
    if group.narrative.fields.get("analysis"):
        return group.narrative.fields["analysis"]
    return " ".join(shared_facts([(result.evidence, result.decision) for result in group.results]))


def feed_text(
    narrative: Narrative, results: list[CaseResult], groups: list[CaseGroup], part: str
) -> str:
    if narrative.fields.get(part):
        return narrative.fields[part]
    review = [result for result in results if result.disposition == REVIEW]
    if part == "summary":
        biggest = groups[0].label if groups else "no case"
        return (
            f"{len(results)} case(s): {len(review)} kept for review and "
            f"{len(results) - len(review)} explained by code. The largest group: {biggest}."
        )
    return (
        "Start with the review cases, in the order below; each card lists what to look up and "
        "where. Flow records carry no payload, process or user, so none of them can show what a "
        "host ran."
    )
