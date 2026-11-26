"""The report's structure, computed once for both renderers: the threats behind the feed, what to
do and where, the checks behind every verdict, and each case's verdict lines. Code-written and
display-only, so the HTML and the Markdown cannot disagree.

The shape follows the php2shell hunt write-up: a summary, the background, an analysis of each
group of like cases, the conclusion with its actions, one card per case, and an appendix that
lists what was checked and what a positive would have looked like.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from ioc_report.casefile import next_step_items
from ioc_report.contact import Contact
from ioc_report.digest import Line
from ioc_report.knowledge import family_profile, other_list_background, service_for
from ioc_report.live import horizon_for
from ioc_report.rules import NEW_NAME_DAYS, REVIEW
from ioc_report.summary import CaseResult

SYSTEM_ORDER = ("device", "endpoint", "triage stream", "web gateway", "resolver", "mail", "run")
SYSTEM_LABEL = {
    "device": "Device lease",
    "endpoint": "Endpoint record",
    "triage stream": "Triage stream",
    "web gateway": "Web gateway or proxy",
    "resolver": "Resolver logs",
    "mail": "Mail gateway",
    "run": "This report's next run",
}
# What each system can settle, in general; each case card carries the exact window.
SYSTEM_ACTION = {
    "device": "Identify the device that held each address in its match window, from DHCP, "
    "network access control or VPN logs: an address is not a device.",
    "endpoint": "Check the endpoint record around each match for the process behind the contact "
    "and anything it fetched or started.",
    "triage stream": "Read the stream's episode on the flagged destination beside the match.",
    "web gateway": "Pull the web gateway or proxy logs for the flagged domain: the full URL, the "
    "user agent and any file served.",
    "resolver": "Pull the resolver logs for the device's queries for the flagged domain.",
    "mail": "Look for mail linking to the flagged domain in the 24 hours before the visit.",
}
CAVEAT_ACTION = {
    "stream": "Keep the triage publisher running daily, so every match day is published (K3).",
    "retained": "Keep the triage publisher running daily, so every match day is retained (K4).",
    "e3-name": "Run with NAME_LOOKUP=rdap, so each name E3 rests on has a registration date.",
}
CAVEAT_WOULD_CHANGE = {
    "stream": "the match day published, so the stream check can run",
    "retained": "the match day retained, so the 5-minute schedule check can run",
    "e3-name": "the registration date of the name E3 rests on",
}


def _caveat_action(code: str, result: CaseResult) -> str:
    if code != "live":
        return CAVEAT_ACTION[code]
    retention = result.evidence.live_retention_days
    if retention is None:
        return "Run the report with the live source, so it re-checks every contact."
    return (
        f"Run each feed within {horizon_for(retention)} days of arrival, so the live source "
        "re-checks every contact."
    )


def _caveat_would_change(code: str, result: CaseResult) -> str:
    if code != "live":
        return CAVEAT_WOULD_CHANGE[code]
    retention = result.evidence.live_retention_days
    if retention is None:
        return "a re-query of the match day from the live source"
    return f"a re-query of the match day inside the source's {horizon_for(retention)}-day window"


KEEP_WOULD_CHANGE = {
    "K1": "the endpoint and web-gateway records of what the visit fetched or started",
    "K2": "the process that used the tunnel and what it reached",
    "K3": "the stream episode read beside the match",
    "K4": "the process behind the scheduled contact",
    "K5": "what the transfer was, from proxy or endpoint file records",
    "unexplained": "an ordinary reason for the contacts no rule explains",
}


@dataclass(frozen=True, slots=True)
class FamilyNote:
    name: str
    source: str
    malware: str
    threat_types: tuple[str, ...]
    numbers: tuple[int, ...]
    background: str
    sources: tuple[str, ...]


def families(results: Sequence[CaseResult]) -> list[FamilyNote]:
    """Each listed family in the feed once, with its cited background when there is one."""
    found: dict[str, list[tuple[int, CaseResult]]] = defaultdict(list)
    for number, result in enumerate(results, 1):
        found[result.evidence.case.listing.malware].append((number, result))
    notes = []
    for malware, members in sorted(found.items(), key=lambda item: -len(item[1])):
        source = members[0][1].evidence.case.listing.source
        profile = family_profile(malware) or other_list_background(source, malware)
        notes.append(
            FamilyNote(
                name=profile.name if profile is not None else malware,
                source=source,
                malware=malware,
                threat_types=tuple(
                    sorted({result.evidence.case.listing.threat_type for _, result in members})
                ),
                numbers=tuple(number for number, _ in members),
                background=(
                    profile.background
                    if profile is not None
                    else "No cited profile describes this family, so no rule draws on it."
                ),
                sources=profile.sources if profile is not None else (),
            )
        )
    return notes


@dataclass(frozen=True, slots=True)
class Action:
    system: str
    label: str
    text: str
    numbers: tuple[int, ...]


def actions(results: Sequence[CaseResult]) -> list[Action]:
    """What to do, by the system that can settle it, with the cases each covers. Review cases
    bring their lookups; explained cases bring what would make their explanation firm."""
    systems: dict[str, set[int]] = defaultdict(set)
    for number, result in enumerate(results, 1):
        if result.disposition == REVIEW:
            for step in next_step_items(result.evidence, result.decision):
                systems[step.system].add(number)
    found = [
        Action(system, SYSTEM_LABEL.get(system, system), SYSTEM_ACTION[system], _sorted(numbers))
        for system in SYSTEM_ORDER
        if (numbers := systems.get(system)) and system in SYSTEM_ACTION
    ]
    caveated: dict[str, set[int]] = defaultdict(set)
    for number, result in enumerate(results, 1):
        if result.disposition != REVIEW:
            for caveat in result.caveats:
                caveated[_caveat_action(caveat.code, result)].add(number)
    found += [
        Action("run", SYSTEM_LABEL["run"], text, _sorted(numbers))
        for text, numbers in caveated.items()
    ]
    return found


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    scope: str
    positive: str
    result: str


def checks(results: Sequence[CaseResult]) -> list[Check]:
    """php2shell's Table 2: each check, what it covered, what a positive would have looked like,
    and what it found. Counted from the decisions and their caveats."""
    total = len(results)

    def kept(rule: str) -> list[int]:
        return [n for n, r in enumerate(results, 1) if rule in r.decision.keeping_rules]

    def covered(code: str) -> int:
        return sum(1 for r in results if code not in {c.code for c in r.caveats})

    domains = sum(1 for r in results if r.evidence.case.is_domain)
    payload = sum(1 for r in results if r.evidence.case.listing.threat_type == "payload_delivery")
    # Kinds of contact per case, each once: not a hidden feed copy, nor one per live day.
    e3_alone = sum(
        len(
            {
                judged.item.label
                for index, judged in enumerate(r.decision.contacts)
                if judged.rules == ("E3",)
                and isinstance(judged.item, Contact)
                and not r.evidence.hidden_contact(index)
            }
        )
        for r in results
    )
    tunnels = sum(
        1
        for r in results
        if any(
            service_for(name)
            for name in (
                r.evidence.case.indicator,
                *(n for c in r.evidence.contacts for n in c.names),
            )
        )
    )
    e3_unknown = sum(1 for r in results for c in r.caveats if c.code == "e3-name")
    return [
        Check(
            "Named the flagged domain",
            f"{domains} case(s) on a domain indicator",
            "a contact whose TLS or DNS name is under the flagged domain",
            _found(kept("K1")),
        ),
        Check(
            "A tunnel reached as a visitor",
            f"{tunnels} case(s) with a name of a cited tunnelling service",
            "a tunnelling service reached on a port other than its client port",
            _found(kept("K2")),
        ),
        Check(
            "A stream episode on the flagged destination",
            f"{covered('stream')} of {total} case(s) with every match day published",
            "a relationship or persistence episode on the flagged domain or address",
            _found(kept("K3")),
        ),
        Check(
            "A scheduled low-volume contact",
            f"minute grain on {covered('live')} of {total} case(s) re-queried; 5-minute grain on "
            f"{covered('retained')} with every match day retained",
            "regular contact over 6 h or more at low volume (CASE_STUDY §10, §13)",
            _found(kept("K4")),
        ),
        Check(
            "A transfer from a payload server",
            f"{payload} payload-delivery case(s)",
            "a long flow of 1 MB or more not on an established shared site",
            _found(kept("K5")),
        ),
        Check(
            "A newly registered TLS name",
            f"{e3_alone} kind(s) of contact explained by the TLS-name rule alone",
            f"a name registered under {NEW_NAME_DAYS} days before the match (RDAP)",
            f"{e3_alone} checked; the age of the names in {e3_unknown} case(s) is unknown",
        ),
    ]


def would_change(result: CaseResult) -> str:
    """What would move the reading: for a review case, what settles each reason it was kept; for
    an explained case, what it could not check."""
    if result.disposition == REVIEW:
        rules = result.decision.keeping_rules or ("unexplained",)
        return "; ".join(KEEP_WOULD_CHANGE.get(rule, rule) for rule in rules)
    found = [_caveat_would_change(c.code, result) for c in result.caveats]
    return "; ".join(dict.fromkeys(found)) or (
        "new contact with the flagged address that no rule explains"
    )


def model_verdict(result: CaseResult) -> str:
    """The blind verdict in a few words, for badges and tables."""
    shadow = result.shadow
    if shadow is None:
        return "not asked"
    votes = sum(1 for sample in shadow.samples if sample.verdict == shadow.majority)
    asked = len(shadow.samples) + len(shadow.errors)
    if shadow.majority is None:
        return f"split ({asked} samples)"
    agrees = "agrees" if shadow.agrees(result.disposition) else "disagrees"
    return f"{shadow.majority}, {votes} of {asked}: {agrees}"


def reasons(result: CaseResult) -> list[Line]:
    """Why code decided: the digest's grouped decision lines after the first."""
    if result.digest is None:
        return []
    return [line for line in result.digest.decision[1:] if line.source != "Coverage"]


def _sorted(numbers: set[int]) -> tuple[int, ...]:
    return tuple(sorted(numbers))


def _found(numbers: list[int]) -> str:
    if not numbers:
        return "none"
    return f"{len(numbers)} case(s): " + ", ".join(f"#{n}" for n in numbers)
