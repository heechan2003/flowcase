"""One short PDF per case, for a reader who knows nothing of how the team works: the academic lead,
who marks only what is submitted. It says what the threat is, what the host did, why the case stays
open or has an ordinary reason, and what to do next, and never how any of that was reached.

It reads the JSON a run wrote, so a PDF cannot disagree with its report, costs no source query and
still works once the source's minute window has passed. The decision is the one in that file. The
writer reads a brief cut down from the case's saved digest, with the blind verdict, the source tags,
the rule codes and the thresholds gone, and the host's address replaced before anything leaves the
machine. Code checks every reply and writes the title, the facts line, the headings, the sources and
the limits. When a reply fails, the brief's own sentences stand in, and the caller says so.

PDFs carry internal addresses and domains, as the hunt write-ups do. They go to a git-ignored
directory and are never committed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import typst

from ioc_report.casefile import observed_from_case_file
from ioc_report.knowledge import (
    SHARED_NETWORKS,
    THREATFOX,
    family_background,
    is_unnamed_family,
    service_for,
)
from ioc_report.model import ModelClient
from ioc_report.narrative import NOT_WRITTEN, REPORT_FIELDS, Narrative, Progress, Writer, restore
from ioc_report.openrouter import OpenRouterClient
from ioc_report.rules import REVIEW
from ioc_report.text import HOST_TOKEN, without_addresses

CaseData = Mapping[str, Any]

LIMITS = (
    "Network flow records carry no payload, URL, process or user, so they cannot show what ran on "
    "a host, and an address can move between devices. Times are UTC."
)
THREAT_TYPES = {
    "botnet_cc": "botnet command and control",
    "payload_delivery": "payload delivery",
    "exploit_source": "exploit source",
}
SOURCE_LABELS = {
    "malpedia.caad.fkie.fraunhofer.de": "Malpedia",
    "unit42.paloaltonetworks.com": "Unit 42",
    "censys.com": "Censys",
    "blog.qualys.com": "Qualys",
    "threatdown.com": "ThreatDown",
    "isc.sans.edu": "SANS ISC",
    "github.com": "GitHub",
    "aws.amazon.com": "Amazon",
    "php.net": "PHP",
    "developers.cloudflare.com": "Cloudflare",
    "blog.remirepo.net": "Remi",
    "developer.wordpress.org": "WordPress",
}
EXPLAINED_NEXT = (
    "This reading would change only with new contact with the listed address that has no ordinary "
    "reason, or with what the lines under Not checked could not settle."
)

_DIGEST_LINE = re.compile(r"^- \[([^\]]*)\] (.*)$")
_SERVICES = re.compile(r"on (\S+) it used (\d+) distinct services? \(the campus median was (\d+)")
_NEW_NAMED = re.compile(r"(\d+ new named destination\(s\))")
_IN_NETWORK = re.compile(r"the flagged address (\S+) is in AS(\d+)", re.IGNORECASE)
# The second form is what a run writes now; the first is what older saved runs hold.
_NOT_SHOWN_SHARED = re.compile(
    r"^(\S+) carried at most \d+ registered domain\(s\)"
    r"(?:: not shown to be|, and is on \S+ network)"
)
_NO_PROFILE = re.compile(
    r"we hold no description of how (?:\S+ communicates, so its protocol cannot explain this|"
    r"it communicates)"
)
# Output bound: the page holds about one paragraph on this.
OTHER_MATCHES = 3
_KEPT_BY = re.compile(r"[EK]\d \(([^)]*)\)")

# The digest's words for how the team works, in the words the brief uses. Applied in order, to every
# line that survives, so the writer does not have to translate them and code's own text can stand.
_WORDING: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), plain)
    for pattern, plain in (
        (r"^[EK]\d explains (\d+) item\(s\)", r"An ordinary reason covers \1 item(s)"),
        (r"^[EK]\d on (\d+) items; the first: ", r"\1 items; the first: "),
        (r"^[EK]\d: ", ""),
        (
            r"established \(\d+\+ addresses on \d+\+ days(?:, CASE_STUDY §\d+)?\): (yes|no)",
            r"in routine campus use: \1",
        ),
        (r"\s*\(CASE_STUDY §\d+(?:, §\d+)*\)", ""),
        (r",?\s*CASE_STUDY §\d+(?:, §\d+)*", ""),
        (r"; an established site needs \d+ on \d+", ""),
        (r"; shared hosting needs \d+", ""),
        (r" \(\d+\+ would be\)", ""),
        (r", CV \d+\.\d+", ""),
        (r", \d+ campus row\(s\)", ""),
        (r"retained 5-minute activity", "5-minute activity"),
        (r"nothing about this address is retained", "we hold no campus history for this address"),
        (r"No day before the first match is retained", "We hold no day before the first match"),
        (r"no retained day before the match", "no campus history before the match"),
        (r"retained day\(s\)", "day(s) of campus history"),
        (r"retained days", "days of campus history"),
        (r"retained history", "campus history"),
        (
            r"a stream episode on the flagged destination",
            "our behaviour monitoring also flagged it",
        ),
        (
            r"the published triage stream has an? \S+ \S+ episode on (.+?) itself on (\S+?)\.",
            r"our campus behaviour monitoring separately flagged the host's contact with \1 on \2.",
        ),
        (
            r"(\S+) has no cited C2 profile, so protocol cannot explain it",
            r"we hold no description of how \1 communicates, so its protocol cannot explain this",
        ),
        (r"the family has no cited C2 profile", "we hold no description of how it communicates"),
        (r"a name the campus had not established", "a name not in routine campus use"),
        (r"new to it or unestablished on campus", "new to it or not in routine campus use"),
        (r"not established on campus", "not in routine campus use"),
        (r"as an established site", "as a site in routine campus use"),
        (r"an established site", "a site in routine campus use"),
        (
            r"campus addresses with a service row had a median of (\d+) and a 90th percentile of "
            r"(\d+)",
            r"the campus median was \1 and the 90th percentile \2",
        ),
        (r"the re-queried day\(s\)", "the later day(s) we read"),
        (r"^Read (\S+) to (\S+) \(", r"From \1 to \2 ("),
        (r"in this feed", "in this batch of matches"),
        (r"the rules can name", "we can name"),
        (r"no rule applies", "nothing explains it"),
        (r"no rule explains", "nothing explains"),
        (r"no family rule applies", "the family can explain nothing"),
        (r" \(\d{4}-\d{2}-\d{2} \d{2}:\d{2} [A-Z][A-Za-z ]*\)", ""),
        (r"\bSNI\b", "TLS name"),
        (r"\bbotnet_cc\b", "botnet command and control"),
        (r"\bpayload_delivery\b", "payload delivery"),
        (r"\bexploit_source\b", "exploit source"),
        (r"(\d+) kinds of contact", r"\1 address, port and name combinations"),
        (r"(\d+) kind\(s\) of contact", r"\1 address, port and name combination(s)"),
        (r"the kinds of contact:", "the address, port and name combinations:"),
        (r"Not explained: ", "No ordinary reason found: "),
        (r"The first in full: ", "In detail: "),
        (r"compromised legitimate sites", "hijacked legitimate sites"),
        (r"the compromised site itself", "the hijacked site itself"),
    )
)
# What could not be checked, in the brief's words. A saved report holds the sentences, not their
# parts, so each is matched whole.
_COVERAGE: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), plain)
    for pattern, plain in (
        (
            r"^the live source (?:.*?): the contacts are the feed's own minutes",
            "the contacts could not be re-read from the full traffic records; they rest on the "
            "original match alone",
        ),
        (
            r"^minute detail for (.+?) had expired: the contacts on those days are the feed's own "
            r"minutes",
            r"per-minute records for \1 had aged out, so the contacts on those days rest on the "
            r"original match alone",
        ),
        (
            r"^no published triage stream for (.+?): K3 could not be checked",
            r"our behaviour monitoring did not cover \1",
        ),
        (
            r"^(.+?) not retained: the 5-minute schedule check \(K4\) could not run",
            r"we hold no campus history for \1, so we could not check for a schedule",
        ),
        (
            r"^E3 alone explains (.+?): (\S+): (?:its registration date was not looked up.*?|"
            r"it was registered again after the match, so its age then is unknown|"
            r"its registration date is unknown(?:: [^;]*)?)(;.*?)?\.?$",
            r"the age of \2 is unknown, and the ordinary reason for \1 rests on it\3.",
        ),
    )
)
# The brief's markers for the writer, which code's own text does not print.
_MARKERS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), plain)
    for pattern, plain in (
        (r"^Background not evidence: ", ""),
        (r"^(.+?), about the indicator only: ", r"In \1, "),
        (r"^Outcome: (?:review|explained)\. ", ""),
    )
)
# Next steps that name our own tools, or that the lead cannot act on.
_INTERNAL_STEP = re.compile(r"triage stream", re.IGNORECASE)
_STEP_WORDING: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), plain)
    for pattern, plain in (
        (r"\s*To judge whether the address still holds that device:.*?\(see \[[^\]]*\]\)\.", ""),
        (r"^(Identify the process behind .*? at \S+ \S+ UTC(?: \([^)]*\))?): .*$", r"\1."),
        (r"\s*listed under K\d", ""),
        (r"contacts and flows nothing explains", "contacts and flows we could not explain"),
    )
)


class CaseReportError(ValueError):
    """The report file or the case asked for cannot make a case report."""


@dataclass(frozen=True, slots=True)
class Brief:
    """What the writer reads, by what the lead will read it for."""

    threat: tuple[str, ...]
    host: tuple[str, ...]
    happened: tuple[str, ...]
    outcome: tuple[str, ...]
    next_steps: tuple[str, ...]

    def text(self) -> str:
        parts = (
            ("Threat", self.threat),
            ("Host", self.host),
            ("What happened", self.happened),
            ("Outcome", self.outcome),
            ("Next steps", self.next_steps),
        )
        return "\n".join(
            f"{title}:\n" + "\n".join(f"- {line}" for line in lines)
            for title, lines in parts
            if lines
        )


@dataclass(frozen=True, slots=True)
class Written:
    number: int
    disposition: str
    pdf: Path
    audit: Path
    narrative: Narrative
    words: int
    family_described: bool
    """False when no cited description exists, so the Threat paragraph rests on the listing."""


def load_report(path: Path) -> dict[str, Any]:
    """The JSON file an `ioc-report` run wrote."""
    try:
        found = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CaseReportError(
            f"cannot read {path} as a report: give the .json file a run wrote"
        ) from exc
    if not isinstance(found, dict) or not isinstance(found.get("cases"), list):
        raise CaseReportError(f"{path} is not a report: give the .json file a run wrote")
    return found


def select_cases(report: Mapping[str, Any], numbers: Sequence[int] | None) -> list[CaseData]:
    """Every review case, or the cases asked for by their report number, whatever their outcome."""
    cases: list[CaseData] = report["cases"]
    if any("number" not in case for case in cases):
        raise CaseReportError(
            "this report predates case numbers and digests, so run ioc-report on its feed again"
        )
    if not numbers:
        chosen = [case for case in cases if case["disposition"] == REVIEW]
    else:
        by_number = {case["number"]: case for case in cases}
        missing = [number for number in numbers if number not in by_number]
        if missing:
            raise CaseReportError(
                f"no case {', '.join(map(str, missing))} in this report: it holds cases 1 to "
                f"{len(cases)}"
            )
        chosen = [by_number[number] for number in dict.fromkeys(numbers)]
    if without := [case["number"] for case in chosen if not case.get("digest")]:
        raise CaseReportError(
            f"case {', '.join(map(str, without))} has no digest: this report predates them, so run "
            "ioc-report on its feed again"
        )
    return chosen


# --- the brief ------------------------------------------------------------------------------------


def brief(case: CaseData, others: Sequence[CaseData] = ()) -> Brief:
    """The case's digest with the blind verdict, the source tags, the rule codes and the thresholds
    gone, plus its next steps. `others` are the run's cases, for what else this address matched.
    Nothing here adds a fact: every line comes from the saved run or `knowledge.py`."""
    sections = _sections(case["digest"])
    networks = _flagged_networks(sections.get("Threat", ()))
    host = tuple(_plain(text) for source, text in sections.get("Host", ()) if _keep(source))
    return Brief(
        threat=tuple(_threat(case, sections.get("Threat", ()))),
        host=host,
        happened=(
            *_other_matches(case, others),
            *(
                _weighed(_shared_by_design(_plain(text), networks), host)
                for _source, text in sections.get("What happened", ())
                if not text.startswith("Named destinations shared by")
            ),
        ),
        outcome=tuple(
            _known_channel(_outcome(line), _claim(case)["malware"])
            for line in sections.get("Decision", ())
        ),
        next_steps=tuple(_next_steps(case)),
    )


def _sections(digest: str) -> dict[str, list[tuple[str, str]]]:
    found: dict[str, list[tuple[str, str]]] = {}
    current: list[tuple[str, str]] = []
    for line in digest.splitlines():
        if (match := _DIGEST_LINE.match(line)) is not None:
            current.append((match.group(1), match.group(2)))
        elif line.endswith(":") and not line.startswith("- "):
            current = found.setdefault(line[:-1], [])
    return found


def _weighed(text: str, host: Sequence[str]) -> str:
    """A count of new destinations beside what weighs it, since a busy address reaches many."""
    for line in host:
        if (found := _SERVICES.search(line)) is not None:
            day, used, median = found.groups()
            return _NEW_NAMED.sub(
                rf"\1 (this address used {used} distinct services on {day}, against a campus "
                f"median of {median})",
                text,
            )
    return text


def _flagged_networks(lines: Sequence[tuple[str, str]]) -> dict[str, int]:
    return {
        match.group(1): int(match.group(2))
        for _source, text in lines
        if (match := _IN_NETWORK.search(text)) is not None
    }


def _shared_by_design(text: str, networks: Mapping[str, int]) -> str:
    """How few names we saw on an address says nothing where the network shares it by design."""
    match = _NOT_SHOWN_SHARED.match(text)
    network = SHARED_NETWORKS.get(networks.get(match.group(1), 0)) if match else None
    if match is None or network is None:
        return text
    return (
        f"{match.group(1)} is on {network.name}'s network, whose proxied sites all share its "
        "addresses, so the address alone does not tie traffic to one site; only a TLS name on the "
        "contact does."
    )


def _known_channel(text: str, malware: str) -> str:
    """The rules hold no profile for a family described for the reports alone, but we do."""
    known = family_background(malware)
    return text if known is None or known.channel is None else _NO_PROFILE.sub(known.channel, text)


def _other_matches(case: CaseData, others: Sequence[CaseData]) -> list[str]:
    """What else this campus address matched in the run, nearest first."""
    found = sorted(
        (o for o in others if o["host"] == case["host"] and o["number"] != case["number"]),
        key=lambda other: abs(_days_apart(case, other) or 0),
    )
    lines = [_other_match(other, _days_apart(case, other)) for other in found[:OTHER_MATCHES]]
    if len(found) > OTHER_MATCHES:
        lines.append(f"It matched {len(found) - OTHER_MATCHES} more listed indicator(s) as well.")
    return lines


def _days_apart(case: CaseData, other: CaseData) -> int | None:
    """None where a saved case holds no matched minute."""
    if not case.get("matched_first") or not other.get("matched_first"):
        return None
    first, then = (datetime.fromisoformat(c["matched_first"]).date() for c in (case, other))
    return (then - first).days


def _other_match(other: CaseData, days: int | None) -> str:
    malware = _claim(other)["malware"]
    known = family_background(malware)
    if is_unnamed_family(malware):
        listed = f"for which {_source(other)} names no family"
    else:
        listed = f"listed by {_source(other)} as {known.name if known else malware}"
    if days is None:
        when = ""
    elif days == 0:
        when = f", first on {other['matched_first'][:10]}, the same day as this match"
    else:
        apart = f"{abs(days)} day(s) {'before' if days < 0 else 'after'} this match"
        when = f", first on {other['matched_first'][:10]}, {apart}"
    outcome = (
        "we kept that match for review"
        if other["disposition"] == REVIEW
        else "we found an ordinary reason for that match"
    )
    return (
        f"The same campus address also matched another indicator: {other['indicator']}, {listed}"
        f"{when}; {outcome}. An address is not a device, so this may be a different device."
    )


def _keep(source: str) -> bool:
    """The whole host's stream counts describe our monitoring, not the case."""
    return not source.startswith("Published triage stream")


def _plain(text: str, wording: Sequence[tuple[re.Pattern[str], str]] = _WORDING) -> str:
    for pattern, plain in wording:
        text = pattern.sub(plain, text)
    return text


def _claim(case: CaseData) -> Mapping[str, Any]:
    """What the list says. A report written before other lists were accepted calls it `threatfox`
    and names no source."""
    found: Mapping[str, Any] = case.get("listing") or case["threatfox"]
    return found


def _source(case: CaseData) -> str:
    return str(_claim(case).get("source") or THREATFOX.source)


def _threat(case: CaseData, lines: Sequence[tuple[str, str]]) -> list[str]:
    malware = _claim(case)["malware"]
    found = []
    for source, text in lines:
        if source.startswith("Knowledge"):
            found.append(_family_line(malware, _source(case)))
        elif source.endswith("about the indicator only"):
            found.append(f"{source}: {_plain(text)}")
        else:
            found.append(_plain(text))
    return found


def _family_line(malware: str, source: str) -> str:
    if (known := family_background(malware)) is not None:
        return f"Background not evidence: {known.name}: {_plain(known.background)}"
    if is_unnamed_family(malware):
        return f"{source} names no family for this indicator: {malware} is a generic label."
    return f"We hold no description of {malware}."


def _outcome(line: tuple[str, str]) -> str:
    source, text = line
    if source == "Coverage":
        return f"Not checked: {_plain(_plain(text, _COVERAGE))}"
    if text.startswith("review: kept by "):
        reasons = "; ".join(_plain(reason) for reason in _KEPT_BY.findall(text))
        return f"Outcome: review. We kept this case for review because: {reasons}."
    if text.startswith("review: "):
        return (
            "Outcome: review. We kept this case for review: not every contact has an ordinary "
            "reason."
        )
    if text.startswith("explained: "):
        return f"Outcome: explained. {_sentence(_plain(text.removeprefix('explained: ')))}"
    return _plain(text)


def _next_steps(case: CaseData) -> list[str]:
    if case["disposition"] != REVIEW:
        return [EXPLAINED_NEXT]
    steps = [
        _plain(_plain(step, _WORDING), _STEP_WORDING)
        for step in case.get("next_steps") or ()
        if not _INTERNAL_STEP.search(step)
    ]
    known = family_background(_claim(case)["malware"])
    if known is not None and known.check not in steps:
        steps.append(known.check)
    return steps


def code_text(found: Brief) -> dict[str, str]:
    """The brief's own sentences, by paragraph: what stands when no reply passes the checks."""

    def joined(lines: Sequence[str]) -> str:
        return " ".join(_sentence(_plain(line, _MARKERS)) for line in lines)

    return {
        "summary": joined((*found.happened[:1], *found.outcome[:1])),
        "threat": joined(found.threat),
        "host": joined(found.host[:2]),
        "contact": joined(found.happened),
        "why": joined(found.outcome),
        "after": "",
        "conclusion": joined(found.next_steps),
    }


def _sentence(line: str) -> str:
    line = line.strip()
    return line[:1].upper() + line[1:] if line else line


# --- the page -------------------------------------------------------------------------------------


def _facts(report: Mapping[str, Any], case: CaseData) -> str:
    claim = _claim(case)
    known = family_background(claim["malware"])
    family = (
        known.name
        if known is not None
        else "an unnamed family"
        if is_unnamed_family(claim["malware"])
        else claim["malware"]
    )
    kind = THREAT_TYPES.get(claim["threat_type"], str(claim["threat_type"]).replace("_", " "))
    status = "open for review" if case["disposition"] == REVIEW else "explained"
    parts = [f"{_source(case)} lists {case['indicator']} as {family} ({kind})."]
    if (first := _first_contact(case)) is not None:
        parts.append(f"First contact {_day(first)}, {first:%H:%M} UTC.")
    parts.append(f"Status: {status}.")
    if report.get("generated_at"):
        parts.append(f"Data to {_day(datetime.fromisoformat(report['generated_at']))}.")
    return " ".join(parts)


def _first_contact(case: CaseData) -> datetime | None:
    times = [
        datetime.fromisoformat(item["first"])
        for item in case.get("contacts") or ()
        if item.get("first")
    ]
    return min(times, default=None)


def _day(value: datetime) -> str:
    return f"{value.day} {value:%b %Y}"


def _sources(case: CaseData) -> list[dict[str, str]]:
    urls: list[str] = []
    if (known := family_background(_claim(case)["malware"])) is not None:
        urls += known.sources
    if (
        case.get("indicator_type") == "domain"
        and (service := service_for(case["indicator"])) is not None
    ):
        urls += service.sources
    return [{"label": _source_label(url), "url": url} for url in dict.fromkeys(urls)]


def _source_label(url: str) -> str:
    host = (urlparse(url).hostname or url).removeprefix("www.")
    return SOURCE_LABELS.get(host, host)


def page_data(
    report: Mapping[str, Any], case: CaseData, fields: Mapping[str, str]
) -> dict[str, Any]:
    """What the template draws. The paragraphs come from `fields`; everything else is code's."""
    return {
        "title": f"Case Report: {case['host']} and {case['indicator']}",
        "facts": _facts(report, case),
        "why_heading": (
            "Why this case stays open"
            if case["disposition"] == REVIEW
            else "Why the contact has an ordinary reason"
        ),
        "sources": _sources(case),
        "limits": LIMITS,
        **{name: fields.get(name, "") for name in REPORT_FIELDS},
    }


def render_pdf(page: Mapping[str, Any], template_name: str = "case_report.typ") -> bytes:
    template = files("ioc_report").joinpath(template_name).read_bytes()
    try:
        found = typst.compile(
            template,
            format="pdf",
            sys_inputs={"report": json.dumps(page)},
            ignore_system_fonts=True,
        )
    except typst.TypstError as exc:
        raise CaseReportError(f"the PDF could not be laid out: {exc.message}") from exc
    if not isinstance(found, bytes):
        raise CaseReportError("the PDF could not be laid out: no single document came back")
    return found


# --- writing --------------------------------------------------------------------------------------


_UNSAFE_IN_FILE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_UNSAFE_IN_THREAT_LABEL = re.compile(r"[^A-Za-z0-9 ._-]+")
_IN_BRACKETS = re.compile(r"\s*\([^)]*\)")
# A file name stops at 255 bytes. These leave room for the host, the extension and the separators.
_LONGEST_THREAT_LABEL = 40
_LONGEST_THREAT_DETAIL = 120
_LONGEST_RUN_NAME = 40
_UNNAMED_KINDS = {"": "family", "rat": "RAT"}


def file_stem(report: Mapping[str, Any], case: CaseData) -> str:
    """A review case is named for what it is about: `Threat (host, domain or address)`, so a folder
    sorts by threat. Any other case keeps its run and number. A port is left out unless the same
    host matched the same address on another port in this run, which would give both one name."""
    if case["disposition"] != REVIEW:
        return f"{report['name']}_case_{case['number']}"
    detail = _listed_name(case)
    if any(
        other["number"] != case["number"]
        and other["disposition"] == REVIEW
        and other["host"] == case["host"]
        and _listed_name(other) == detail
        for other in report["cases"]
    ):
        detail = case["indicator"]
    host = _for_file_name(case["host"])
    return f"{_threat_label(case)} ({host}, {_for_file_name(detail)[:_LONGEST_THREAT_DETAIL]})"


def _threat_label(case: CaseData) -> str:
    """The family as the report names it, shorter: a folder lists these side by side."""
    malware = str(_claim(case)["malware"])
    known = family_background(malware)
    if known is not None:
        label = _IN_BRACKETS.sub("", known.name)
    elif is_unnamed_family(malware):
        kind = malware.strip().lower().removeprefix("unknown").strip("_").replace("_", " ")
        label = f"Unnamed {_UNNAMED_KINDS.get(kind, kind)}"
    else:
        label = malware
    safe = _UNSAFE_IN_THREAT_LABEL.sub("-", label).strip(". -")[:_LONGEST_THREAT_LABEL]
    return safe.strip(". -") or "Unnamed family"


def _listed_name(case: CaseData) -> str:
    indicator = str(case["indicator"])
    return indicator.rsplit(":", 1)[0] if case.get("indicator_type") == "ip:port" else indicator


def _for_file_name(value: str) -> str:
    """A feed's value decides this name, so nothing in it may leave the folder or hide the file."""
    return _UNSAFE_IN_FILE_NAME.sub("-", value).strip(".-") or "unknown"


def _own_stem(stem: str, report: Mapping[str, Any], out_dir: Path) -> str:
    """Runs often share a folder, and one host can match one indicator in several of them. A run
    overwrites its own report, but never another run's: it adds its name to the file name."""
    audit = out_dir / f"{stem}.json"
    if not audit.is_file():
        return stem
    try:
        owner = json.loads(audit.read_text(encoding="utf-8")).get("report")
    except ValueError:
        owner = None
    if owner == report["name"]:
        return stem
    return f"{stem} {_for_file_name(str(report['name']))[:_LONGEST_RUN_NAME]}"


def write_case_report(
    report: Mapping[str, Any], case: CaseData, out_dir: Path, writer: Writer | None
) -> Written:
    """One PDF and its audit file. With no writer, or a reply that fails, code's text stands."""
    number = case["number"]
    found = brief(case, report["cases"])
    sent = without_addresses(found.text(), {case["host"], case.get("source_host") or case["host"]})
    narrative = NOT_WRITTEN
    if writer is not None:
        reply = writer.report(
            sent,
            observed_from_case_file(case.get("case_file") or ""),
            case["disposition"],
            f"case {number}",
            source=_source(case),
            inbound=bool(_claim(case).get("inbound")),
        )
        narrative = restore(reply, {HOST_TOKEN: case["host"]})
    fields = dict(narrative.fields) or code_text(found)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = _own_stem(file_stem(report, case), report, out_dir)
    pdf = out_dir / f"{stem}.pdf"
    audit = out_dir / f"{stem}.json"
    pdf.write_bytes(render_pdf(page_data(report, case, fields)))
    words = sum(len(text.split()) for text in fields.values())
    audit.write_text(
        json.dumps(
            {
                "report": report["name"],
                "case": number,
                "disposition": case["disposition"],
                "indicator": case["indicator"],
                "host": case["host"],
                "written_by": narrative.written_by,
                "attempts": narrative.attempts,
                "cached": narrative.cached,
                "notes": list(narrative.notes),
                "problems": list(narrative.problems),
                "prompt_version": narrative.prompt_version,
                "words": words,
                "what_the_writer_read": sent,
                "paragraphs": fields,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    malware = _claim(case)["malware"]
    return Written(
        number,
        case["disposition"],
        pdf,
        audit,
        narrative,
        words,
        family_background(malware) is not None or is_unnamed_family(malware),
    )


# A report weighs nothing: the decision is already made. At `medium`, a long case spent the whole
# reply allowance on reasoning and returned no text.
REPORT_EFFORT = "low"


def write_case_reports(
    report: Mapping[str, Any],
    cases: Sequence[CaseData],
    out_dir: Path,
    client: ModelClient | None,
    progress: Progress | None = None,
) -> list[Written]:
    """Replies are cached by their exact request beside the run's own, so re-rendering is free.

    Case reports run last, so a client the run shared with the second opinion has finished its
    evaluated work at its own effort by now."""
    if isinstance(client, OpenRouterClient):
        client.config = replace(client.config, effort=REPORT_EFFORT)
    writer = Writer(client, out_dir / ".model-cache", progress) if client is not None else None
    return [write_case_report(report, case, out_dir, writer) for case in cases]
