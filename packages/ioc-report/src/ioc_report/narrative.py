"""The prose of the report: each case's overview, a paragraph per group of like cases, and the
feed's executive summary. Written by the local model from code-built digests, checked by code,
and replaced by code-written text whenever the model is off or its reply fails the checks.

The model reads the digest, never the raw case file, so a case with a hundred contacts fits its
window. It describes what code decided and what the blind verdict said; it never decides, and a
reply that contradicts the code's disposition is withheld like any other failed reply. Replies are
cached by the exact request, so re-rendering a run costs nothing.

A case report's paragraphs (`case_report.py`) go through the same checks and the same retries, with
two of their own: a word limit, and no word that says how the team works.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ioc_report.casefile import Observed
from ioc_report.knowledge import FAMILIES, REPORT_FAMILIES, THREATFOX
from ioc_report.model import (
    _ATTRIBUTION,
    _THREAT_LABEL,
    CONTEXT_MARGIN,
    ModelClient,
    ModelError,
    _hedged,
    confidence_as_evidence,
    host_state_words,
    unsupported_shapes,
    unverified_numbers,
)
from ioc_report.rules import EXPLAINED, REVIEW


def _rules(source: str) -> str:
    return f"""\
Rules:
1. Use only the input. Copy numbers, names and addresses exactly as written there, and never \
calculate a new number.
2. {source}'s family and threat type describe the indicator, not the host: write \
"{source} lists ... as ...". Use the words malware, malicious, botnet, command-and-control or C2 \
only in a sentence that names {source}. Lines marked "background not evidence" describe the \
family in general, never this host. Do not mention {source}'s confidence.
3. Never say or suggest that a host is compromised, infected, benign, safe, part of a botnet or \
under someone's control, and never say that it is not. Flow records cannot show either. An \
address is not a device: you may say what the products it used are typical of, never what the \
host is.
4. Code has already decided every case: "review" means a person should look, "explained" means \
every contact has an ordinary reason the rules name. Never change or argue against that decision. \
A blind model verdict that disagrees is a reason for a second look, nothing more.
5. Say what the rules mean in plain words; do not write rule codes such as K1 or E3. Call a \
family by its name (for example NanoCore), never "the malware" or "the botnet".
6. Expired, unpublished or unqueried data is missing data, not absence of activity.
7. Describe a held-open connection or a regular schedule only where the input says one was \
observed.
8. Never call a contact, a host or its traffic suspicious, normal or unusual: say what code \
found and what the input compares it with."""


def case_prompt(source: str = THREATFOX.source) -> str:
    return f"""\
You help a network security analyst on a university campus network read one {source} IOC match: \
flow records show contact between an internal host and an address or domain {source} lists. The \
input is a digest of the case written by code, under the headings Threat, Host, What happened, \
Decision and Model verdict, one sourced fact per line. Write the case's overview for the analyst.

{_rules(source)}

Reply as JSON with four fields, each one sentence of at most 35 words:
- "threat": what {source} says the indicator is and what that family does, or that no profile \
describes it;
- "host": what the address did across its retained days and which products with a known purpose \
it used;
- "what_happened": the contact with the flagged address in plain words, and anything notable just \
before or after it;
- "reading": how to read the case as a whole: why code decided as it did, whether the blind model \
agrees if one was asked, and what the flow records cannot settle.

An example of the style, for a different case:
{{"threat": "{source} lists the address as win.nanocore, a Windows remote-access trojan whose \
own channel is plain TCP without TLS.", "host": "Across its retained days the address used \
Microsoft 365, Windows Update and Chrome updates, services typical of a Windows PC.", \
"what_happened": "One minute of UDP and one TLS session behind an ECH outer name, as a browser \
sends, with a few kilobytes each way.", "reading": "Code explained both contacts: NanoCore's \
channel never uses UDP and is not a browser; flow records cannot show which program ran."}}"""


def group_prompt(source: str = THREATFOX.source) -> str:
    return f"""\
You help a network security analyst on a university campus network read a group of {source} IOC \
matches that code decided the same way for the same reasons. The input, written by code, names the \
group, what its cases share, the family's background, what each deciding rule means, and one line \
per case with its own contacts. Say only what the lines show for every case; a detail of one case \
belongs to that case. Write one paragraph for the analyst.

{_rules(source)}

Reply as JSON with one field, "analysis": at most four sentences and 90 words, saying what the \
pattern is, why code decided these cases this way, and what differs between them."""


def feed_prompt(source: str = THREATFOX.source) -> str:
    return f"""\
You help a network security analyst on a university campus network. Code has decided every \
{source} IOC match in one feed. The input, written by code, gives the totals, each group of like \
cases, and what the run could not check. Write the report's executive summary and its conclusion.

{_rules(source)}

Reply as JSON with two fields:
- "summary": at most five sentences and 120 words: what the feed held, what the matches mostly \
were, which cases need a person and why, and the most important gap in what could be checked;
- "conclusion": at most three sentences and 70 words: what to do first, and what the flow records \
cannot settle.

The page already says that no case shows whether a host is compromised: do not repeat it, and do \
not use the words compromised, infected or malicious at all."""


# Output bounds, not thresholds: the words each paragraph of a case report may run to, which keep
# the report to about one page.
REPORT_WORDS = {
    "summary": 110,
    "threat": 70,
    "host": 60,
    "contact": 90,
    "why": 80,
    "after": 70,
    "conclusion": 110,
}
# A reply a little over a limit still fits the page; well over it reads as a report that did not
# choose what matters.
REPORT_WORDS_MARGIN = 1.25
# On a list of addresses that connect in, "after" also carries what the host later fetched.
INBOUND_WORDS = {**REPORT_WORDS, "after": 100}


def report_prompt(source: str = THREATFOX.source, inbound: bool = False) -> str:
    """`inbound`: the list names addresses that connect in, so its contact reads the other way."""
    reach = "which host it was in contact with" if inbound else "which host reached it"
    direction = (
        "\n18. This list names addresses that connect in to their targets, but the records do not "
        "show who opened a contact. Never state as fact that the listed address connected in or "
        "reached the host: where the input says so, write that the contact fits the listed "
        "address connecting in, and that the TLS name would then be the host's own site. Give the "
        "total size of large later uploads and of large later downloads, not each one, and never "
        f'link later traffic to the listed address: the records cannot show that. Here "after" '
        f"may run to {INBOUND_WORDS['after']} words. The days given for later contact are the "
        "only later days we read, so say nothing of any day after them. A contact's minutes are "
        "the minutes it was seen in, not how long it lasted."
        if inbound
        else ""
    )
    return f"""\
You write a short report on one case for the academic lead of a university network-security \
project. The lead reads only this report and knows nothing about how the team works. The input, \
written by the team's own analysis, holds the facts of one {source} IOC match on a university \
campus network: a campus host exchanged traffic with an address or domain {source} lists. The \
report says what the threat is, what the host did, why the case stays open or has an ordinary \
reason, and what to do next. It is high level and straight to the point.

{_rules(source)}

For this report:
9. Write as the team ("we") and open each paragraph with its finding. Pick what matters to the \
lead and leave the rest out; a long list of names or counts is rarely needed.
10. State what we found, never how we found it. Do not mention tools, data stores, queries, rules, \
thresholds, scores, models or the layout of the input. Where rules 4 and 8 speak of code, write \
"we": "we kept this case for review", "we found".
11. Never use these words: retained, triage, stream, episode, digest, verdict, blind, threshold, \
feed, model, rule (except "rule out"), "the input", compromised, infected, malicious.
12. The campus host's address is written HOST in the input. Write HOST exactly when you name it, \
and "the host" otherwise. HOST is the address itself, so write "the device at HOST", never "HOST's \
address".
13. Write dates like 22 Oct 2026, give times in UTC only, and say "TLS name" for an SNI.
14. A line under "Not checked" limits what we can say: mention it only where it limits a finding, \
in plain words.
15. The page already lists the general limits of network records, so do not explain them in \
general: say only what they mean for this case.
16. If the "after" paragraph gives a count of new destinations, weigh it with the services count \
and campus median of the one day the input names, as two separate facts: "From <first day> to \
<last day> it reached <count> new named destinations; on <that day> alone it used <services> \
services, against a campus median of <median>." A busy address reaches many new destinations. \
Never set the count against the median alone, and never say the count fell on that one day.
17. Say what the products an address used are typical of, such as Windows PCs or Linux servers. \
Never call its use ordinary, normal or everyday.
Where the input says the same campus address also matched another indicator, write "the same \
campus address" and call the other a match, not a case. Give each size, time and span as the input \
gives it, and never call two sizes the same unless their figures are. What a family does comes \
from public sources, so never say {source} describes it. Where the input says whether campus used \
the name before the match, keep that in the "contact" or "why" paragraph.{direction}

Reply as JSON with seven fields, each one paragraph of plain sentences within its word limit:
- "summary" (at most {REPORT_WORDS["summary"]} words): what {source} lists, {reach} \
and when, the outcome and its main reason, and the most important next step;
- "threat" (at most {REPORT_WORDS["threat"]} words): what {source} lists the indicator as and \
what that family does, stated directly; only where a line says we hold no description or {source} \
names no family, say {source}'s listing is all we hold;
- "host" (at most {REPORT_WORDS["host"]} words): what the address did across the days we hold and \
which products it used; what they are typical of if that helps, never what the host is;
- "contact" (at most {REPORT_WORDS["contact"]} words): the contact with the listed address: when, \
how long, the port and TLS name, how much moved each way, and whether the address is shared;
- "why" (at most {REPORT_WORDS["why"]} words): under outcome "review", why the case stays open; \
under "explained", the ordinary reason for the contact;
- "after" (at most {REPORT_WORDS["after"]} words): what came just before and after the contact: \
new destinations, uploads, later contact; if the input holds nothing on this, say we could not \
check it;
- "conclusion" (at most {REPORT_WORDS["conclusion"]} words): what we can and cannot say, then the \
next steps as one sentence, the most important first: "The next steps are to ...; ...; and ...".

An example of the style for three of the fields, for a different case:
{{"summary": "A campus host, HOST, exchanged a small amount of traffic with an address {source} \
lists as the server of a remote-access trojan. We kept the case for review because nothing we hold \
explains the contact. The next step is to identify the device and check its endpoint record.", \
"why": "The case stays open because the address serves a single site that no other campus host had \
used, so it cannot be put down to shared hosting.", "conclusion": "We can say that the contact \
happened and how much it moved; we cannot say which program made it. The next steps are to \
identify the device from its address lease; check its endpoint record at the time of the contact; \
and review the web gateway's record of the request."}}"""


CASE_FIELDS = ("threat", "host", "what_happened", "reading")
# A reply that fails the checks is sent back with its problems; the last failure is withheld.
ATTEMPTS = 3
GROUP_FIELDS = ("analysis",)
FEED_FIELDS = ("summary", "conclusion")
REPORT_FIELDS = tuple(REPORT_WORDS)


def _schema(fields: tuple[str, ...]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {name: {"type": "string"} for name in fields},
        "required": list(fields),
        "additionalProperties": False,
    }


CASE_PROMPT = case_prompt()
GROUP_PROMPT = group_prompt()
FEED_PROMPT = feed_prompt()
REPORT_PROMPT = report_prompt()

PROMPT_VERSION = hashlib.sha256(
    "\x00".join((CASE_PROMPT, GROUP_PROMPT, FEED_PROMPT, REPORT_PROMPT)).encode()
).hexdigest()[:12]
"""Recorded with every narrative and part of the cache path: a changed prompt starts afresh."""

_NAME = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z]\b", re.I)
_ADDRESS = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_RULE_CODE = re.compile(r"\b[EK][1-6]\b")
# A sentence about a family's own channel ("NanoCore's C2 is plain TCP") is about the family, not
# the host, as a sentence naming ThreatFox is. Overviews have to say why a protocol explains a
# contact, the same allowance the evaluation's grounding check makes for verdict reasoning.
_FAMILY_TERMS = re.compile(
    r"\b(?:famil(?:y|ies)|"
    + "|".join(
        re.escape(term)
        for family, name in (
            *((profile.family, profile.name) for profile in FAMILIES.values()),
            *((entry.family, entry.name) for entry in REPORT_FAMILIES.values()),
        )
        for term in (family, name.split()[0].split("-")[0])
    )
    + r")\b",
    re.IGNORECASE,
)
_HOST_VERDICT = re.compile(r"\b(benign|harmless|malware-free|clean|safe)\b", re.IGNORECASE)
_JUDGEMENT = re.compile(
    r"\b(?:un)?suspicious\b|\bmalicious (?:intent|purpose)\b|"
    r"\b(?:no|without) (?:evidence of |sign of )?malicious\b|\bordinary (?:use|usage|user)\b|"
    r"\bnormal (?:campus |user |office )?(?:use|usage|activity|traffic|behaviou?r)\b",
    re.IGNORECASE,
)
_DEVICE_CLAIM = re.compile(
    r"\b(?:host|address|device|machine)\s+(?:is|was)\s+an?\s+(?:[\w-]+\s+){0,3}?"
    r"(?:pc|laptop|desktop|workstation|server|phone|mac|computer|machine|device|vm)\b",
    re.IGNORECASE,
)
# How the team works, which a case report never says. Ordinary senses stay allowed: "rule out",
# "remote code execution", a Windows "user profile", a file's "hash".
_METHOD = re.compile(
    r"\bCASE_STUDY\b|\b(?:retained|triage|episodes?|digest|verdicts?|blind|shadow|thresholds?|"
    r"pipeline|detectors?|jaccard|duckdb|clickhouse|activity_1m|long_flow\w*|"
    r"rdap|ollama|openrouter|haiku|qwen\w*|llm|language model|models?|(?:cited|c2) profiles?|"
    r"family profiles?|stream|feed|case file|live source|re-?quer\w+|hashed|"
    r"scor(?:e|es|ed|ing)|the input|background|established (?:site|on campus))\b|"
    r"\brules?\b(?!\s+(?:\w+\s+)?out\b)|"
    r"\b(?:by code|code (?:decided|decides|kept|keeps|explained|explains|found|finds|checked|"
    r"checks|has|wrote|writes))\b",
    re.IGNORECASE,
)
# "Ordinary reason" is the outcome's own phrase; an ordinary host is a verdict on it.
_NO_CONTACT_AFTER = re.compile(
    r"\bno (?:\w+ )?contact\b[^.]*\b(?:after|through|until|up to) \d", re.IGNORECASE
)
_UNDATED_NO_CONTACT = re.compile(
    r"\bno (?:later|further) contact with (?:\S+|the (?:listed |flagged )?address)\.(?:\s|$)",
    re.IGNORECASE,
)
_OTHER_MATCH = re.compile(r"also matched another indicator: (\S+),")
_DOWNLOAD_TOTAL = re.compile(r"sent it 1 MB or more, ([\d.]+ [KMGT]?B) in all")
_NEW_DESTINATIONS = re.compile(r"\b\d[\d,]* new (?:named )?destinations?\b")
_SERVICES_USED = re.compile(r"this address used (\d+) distinct services")
_STATED_DIRECTION = re.compile(
    r"\b(?:connected (?:in\b|to (?:the host|HOST))|reached (?:the host|HOST)|attacked|"
    r"targeted (?:the host|HOST))",
    re.IGNORECASE,
)
_ORDINARY_USE = re.compile(
    r"\b(?:ordinary|normal|everyday) (?:[\w-]+ ){0,2}(?:use|usage|browsing|activity|traffic|"
    r"behaviou?r)\b",
    re.IGNORECASE,
)
_CONTRADICTS = {
    EXPLAINED: re.compile(
        r"\b(?:needs?|requires?|warrants?|merits?|deserves?|calls? for)\b[^.;]*?"
        r"\b(?:review|investigation|escalation)\b|\bshould be (?:kept|held|escalated|reviewed|"
        r"investigated)\b|\b(?:kept|held|left) (?:for|in) review\b",
        re.IGNORECASE,
    ),
    REVIEW: re.compile(
        r"\b(?:can|could|may) (?:safely )?be (?:safely )?(?:cleared|dismissed|ignored|closed)\b|"
        r"\b(?:the case|the match|this case|it) (?:is|was) (?:explained|cleared|dismissed)\b|"
        r"\bno (?:further )?(?:action|review|follow[- ]up) (?:is )?(?:needed|required)\b",
        re.IGNORECASE,
    ),
}


@dataclass(frozen=True, slots=True)
class Narrative:
    """A piece of model prose, or why there is none and code's text stands instead."""

    written_by: str
    """The model's label when its reply passed the checks, "code" otherwise."""
    fields: Mapping[str, str] = field(default_factory=dict)
    """Empty unless the model's reply stands."""
    notes: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()
    attempts: int = 0
    cached: bool = False
    seconds: float = 0.0
    prompt_version: str = PROMPT_VERSION

    @property
    def by_model(self) -> bool:
        return bool(self.fields)


NOT_WRITTEN = Narrative("code", notes=("No model: the run used --no-model.",))


def check_prose(
    text: str, source: str, observed: Observed, disposition: str | None = None
) -> list[str]:
    """Problems with a reply, against what the model read (`source`: the prompt and the input)."""
    problems = []
    if numbers := unverified_numbers(text, source):
        problems.append("numbers that are not in the input: " + ", ".join(numbers))
    lowered = source.lower()
    if names := sorted(
        {name for name in _NAME.findall(text) if name.lower() not in lowered and "." in name}
    ):
        problems.append("names that are not in the input: " + ", ".join(names))
    if addresses := sorted(set(_ADDRESS.findall(text)) - set(_ADDRESS.findall(source))):
        problems.append("addresses that are not in the input: " + ", ".join(addresses))
    if words := host_state_words(text):
        problems.append(
            "describes the host's state (" + ", ".join(words) + "); flow records cannot show that"
        )
    for pattern, what in (
        (_HOST_VERDICT, "calls something benign or safe"),
        (_DEVICE_CLAIM, "says what the host is"),
    ):
        if _affirmed(pattern, text):
            problems.append(f"{what}; describe what the address did instead")
    if found := _JUDGEMENT.search(text):
        problems.append(f"judges the traffic ('{found.group(0)}'); say what code found instead")
    if _RULE_CODE.search(text):
        problems.append("uses rule codes; say what the rule means instead")
    problems.extend(unsupported_shapes(text, observed))
    problems.extend(_unattributed(text))
    if confidence_as_evidence(text):
        problems.append(
            "treats the list's confidence as evidence; it rates the indicator, not this host"
        )
    if disposition in _CONTRADICTS and _affirmed(_CONTRADICTS[disposition], text):
        problems.append(
            f"contradicts the code's decision ({disposition}); describe it, never change it"
        )
    return problems


def _unattributed(text: str) -> list[str]:
    """Threat labels in a sentence that names neither the list, the indicator nor the family."""
    problems = []
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if _ATTRIBUTION.search(sentence) or _FAMILY_TERMS.search(sentence):
            continue
        for match in _THREAT_LABEL.finditer(sentence):
            if not _hedged(sentence, match.start(), match.end()):
                problems.append(
                    f"uses '{match.group(0)}' without attributing it to its list, the indicator "
                    "or the family"
                )
                break
    return problems


def _affirmed(pattern: re.Pattern[str], text: str) -> bool:
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        for match in pattern.finditer(sentence):
            if not _hedged(sentence, match.start(), match.end()):
                return True
    return False


def method_words(text: str) -> list[str]:
    """Words that say how the team works, or a rule code, which a case report's reader has no use
    for. Nothing here decides anything: a reply using one goes back to be rewritten."""
    found = {match.group(0).lower() for match in _METHOD.finditer(text)}
    found |= {match.group(0) for match in _RULE_CODE.finditer(text)}
    return sorted(found)


def inbound_problems(written: Mapping[str, str]) -> list[str]:
    """No flow record says who opened a contact (CASE_STUDY §7), whatever the list is about."""
    if found := _STATED_DIRECTION.search(" ".join(written.values())):
        return [
            f"states who opened the contact ('{found.group(0)}'); the records cannot show that, "
            "so say the contact fits the listed address connecting in"
        ]
    return []


def unweighed_count(written: Mapping[str, str], brief: str = "") -> list[str]:
    """A busy address reaches many new destinations, so the count means nothing alone. Weighing it
    takes the address's own count for that day: a count over many days against a one-day median
    compares unlike things."""
    after = written.get("after", "")
    if not _NEW_DESTINATIONS.search(after):
        return []
    used = _SERVICES_USED.search(brief)
    if "median" not in after or (used and not re.search(rf"\b{used.group(1)}\b", after)):
        return [
            "after counts new destinations with nothing to weigh them; set them beside how many "
            "services the address used that day, against that day's campus median"
        ]
    return []


def missing_facts(written: Mapping[str, str], brief: str) -> list[str]:
    """Facts the lead cannot weigh the case without, which a writer choosing can drop."""
    text = " ".join(written.values())
    problems = []
    for indicator in _OTHER_MATCH.findall(brief):
        if indicator.split(":")[0] not in text:
            problems.append(f"leaves out that the same campus address also matched {indicator}")
    for total in _DOWNLOAD_TOTAL.findall(brief):
        if total not in text:
            problems.append(f"leaves out the {total} the host received from new destinations")
    return problems


# Words that judge a host. "Vulnerable" and "unpatched" always do; the others are allowed about the
# product ("affected versions", "known to be exploited") and refused in a sentence about an address.
def report_problems(
    written: Mapping[str, str], limits: Mapping[str, int] = REPORT_WORDS
) -> list[str]:
    """What a case report must also pass, beyond `check_prose`."""
    problems = []
    if words := method_words(" ".join(written.values())):
        problems.append(
            "says how we work (" + ", ".join(words) + "); state the finding in plain words"
        )
    if _UNDATED_NO_CONTACT.search(" ".join(written.values())):
        problems.append(
            "says there was no later contact without naming the days; say only that there was none "
            "on the later days the input names"
        )
    if _NO_CONTACT_AFTER.search(" ".join(written.values())):
        problems.append(
            "says there was no contact after a date; say only that there was none on the later "
            "days the input names"
        )
    if any(mark in " ".join(written.values()) for mark in "{}"):
        problems.append("has a stray brace; write plain sentences")
    if found := _ORDINARY_USE.search(" ".join(written.values())):
        problems.append(
            f"judges the host's use ('{found.group(0)}'); say what its products are typical of"
        )
    for name, limit in limits.items():
        count = len(written.get(name, "").split())
        if count > limit * REPORT_WORDS_MARGIN:
            problems.append(f"{name} runs to {count} words; keep it to {limit}")
    return problems


Progress = Callable[[str], None]
ExtraCheck = Callable[[Mapping[str, str]], list[str]]


def _listed_by(source: str, extra: ExtraCheck | None) -> ExtraCheck:
    """`extra`, and on a case from another list, no credit to ThreatFox."""

    def check(written: Mapping[str, str]) -> list[str]:
        problems = extra(written) if extra is not None else []
        if source != THREATFOX.source and "threatfox" in " ".join(written.values()).lower():
            problems.append(f"names ThreatFox; {source} lists this indicator")
        return problems

    return check


class Writer:
    """The local model as the report's writer: one checked, cached reply per request."""

    def __init__(
        self,
        client: ModelClient,
        cache_dir: Path | None = None,
        progress: Progress | None = None,
    ) -> None:
        self._client = client
        self._progress = progress
        self._cache_path = (
            cache_dir / _slug(client.model) / "narrative.jsonl" if cache_dir else None
        )
        self._cache = self._read_cache()

    @property
    def label(self) -> str:
        return self._client.label

    def case(
        self,
        digest: str,
        observed: Observed,
        disposition: str,
        what: str,
        source: str = THREATFOX.source,
    ) -> Narrative:
        return self._write(
            case_prompt(source), digest, CASE_FIELDS, observed, disposition, what, source=source
        )

    def group(
        self,
        digest: str,
        observed: Observed,
        disposition: str,
        what: str,
        source: str = THREATFOX.source,
    ) -> Narrative:
        return self._write(
            group_prompt(source), digest, GROUP_FIELDS, observed, disposition, what, source=source
        )

    def feed(
        self, digest: str, observed: Observed, what: str, source: str = THREATFOX.source
    ) -> Narrative:
        return self._write(
            feed_prompt(source), digest, FEED_FIELDS, observed, None, what, source=source
        )

    def report(
        self,
        brief: str,
        observed: Observed,
        disposition: str,
        what: str,
        source: str = THREATFOX.source,
        inbound: bool = False,
    ) -> Narrative:
        """A case report's paragraphs. A failure is not kept: this text goes to someone else, so
        the next run asks again rather than stand on a failed reply or a lost connection."""
        return self._write(
            report_prompt(source, inbound),
            brief,
            REPORT_FIELDS,
            observed,
            disposition,
            what,
            extra=lambda written: [
                *report_problems(written, INBOUND_WORDS if inbound else REPORT_WORDS),
                *(inbound_problems(written) if inbound else ()),
                *(unweighed_count(written, brief) if "campus median" in brief else ()),
                *missing_facts(written, brief),
            ],
            keep_failures=False,
            source=source,
        )

    def _write(
        self,
        prompt: str,
        text: str,
        fields: tuple[str, ...],
        observed: Observed,
        disposition: str | None,
        what: str,
        *,
        extra: ExtraCheck | None = None,
        keep_failures: bool = True,
        source: str = THREATFOX.source,
    ) -> Narrative:
        messages = [{"role": "system", "content": prompt}, {"role": "user", "content": text}]
        # The key is the whole request, prompt included, so a changed prompt misses only its own
        # replies.
        key = hashlib.sha256(
            json.dumps([self._client.model, messages], sort_keys=True).encode()
        ).hexdigest()
        if key in self._cache:
            self._say(f"{what}: cached")
            return _from_record(self._cache[key], cached=True)
        self._say(f"{what}: writing")
        found = _checked(
            self._client,
            messages,
            fields,
            prompt + "\n" + text,
            observed,
            disposition,
            _listed_by(source, extra),
        )
        if found.by_model or keep_failures:
            self._store(key, found)
        return found

    def _say(self, message: str) -> None:
        if self._progress is not None:
            self._progress(message)

    def _read_cache(self) -> dict[str, dict[str, Any]]:
        if self._cache_path is None or not self._cache_path.is_file():
            return {}
        found = {}
        for line in self._cache_path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and isinstance(record.get("key"), str):
                found[record["key"]] = record
        return found

    def _store(self, key: str, narrative: Narrative) -> None:
        record = {
            "key": key,
            "written_by": narrative.written_by,
            "fields": dict(narrative.fields),
            "notes": list(narrative.notes),
            "problems": list(narrative.problems),
            "attempts": narrative.attempts,
            "seconds": narrative.seconds,
        }
        self._cache[key] = record
        if self._cache_path is None:
            return
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        with self._cache_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")


def _from_record(record: Mapping[str, Any], *, cached: bool) -> Narrative:
    return Narrative(
        written_by=str(record.get("written_by", "code")),
        fields={str(k): str(v) for k, v in dict(record.get("fields") or {}).items()},
        notes=tuple(str(note) for note in record.get("notes") or ()),
        problems=tuple(str(problem) for problem in record.get("problems") or ()),
        attempts=int(record.get("attempts") or 0),
        cached=cached,
        seconds=float(record.get("seconds") or 0.0),
    )


def _checked(
    client: ModelClient,
    messages: list[dict[str, str]],
    fields: tuple[str, ...],
    source: str,
    observed: Observed,
    disposition: str | None,
    extra: ExtraCheck | None = None,
) -> Narrative:
    """One reply, checked; one retry with the problems listed; withheld if it fails twice."""
    schema = _schema(fields)
    problems: list[str] = []
    seconds = 0.0
    for attempt in range(1, ATTEMPTS + 1):
        try:
            parsed, raw, tokens, elapsed = client.complete(messages, schema)
        except ModelError as exc:
            problems = [str(exc)]
            continue
        seconds += elapsed
        if tokens >= CONTEXT_MARGIN * client.num_ctx:
            return Narrative(
                "code",
                notes=(
                    "The input came within 10% of the model's context window and may have been "
                    "cut off; the model's text is withheld.",
                ),
                attempts=attempt,
                seconds=seconds,
            )
        written = {name: str(parsed.get(name) or "").strip() for name in fields}
        missing = [name for name, value in written.items() if not value]
        problems = [f"empty field: {name}" for name in missing]
        problems += check_prose(" ".join(written.values()), source, observed, disposition)
        if extra is not None:
            problems += extra(written)
        if not problems:
            return Narrative(client.label, written, attempts=attempt, seconds=seconds)
        messages = [
            *messages[:2],
            {"role": "assistant", "content": raw},
            {
                "role": "user",
                "content": "Your answer has these problems:\n"
                + "\n".join(f"- {problem}" for problem in problems)
                + "\nRewrite it to fix them, using only the input, in the same JSON format.",
            },
        ]
    return Narrative(
        "code",
        notes=(
            f"The model's text failed the checks {ATTEMPTS} times; code's text stands instead.",
        ),
        problems=tuple(problems),
        attempts=ATTEMPTS,
        seconds=seconds,
    )


def restore(narrative: Narrative, replacements: Mapping[str, str]) -> Narrative:
    """Put back what was pseudonymised before the text reached the model."""
    if not narrative.fields:
        return narrative
    fields = {}
    for name, value in narrative.fields.items():
        for token, original in replacements.items():
            value = value.replace(token, original)
        fields[name] = value
    return Narrative(
        narrative.written_by,
        fields,
        narrative.notes,
        narrative.problems,
        narrative.attempts,
        narrative.cached,
        narrative.seconds,
        narrative.prompt_version,
    )


def _slug(model: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "_", model.lower()).strip("_")
