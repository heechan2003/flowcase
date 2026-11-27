"""Write the report: one HTML page and one Markdown file for people, one JSON file for reuse.

Both read like the php2shell hunt write-up: an executive summary, the threats behind the feed, an
analysis of each group of like cases, the conclusion with what to do, one card per case, and an
appendix of the checks behind every verdict. Every case gets an overview, review and explained
alike: the local model writes it from the case's digest and code checks it, and when the model
is off or its text fails the checks, code's own sentences stand in. No prose changes a decision.

All three files carry internal addresses and domains. They go to a git-ignored directory and are
never committed or pasted outside the team.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import date, datetime
from pathlib import Path
from typing import Any

from ioc_report import html_report
from ioc_report.contact import Contact
from ioc_report.facts import CaseFacts, case_facts
from ioc_report.feed import Feed
from ioc_report.history import HistoryContext
from ioc_report.live import LiveContext
from ioc_report.narrative import NOT_WRITTEN, Narrative
from ioc_report.outline import (
    actions,
    checks,
    families,
    model_verdict,
    reasons,
    would_change,
)
from ioc_report.report_text import PARTS, written_by
from ioc_report.rules import (
    ESTABLISHED_MIN_ADDRESSES,
    ESTABLISHED_MIN_DAYS,
    EXPLAINED,
    REVIEW,
    SHARED_MIN_DOMAINS,
    Judged,
)
from ioc_report.summary import (
    RULES,
    CaseGroup,
    CaseResult,
    case_groups,
    case_text,
    coverage_items,
    feed_text,
    group_text,
    indicator_age,
    listing_line,
    ordered,
    requeried,
    rule_counts,
    shadow_counts,
    shadow_worth_a_look,
)
from ioc_report.text import duration, minute, size, when

__all__ = ["RULES", "CaseResult", "ordered", "write_report"]

# A family's cited background, which the report's Threats section lists once rather than per case.
BACKGROUND = "Knowledge, background not evidence"
EVERY_CHECK = (
    "nothing; every check ran (live re-query, published stream, retained 5-minute timing)."
)


def write_report(
    out_dir: Path,
    name: str,
    feed: Feed,
    results: list[CaseResult],
    live: LiveContext,
    history: HistoryContext,
    model_label: str,
    generated_at: datetime,
    groups: list[CaseGroup] | None = None,
    summary: Narrative = NOT_WRITTEN,
) -> tuple[Path, Path, Path]:
    """`results` in report order (`ordered`), `groups` from `case_groups` over them.
    Returns (html, markdown, json)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    results = ordered(results)
    groups = groups if groups is not None else case_groups(results)
    facts = [case_facts(result.evidence, result.decision, live, history) for result in results]
    page = out_dir / f"{name}.html"
    markdown = out_dir / f"{name}.md"
    data = out_dir / f"{name}.json"
    page.write_text(
        html_report.render(
            name, feed, results, facts, live, history, model_label, generated_at, groups, summary
        ),
        encoding="utf-8",
    )
    markdown.write_text(
        _markdown(
            name, feed, results, facts, live, history, model_label, generated_at, groups, summary
        ),
        encoding="utf-8",
    )
    data.write_text(
        json.dumps(
            _data(
                name,
                feed,
                results,
                facts,
                live,
                history,
                model_label,
                generated_at,
                groups,
                summary,
            ),
            indent=2,
            default=_json_default,
        )
        + "\n",
        encoding="utf-8",
    )
    return page, markdown, data


def _markdown(
    name: str,
    feed: Feed,
    results: list[CaseResult],
    facts: list[CaseFacts],
    live: LiveContext,
    history: HistoryContext,
    model_label: str,
    generated_at: datetime,
    groups: list[CaseGroup],
    summary: Narrative,
) -> str:
    """The report for people: what each case is, what code decided and why, every contact and how
    it was judged, and the sourced facts behind it. The writer's overviews, the digests and the case
    files are in the JSON, not here."""
    review = [result for result in results if result.disposition == REVIEW]
    explained = [result for result in results if result.disposition == EXPLAINED]
    caveated = sum(1 for result in explained if result.caveats)
    reason = {number: _reason(group) for group in groups for number in group.numbers}
    lines = [
        f"# IOC match report: {name}",
        "",
        f"Generated {generated_at:%Y-%m-%d %H:%M} UTC from {', '.join(p.name for p in feed.paths)}"
        f": {len(results)} case(s) from {feed.record_count} record(s), {feed.hosts} host(s), "
        f"{feed.indicators} indicator(s). Sensitive: internal addresses and domains; share only "
        "with people cleared to see the network's data. The writer's overviews, the digests and "
        f"the case files are in `{name}.json`.",
        "",
        "## Summary",
        "",
        feed_text(summary, results, groups, "summary"),
        "",
        f"**{len(review)} to review, {len(explained)} explained** ({caveated} with caveats, "
        f"{len(explained) - caveated} with every check run). Code decides every case; no case "
        "says a host is compromised, infected or benign, because flow records cannot show that. "
        f"*Summary {written_by(summary, model_label)}.*",
        "",
    ]
    for item in coverage_items(feed, results, live, history):
        lines.append(f"- **{item.label}:** {item.text}")
        lines.extend(f"  - {detail}" for detail in item.details)
    lines += ["", "## Threats", ""]
    for note in families(results):
        sources = f" Sources: {', '.join(note.sources)}." if note.sources else ""
        lines.append(
            f"- **{note.name}** ({note.source} `{note.malware}`, {', '.join(note.threat_types)}; "
            f"cases {_numbers(note.numbers)}): {note.background}{sources}"
        )
    lines += [
        "",
        "## Cases",
        "",
        "| # | Indicator | Host | Listing | First match | Decision | Reason |",
        "|---|---|---|---|---|---|---|",
    ]
    for number, result in enumerate(results, 1):
        case = result.evidence.case
        lines.append(
            f"| [{number}](#case-{number}) | `{case.indicator}` | `{case.host}` | "
            f"{case.listing.malware}, {case.listing.threat_type} | {when(case.first)} | "
            f"{_decision(result)} | {_cell(reason.get(number, ''))} |"
        )
    shared = [group for group in groups if len(group.results) > 1]
    if shared:
        lines += ["", "## Groups", ""]
        for group in shared:
            lines += [
                f"### {group.label} (cases {_numbers(group.numbers)})",
                "",
                group_text(group),
                f"*{written_by(group.narrative, model_label)}.*",
                "",
            ]
    lines += [
        "",
        "## Next steps by system",
        "",
        feed_text(summary, results, groups, "conclusion"),
        "",
        "| Where | What to do | Cases |",
        "|---|---|---|",
        *(
            f"| {action.label} | {action.text} | {_numbers(action.numbers)} |"
            for action in actions(results)
        ),
        "",
        "## Each case",
    ]
    for number, (result, found) in enumerate(zip(results, facts, strict=True), 1):
        lines += ["", *_case_section(number, result, found)]
    lines += ["", *_appendix(results)]
    return "\n".join(lines) + "\n"


def _reason(group: CaseGroup) -> str:
    """The group label without its family: what decided the case."""
    return group.label.split(": ", 1)[-1]


def _decision(result: CaseResult) -> str:
    rules = result.decision.rules
    return f"{result.disposition} ({', '.join(rules)})" if rules else result.disposition


def _case_section(number: int, result: CaseResult, facts: CaseFacts) -> list[str]:
    case = result.evidence.case
    lines = [
        f'<a id="case-{number}"></a>',
        f"### {number}. `{case.indicator}` · `{case.host}` · {_decision(result)}",
        "",
        " · ".join(_particulars(result)) + ".",
        "",
        "**Why:**",
        "",
        *(f"- {line.text}" for line in reasons(result)),
        "",
    ]
    if facts.timeline:
        lines += [
            "| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |",
            "|---|---|---|---|---|---|---|---|---|",
            *(
                f"| {minute(row.first)} | {minute(row.last)} | {row.source} | "
                f"{_cell(f'{row.kind}: {row.what}')} | "
                f"{row.minutes if row.minutes is not None else row.flows} | {size(row.received)} | "
                f"{size(row.sent)} | "
                f"{duration(row.longest_sec) if row.longest_sec is not None else '—'} | "
                f"{_cell(row.status)} |"
                for row in facts.timeline
            ),
            "",
        ]
    if result.digest is not None:
        for title, digest_lines in result.digest.sections():
            if title == "Decision" or (title == "Model verdict" and result.shadow is None):
                continue
            shown = [line for line in digest_lines if line.source != BACKGROUND]
            if shown:
                lines += [f"**{title}**", "", *(f"- {line.render()}" for line in shown), ""]
    if len(facts.coverage) > 1:
        lines += ["**Could not check:**", "", *(f"- {text}" for text in facts.coverage), ""]
    else:
        gap = facts.coverage[0] if facts.coverage else EVERY_CHECK
        lines += [f"**Could not check:** {gap}", ""]
    if result.disposition == REVIEW and result.next_steps:
        lines += ["**Next steps:**", ""]
        lines += [f"{index}. {step}" for index, step in enumerate(result.next_steps, 1)]
        lines.append("")
    lines.append(f"**Would change it:** {would_change(result)}.")
    return lines


def _particulars(result: CaseResult) -> list[str]:
    """One line of what the case is: the listing, the match and what else was checked. The flagged
    address and its network are in the Threat facts."""
    case = result.evidence.case
    found = [
        f"{case.listing.malware}, {case.listing.threat_type}",
        f"first match {when(case.first)}",
        f"{len(case.minutes)} matched minute(s) in {len(case.match_ids)} feed record(s)",
    ]
    if case.is_domain:
        found.append(f"registered {indicator_age(result)}")
    if case.threatfox_first_seen is not None:
        found.append(listing_line(case).rstrip("."))
    found += [f"live re-query {requeried(result)}", f"blind model {model_verdict(result)}"]
    return found


def _appendix(results: list[CaseResult]) -> list[str]:
    counts = rule_counts(results)
    lines = [
        "## Appendix",
        "",
        "### The rules",
        "",
        "| Rule | Meaning | Basis | Cases |",
        "|---|---|---|---|",
        *(f"| {rule} | {meaning} | {basis} | {counts[rule]} |" for rule, meaning, basis in RULES),
        f"| — | review because at least one contact has no explanation | — | "
        f"{counts['unexplained']} |",
        "",
        "### The checks behind every verdict",
        "",
        "| Check | Scope | A positive would be | Result |",
        "|---|---|---|---|",
        *(
            f"| {check.name} | {check.scope} | {check.positive} | {check.result} |"
            for check in checks(results)
        ),
    ]
    if tally := shadow_counts(results):
        numbers = {id(result): number for number, result in enumerate(results, 1)}
        worth = [numbers[id(result)] for result in shadow_worth_a_look(results)]
        lines += [
            "",
            "### Blind model verdicts (never applied)",
            "",
            "| Outcome | Cases |",
            "|---|---|",
            *(f"| {key} | {value} |" for key, value in sorted(tally.items())),
        ]
        if worth:
            lines += ["", f"Worth a second look: {_numbers(tuple(worth))}."]
    return lines


def _numbers(numbers: tuple[int, ...]) -> str:
    return ", ".join(f"#{number}" for number in numbers)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _data(
    name: str,
    feed: Feed,
    results: list[CaseResult],
    facts: list[CaseFacts],
    live: LiveContext,
    history: HistoryContext,
    model_label: str,
    generated_at: datetime,
    groups: list[CaseGroup],
    summary: Narrative,
) -> dict[str, Any]:
    numbers = {id(result): number for number, result in enumerate(results, 1)}
    return {
        "name": name,
        "feed": [str(path) for path in feed.paths],
        "listing": feed.listing.key,
        "generated_at": generated_at,
        "model": model_label,
        "records": feed.record_count,
        "rejected": [asdict(item) for item in feed.rejected],
        "thresholds": {
            "shared_min_domains": SHARED_MIN_DOMAINS,
            "established_min_addresses": ESTABLISHED_MIN_ADDRESSES,
            "established_min_days": ESTABLISHED_MIN_DAYS,
        },
        "live": {
            "status": live.status,
            "error": live.error,
            "days_queried": live.days_queried,
            "days_expired": live.days_expired,
            "context_days": live.context_days,
            "destination_days": live.destination_days,
            "queries": [asdict(audit) for audit in live.audits],
        },
        "history": {
            "path": str(history.path),
            "retained_days": len(history.coverage.retained_days),
            "first_day": history.coverage.first_day,
            "last_day": history.coverage.last_day,
            "not_retained": history.coverage.gaps,
        },
        "summary": _narrative_data(summary),
        "groups": [
            {
                "label": group.label,
                "disposition": group.disposition,
                "cases": group.numbers,
                "narrative": _narrative_data(group.narrative),
            }
            for group in groups
        ],
        "cases": [
            {"number": numbers[id(result)], **_case_data(result, found)}
            for result, found in zip(results, facts, strict=True)
        ],
    }


def _narrative_data(narrative: Narrative) -> dict[str, Any]:
    return {**asdict(narrative), "fields": dict(narrative.fields)}


def _case_data(result: CaseResult, facts: CaseFacts | None) -> dict[str, Any]:
    case, decision = result.evidence.case, result.decision
    return {
        "indicator": case.indicator,
        "indicator_type": case.indicator_type,
        "host": case.host,
        "source_host": case.source_host,
        "listing": asdict(case.listing),
        "matched_first": case.matched_first,
        "matched_last": case.matched_last,
        "threatfox_first_seen": case.threatfox_first_seen,
        "threatfox_last_seen": case.threatfox_last_seen,
        "caveats": [asdict(caveat) for caveat in result.caveats],
        "registrations": (
            {domain: asdict(age) for domain, age in result.evidence.registrations.items()}
            if result.evidence.registrations is not None
            else None
        ),
        "match_ids": case.match_ids,
        "disposition": decision.disposition,
        "rules": decision.rules,
        "kept_by": [asdict(finding) for finding in decision.kept_by],
        "contacts": [
            _judged_data(judged, result.evidence.contact_duplicates.get(index))
            for index, judged in enumerate(decision.contacts)
        ],
        "flows": [
            _judged_data(judged, result.evidence.flow_duplicates.get(index))
            for index, judged in enumerate(decision.flows)
        ],
        "notes": decision.notes,
        "next_steps": result.next_steps,
        "would_change": would_change(result),
        "overview": {
            **_narrative_data(result.overview),
            "text": {part: case_text(result, part) for part, _ in PARTS},
        },
        "digest": result.digest.text() if result.digest is not None else None,
        "facts": asdict(facts) if facts is not None else None,
        "shadow": (
            {
                **asdict(result.shadow),
                "majority": result.shadow.majority,
                "unanimous": result.shadow.unanimous,
                "agrees": result.shadow.agrees(result.disposition),
            }
            if result.shadow is not None
            else None
        ),
        "case_file": result.case_file,
    }


def _judged_data(judged: Judged, duplicate_of: int | None = None) -> dict[str, Any]:
    """`duplicate_of`: for a feed item the live re-query holds in full, the index of the live item
    with the same traffic. Both are judged; the report shows and counts the traffic once."""
    item = judged.item
    if isinstance(item, Contact):
        what: dict[str, Any] = {
            "kind": "contact",
            "label": item.label,
            "source": item.source,
            "minutes": len(item.minutes),
            "first": item.minutes[0],
            "last": item.minutes[-1],
            "received_bytes": item.down_bytes,
            "sent_bytes": item.up_bytes,
        }
    else:
        what = {
            "kind": "long_flows",
            "label": item.text,
            "source": item.source,
            "flows": item.flows,
            "start": item.start,
            "finish": item.finish,
            "longest_sec": item.longest_sec,
            "received_bytes": item.down_bytes,
            "sent_bytes": item.up_bytes,
        }
    return {
        **what,
        "duplicate_of": duplicate_of,
        "explained_by": [asdict(finding) for finding in judged.explained_by],
        "gap": judged.gap,
    }


def _json_default(value: object) -> object:
    if isinstance(value, datetime | date):
        return value.isoformat()
    raise TypeError(f"not JSON serializable: {type(value).__name__}")
