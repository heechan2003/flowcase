"""The report as one self-contained HTML page: an executive summary, the threats, an analysis of
each group of like cases, the conclusion, one card per case, and an appendix of the checks.

The layout follows IOC_Processor's report (`agent/report.py`); the content follows this project's
rules. Code decides every case, and a case is review or explained, never a verdict on the host.
Every fact names its source, and the model's text is labelled and checked.

Every value from the feed, the source or the model goes through `html.escape`, because feed names
are untrusted. The page loads nothing from anywhere else, and its Content-Security-Policy says so.
Charts are inline SVG drawn by code: thin marks, a legend, a hover and focus readout written with
`textContent`, and a table with the same numbers.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta
from html import escape

from ioc_report.after import UPLOAD_BYTES
from ioc_report.casefile import FLAGGED_TAG, MAX_CONTEXT_LISTED, NEW_TAG, UNESTABLISHED_TAG
from ioc_report.facts import CaseFacts, DayPoint, Window
from ioc_report.feed import Feed
from ioc_report.history import HistoryContext
from ioc_report.live import CONTEXT_WINDOW_SECONDS, LiveContext
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
from ioc_report.rules import EXPLAINED, REVIEW
from ioc_report.summary import (
    RULE_MEANING,
    RULES,
    CaseGroup,
    CaseResult,
    case_text,
    coverage_items,
    feed_text,
    group_text,
    indicator_age,
    listing_line,
    requeried,
    rule_counts,
    shadow_counts,
    shadow_worth_a_look,
)
from ioc_report.text import (
    day_list,
    duration,
    local_time,
    minute,
    network,
    report_zone,
    size,
    when,
)

TITLE = "IOC match report"
# Output bounds, not thresholds.
AFTER_LISTED = 20
SYSTEM_ORDER = ("device", "endpoint", "triage stream", "web gateway", "resolver", "mail")
SYSTEM_LABEL = {
    "device": "Device: who held the address",
    "endpoint": "Endpoint record",
    "triage stream": "Triage stream",
    "web gateway": "Web gateway or proxy",
    "resolver": "Resolver logs",
    "mail": "Mail gateway",
}
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)


DATE_TIME = re.compile(r"\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2})?")


def e(value: object) -> str:
    return escape(str(value), quote=True)


def prose(value: object) -> str:
    """Escaped text whose dates and times do not break across lines. The pattern matches digits,
    hyphens, a space and a colon only, so wrapping it cannot reopen what escaping closed."""
    return DATE_TIME.sub(lambda found: f"<span class='nowrap'>{found.group(0)}</span>", e(value))


def render(
    name: str,
    feed: Feed,
    results: Sequence[CaseResult],
    facts: Sequence[CaseFacts],
    live: LiveContext,
    history: HistoryContext,
    model_label: str,
    generated_at: datetime,
    groups: Sequence[CaseGroup] = (),
    summary: Narrative = NOT_WRITTEN,
) -> str:
    """`results` in report order, `facts` beside them, `groups` over the same numbering."""
    files = ", ".join(path.name for path in feed.paths)
    cards = "\n".join(
        _card(number, len(results), result, found, model_label)
        for number, (result, found) in enumerate(zip(results, facts, strict=True), 1)
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<title>{e(TITLE)}: {e(name)}</title>
<style>{CSS}</style>
</head>
<body>
<header class="masthead" id="top">
  <div class="wrap masthead-inner">
    <div>
      <div class="eyebrow">IOC matches against flow records</div>
      <h1>{e(TITLE)}: <span class="mono">{e(name)}</span></h1>
      <p class="sub">Generated {e(when(generated_at))} · feed {e(files)}
      · prose by {e(model_label)}</p>
    </div>
    <div class="marking">Sensitive · internal use only</div>
  </div>
</header>
<main class="wrap">
{_summary_section(feed, list(results), list(groups), summary, model_label)}
{_background(feed, list(results), live, history)}
{_analysis(list(groups), model_label)}
{_conclusion(list(results), list(groups), summary)}
<section class="cases" aria-labelledby="cases-heading">
  <h2 id="cases-heading" class="section-title">Cases</h2>
  {cards}
</section>
{_appendix(list(results))}
</main>
<footer class="wrap page-foot">{e(TITLE)} · {e(name)} · generated {e(when(generated_at))} ·
contains internal addresses and per-host activity: do not share outside the team.</footer>
<div class="tip" id="tip" role="status" aria-live="polite" hidden></div>
<script>{SCRIPT}</script>
</body>
</html>
"""


# --- the front matter -----------------------------------------------------------------------------


def _kind(result: CaseResult) -> str:
    if result.disposition == REVIEW:
        return "review"
    return "caveated" if result.caveats else "checked"


def _byline(narrative: Narrative, model_label: str) -> str:
    return f"<p class='byline small muted'>{e(written_by(narrative, model_label))}.</p>"


def _summary_section(
    feed: Feed,
    results: list[CaseResult],
    groups: list[CaseGroup],
    summary: Narrative,
    model_label: str,
) -> str:
    review = [result for result in results if result.disposition == REVIEW]
    explained = [result for result in results if result.disposition == EXPLAINED]
    caveated = sum(1 for result in explained if result.caveats)
    tiles = [
        ("all", "Cases", len(results), ""),
        ("review", "Review", len(review), "review"),
        ("caveated", "Explained, with caveats", caveated, "caveated"),
        ("checked", "Explained, every check ran", len(explained) - caveated, "checked"),
    ]
    tile_html = "".join(
        f'<button type="button" class="tile {css}" data-filter="{key}" '
        f'aria-pressed="{"true" if key == "all" else "false"}">'
        f'<span class="tile-value">{count}</span>'
        f'<span class="tile-label">{e(label)}</span></button>'
        for key, label, count, css in tiles
    )
    static = (
        f'<div class="tile static"><span class="tile-value">{feed.hosts}</span>'
        f'<span class="tile-label">Hosts</span></div>'
        f'<div class="tile static"><span class="tile-value">{feed.indicators}</span>'
        f'<span class="tile-label">Indicators</span></div>'
    )
    if tally := shadow_counts(results):
        agree = sum(v for k, v in tally.items() if k.startswith("agrees"))
        static += (
            f'<div class="tile static"><span class="tile-value">{agree}/{sum(tally.values())}'
            '</span><span class="tile-label">Blind model agrees</span></div>'
        )
    return f"""
<section class="overview" aria-labelledby="summary-heading">
  <h2 id="summary-heading" class="section-title">Executive summary</h2>
  <div class="lede card">
    <p>{prose(feed_text(summary, results, groups, "summary"))}</p>
    {_byline(summary, model_label)}
  </div>
  <div class="tiles" role="group" aria-label="Show cases">{tile_html}{static}</div>
  <p class="small muted">Code decides every case. <span class="badge review">Review</span> means a
  person should look; <span class="badge explained">Explained</span> means every contact has an
  ordinary reason the rules name. No case says a host is compromised, infected or benign: flow
  records carry no payload, process or user. {e(_times_note())}</p>
</section>"""


def _background(
    feed: Feed, results: list[CaseResult], live: LiveContext, history: HistoryContext
) -> str:
    threats = "".join(
        f"<div class='threat'><h3>{e(note.name)} <span class='muted small mono'>"
        f"{e(note.malware)} · {e(', '.join(note.threat_types))}</span></h3>"
        f"<p>{prose(note.background)}</p>"
        f"<p class='small muted'>Cases {e(_numbers(note.numbers))}"
        + (f" · sources: {e(', '.join(note.sources))}" if note.sources else "")
        + "</p></div>"
        for note in families(results)
    )
    coverage = "".join(
        f"<li><strong>{e(item.label)}:</strong> {e(item.text)}"
        + (
            "<ul>" + "".join(f"<li>{e(detail)}</li>" for detail in item.details) + "</ul>"
            if item.details
            else ""
        )
        + "</li>"
        for item in coverage_items(feed, results, live, history)
    )
    return f"""
<section class="front" aria-labelledby="background-heading">
  <h2 id="background-heading" class="section-title">Background</h2>
  <div class="card padded">{threats}</div>
  <details class="about"><summary>The data: sources, coverage and query footprint</summary>
    <ul>{coverage}</ul>
    <p class="small">Sources: <span class="src">IOC feed</span> the feed's matched rows ·
    <span class="src">Live source</span> re-read from the flow source ·
    <span class="src">Retained history</span> the triage repo's store (hashed) ·
    <span class="src">Published triage stream</span> its daily episodes ·
    <span class="src">RDAP</span> registration dates · <span class="src">Measured</span> counts
    against a CASE_STUDY section.</p></details>
</section>"""


def _analysis(groups: list[CaseGroup], model_label: str) -> str:
    blocks = []
    for group in groups:
        rows = "".join(
            f"<tr data-kind='{_kind(result)}'><td class='num'><a href='#case-{number}'>{number}"
            f"</a></td><td class='mono small'>{e(result.evidence.case.host)}<div class='muted'>"
            f"{e(result.evidence.case.indicator)}</div></td>"
            f"<td class='small nowrap'>{_time_cell(result.evidence.case.first)}</td>"
            f"<td>{_verdict_badge(result)}</td><td class='small'>{e(model_verdict(result))}</td>"
            f"<td class='small'>{prose(case_text(result, 'reading'))}</td></tr>"
            for number, result in zip(group.numbers, group.results, strict=True)
        )
        kind = "review" if group.disposition == REVIEW else "caveated checked"
        blocks.append(
            f"<article class='group card padded' data-kind='{kind}'>"
            f"<h3>{e(group.label)} <span class='muted small'>({len(group.results)} case(s))"
            f"</span></h3><p>{prose(group_text(group))}</p>"
            f"{_byline(group.narrative, model_label)}"
            "<div class='table-wrap'><table class='dense'><thead><tr><th class='num'>#</th>"
            "<th>Host / indicator</th><th>First match</th><th>Code</th><th>Blind model</th>"
            f"<th>Reading</th></tr></thead><tbody>{rows}</tbody></table></div></article>"
        )
    return f"""
<section class="front" aria-labelledby="analysis-heading">
  <h2 id="analysis-heading" class="section-title">Analysis</h2>
  <p class="small muted">Cases code decided the same way, for the same reasons, on the same
  family. Review groups first.</p>
  {"".join(blocks)}
</section>"""


def _conclusion(results: list[CaseResult], groups: list[CaseGroup], summary: Narrative) -> str:
    rows = (
        "".join(
            f"<tr><td class='nowrap'>{e(action.label)}</td><td>{prose(action.text)}</td>"
            f"<td class='small'>{_case_links(action.numbers)}</td></tr>"
            for action in actions(results)
        )
        or "<tr><td colspan='3' class='muted'>Nothing to look up.</td></tr>"
    )
    return f"""
<section class="front" aria-labelledby="conclusion-heading">
  <h2 id="conclusion-heading" class="section-title">Conclusion and next steps</h2>
  <div class="lede card"><p>{prose(feed_text(summary, results, groups, "conclusion"))}</p></div>
  <div class="table-wrap card"><table><thead><tr><th>Where</th><th>What to do</th>
  <th>Cases</th></tr></thead><tbody>{rows}</tbody></table></div>
</section>"""


def _numbers(numbers: Sequence[int]) -> str:
    return ", ".join(f"#{number}" for number in numbers)


def _case_links(numbers: Sequence[int]) -> str:
    return ", ".join(f"<a href='#case-{number}'>#{number}</a>" for number in numbers)


def _verdict_badge(result: CaseResult) -> str:
    if result.disposition == REVIEW:
        return "<span class='badge review'>Review</span>"
    return "<span class='badge explained'>Explained</span>"


# --- one case -------------------------------------------------------------------------------------


def _card(number: int, total: int, result: CaseResult, facts: CaseFacts, model_label: str) -> str:
    evidence, decision = result.evidence, result.decision
    case = evidence.case
    caveat_pill = (
        f"<span class='pill warn'><span aria-hidden='true'>⚠</span> {len(result.caveats)} "
        "caveat(s)</span>"
        if result.caveats
        else ""
    )
    pills = (
        f"{_verdict_badge(result)}"
        f"<span class='pill'>blind model: {e(model_verdict(result))}</span>"
        f"<span class='pill'>{e(case.listing.malware)} · {e(case.listing.threat_type)}</span>"
        f"<span class='pill'>live re-query: {e(requeried(result))}</span>{caveat_pill}"
    )
    anchor = f"case-{number}"
    parts = "".join(
        f"<div><dt>{e(title)}</dt><dd>{prose(case_text(result, part))}</dd></div>"
        for part, title in PARTS
    )
    evidence_parts = (
        _facts_box(result) + _around(anchor, facts) + _timeline_table(facts) + _after(anchor, facts)
    )
    digest = result.digest.text() if result.digest is not None else ""
    return f"""
<article class="case card" id="{anchor}" data-kind="{_kind(result)}"
  aria-labelledby="{anchor}-title">
  <header class="case-head">
    <div class="kicker">Case {number} of {total} · {e(decision.disposition)}</div>
    <h3 class="case-title mono" id="{anchor}-title">{e(case.indicator)}</h3>
    <p class="case-sub">and <span class="mono">{e(case.host)}</span>, first match
    {e(when(case.first))}</p>
    <div class="pills">{pills}</div>
  </header>
  <section class="part lead {_kind(result)}"><h4>Overview</h4><dl class="story">{parts}</dl>
  {_byline(result.overview, model_label)}</section>
  {_reasons(result)}
  {_steps(facts) if result.disposition == REVIEW else ""}
  {_case_coverage(facts)}
  <p class="small"><strong>What would change the reading:</strong> {prose(would_change(result))}.
  </p>
  <details class="appendix"><summary>Evidence: the contact, its timing and the windows around
  it</summary>{evidence_parts}</details>
  <details class="appendix"><summary>The digest the overview was written from</summary>
    <pre class="casefile">{e(digest)}</pre></details>
  <details class="appendix"><summary>The case file the blind verdict read (every fact, with its
  source)</summary><pre class="casefile">{e(result.case_file or "")}</pre></details>
  <p class="case-foot"><a href="#top">Back to the summary</a></p>
</article>"""


def _facts_box(result: CaseResult) -> str:
    case = result.evidence.case
    claim = case.listing
    confidence = claim.confidence if claim.confidence is not None else "not given"
    servers: dict[str, str] = {}
    for row in case.rows:
        servers.setdefault(row.server_ip, network(row.asn, row.asn_org, row.country))
    rows = [
        ("Host", case.host),
        ("Indicator", f"{case.indicator} ({case.indicator_type})"),
        (
            f"{claim.source} listing",
            f"{claim.malware}; {claim.threat_type}; confidence {confidence} (shown, never used)",
        ),
        (f"{claim.source} dates", listing_line(case)),
        ("First match", when(case.first)),
        (
            "Matched",
            f"{len(case.minutes)} minute(s) on {day_list(case.days)}; {len(case.match_ids)} feed "
            "record(s)",
        ),
        (
            "Flagged address",
            "; ".join(f"{s} · {n or 'network unknown'}" for s, n in servers.items()),
        ),
    ]
    if case.is_domain:
        rows.append(("Indicator registered", indicator_age(result)))
    items = "".join(f"<div><dt>{e(k)}</dt><dd>{prose(v)}</dd></div>" for k, v in rows)
    return f"<dl class='facts'>{items}</dl>"


def _reasons(result: CaseResult) -> str:
    items = "".join(f"<li>{prose(line.text)}</li>" for line in reasons(result))
    title = (
        "Why code kept it for review" if result.disposition == REVIEW else "Why code explained it"
    )
    return f"<section class='part'><h3>{title}</h3><ul class='kept'>{items}</ul></section>"


# --- around the contact ---------------------------------------------------------------------------


def _window_label(window: Window) -> str:
    end = window.start + timedelta(seconds=CONTEXT_WINDOW_SECONDS)
    return f"{window.start:%H:%M}-{end:%H:%M}"


def _window_counts(window: Window) -> dict[str, int]:
    counts = {"flagged": 0, "new": 0, "unestablished": 0, "other": window.habitual}
    for _row, tag in window.rows:
        key = {FLAGGED_TAG: "flagged", NEW_TAG: "new", UNESTABLISHED_TAG: "unestablished"}.get(
            tag, "other"
        )
        counts[key] += 1
    return counts


WINDOW_SERIES = (
    ("flagged", "flagged address", "s1"),
    ("new", "new to this host", "s2"),
    ("unestablished", "not established on campus", "s3"),
    ("other", "habitual or unplaced", "s0"),
)


def _around(anchor: str, facts: CaseFacts) -> str:
    if not facts.windows:
        return (
            "<section class='part'><h3>Around the contact</h3><p class='muted'>No minute detail "
            "around the contact: its day is outside the source's retention, or the live source "
            "was not queried.</p></section>"
        )
    rows = []
    for window in facts.windows:
        listed = window.rows[:MAX_CONTEXT_LISTED]
        label = f"{_window_label(window)} UTC ({window.position})"
        for row, tag in listed:
            rows.append(
                f"<tr{' class=flagged' if tag == FLAGGED_TAG else ''}><td class='nowrap'>"
                f"{e(label)}</td><td class='mono'>{e(row.root_domain or 'no name')}</td>"
                f"<td>{e(tag or 'unplaced')}</td><td class='num'>{row.active_minutes}</td>"
                f"<td class='num'>{row.addresses}</td>"
                f"<td class='num'>{e(size(row.down_bytes))}</td>"
                "</tr>"
            )
        more = len(window.rows) - len(listed)
        tail = []
        if more > 0:
            tail.append(f"{more} more not listed")
        if window.habitual:
            tail.append(
                f"{window.habitual} habitual service(s): used by this host before and established "
                "on campus"
            )
        if tail:
            rows.append(
                f"<tr class='others'><td class='nowrap'>{e(label)}</td><td colspan='5'>"
                f"{e('; '.join(tail))}</td></tr>"
            )
    return f"""
<section class="part"><h3>Around the contact</h3>
  <p class="small muted">The host's other destinations in the five-minute windows around the
  matched minutes, ranked: the flagged address, names new to this host, names the campus had not
  established (CASE_STUDY §15), then habitual ones, which are counted.</p>
  {_chart_windows(anchor, facts.windows)}
  <details class="background"><summary>Destinations by window ({len(rows)} row(s))</summary>
  <div class="table-wrap"><table class="dense"><thead><tr><th>Window</th><th>Destination</th>
  <th>Standing</th><th class="num">Min</th><th class="num">Addr</th><th class="num">Received</th>
  </tr></thead><tbody>{"".join(rows)}</tbody></table></div></details>
</section>"""


def _timeline_table(facts: CaseFacts) -> str:
    if not facts.timeline:
        return ""
    rows = "".join(
        f"<tr><td class='nowrap small'>{_time_cell(row.first)}<div class='muted'>to "
        f"{e(minute(row.last))} UTC</div></td><td class='small'>{e(row.source)}</td>"
        f"<td class='mono small'>{e(row.kind)}: {e(row.what)}</td>"
        f"<td class='num'>{row.minutes if row.minutes is not None else row.flows}</td>"
        f"<td class='num'>{e(size(row.received))}</td><td class='num'>{e(size(row.sent))}</td>"
        f"<td class='num'>{e(duration(row.longest_sec)) if row.longest_sec is not None else '—'}"
        f"</td><td class='small'>{e(row.status)}</td></tr>"
        for row in facts.timeline
    )
    return f"""
<section class="part"><h3>The contact and its long flows</h3>
  <p class="small muted">Each piece of traffic once: a feed item the live re-query holds in full is
  shown as the live copy. Minutes for contacts, flows for long flows.</p>
  <div class="table-wrap"><table class="dense"><thead><tr><th>From</th><th>Source</th><th>What</th>
  <th class="num">Min / flows</th><th class="num">Received</th><th class="num">Sent</th>
  <th class="num">Longest</th><th>Judged</th></tr></thead><tbody>{rows}</tbody></table></div>
</section>"""


# --- after the contact ----------------------------------------------------------------------------


def _after(anchor: str, facts: CaseFacts) -> str:
    after = facts.after
    if after is None:
        return (
            "<section class='part'><h3>After the contact</h3><p class='muted'>Not read: the "
            "first match day is outside the source's minute horizon, or the live source was not "
            "queried.</p></section>"
        )
    named = [d for d in after.new if d.named]
    nameless = [d for d in after.new if not d.named]
    rows = "".join(
        f"<tr><td class='nowrap small'>{_time_cell(d.first_minute)}</td>"
        f"<td class='mono'>{e(d.name)}</td><td class='num'>{d.active_minutes}</td>"
        f"<td class='num'>{e(size(d.down_bytes))}</td><td class='num'>{e(size(d.up_bytes))}"
        f"{' ⬆' if d.up_bytes >= UPLOAD_BYTES else ''}</td><td class='small'>{e(_standing(d))}</td>"
        "</tr>"
        for d in named[:AFTER_LISTED]
    )
    more = (
        f"<p class='small muted'>{len(named) - AFTER_LISTED} more not listed (all in the JSON).</p>"
        if len(named) > AFTER_LISTED
        else ""
    )
    nameless_text = (
        "; ".join(
            f"{d.name} from {minute(d.first_minute)} UTC, {size(d.up_bytes)} sent"
            for d in nameless[:AFTER_LISTED]
        )
        or "none"
    )
    continuity = after.continuity
    continuity_text = (
        f"named destinations shared by the {continuity.span_days} active day(s) before and after "
        f"the match: {continuity.overlap_after:.2f}"
        + (
            f" ({continuity.overlap_before:.2f} between two spans before it)"
            if continuity.overlap_before is not None
            else ""
        )
        + "; no traffic with a known remote address on "
        f"{continuity.silent_after} of {continuity.days_after} later "
        "day(s); named on every active day before and on none after: "
        + (", ".join(continuity.habitual_missing[:12]) or "none")
        if continuity is not None
        else "not enough active days on both sides to compare"
    )
    table = (
        f"""<div class="table-wrap"><table class="dense"><thead><tr><th>First seen</th>
  <th>New destination</th><th class="num">Min</th><th class="num">Received</th>
  <th class="num">Sent</th>
  <th>Campus standing before the match</th></tr></thead><tbody>{rows}</tbody></table></div>{more}"""
        if named
        else "<p>No named destination was new to this host after the first match.</p>"
    )
    return f"""
<section class="part"><h3>After the contact</h3>
  <p class="small muted">Every destination the host exchanged traffic with, in either direction,
  on each day the live source still holds ({e(after.first_day)} to {e(after.last_day)}). New means
  not seen earlier in that window and, for a name, not used on any retained day before the first
  match. ⬆ marks an upload of 1 MB or more (CASE_STUDY §8).</p>
  {_chart_days(anchor, facts.days)}
  {table}
  <dl class="facts compact">
    <div><dt>Traffic with no name, new after the match</dt><dd>{prose(nameless_text)}</dd></div>
    <div><dt>Is it still the same device?</dt><dd>{prose(continuity_text)}</dd></div>
  </dl>
</section>"""


def _standing(destination: object) -> str:
    established = getattr(destination, "established", None)
    campus = getattr(destination, "campus_before", None)
    if established is None:
        return "not looked up"
    if established:
        return "established on campus"
    if campus == 0:
        return "no campus use in the 90 days before"
    return f"not established ({campus} campus address(es))"


# --- next steps and coverage ----------------------------------------------------------------------


def _steps(facts: CaseFacts) -> str:
    if not facts.steps:
        return ""
    grouped: dict[str, list[str]] = defaultdict(list)
    for step in facts.steps:
        grouped[step.system].append(step.text)
    blocks = "".join(
        f"<div class='step-group'><h4>{e(SYSTEM_LABEL.get(system, system))}</h4>"
        "<ul class='checklist'>"
        + "".join(
            f"<li><span class='box' aria-hidden='true'></span><span>{prose(text)}</span></li>"
            for text in grouped[system]
        )
        + "</ul></div>"
        for system in (*SYSTEM_ORDER, *(s for s in grouped if s not in SYSTEM_ORDER))
        if system in grouped
    )
    return (
        "<section class='part'><h3>Next steps: what only other systems can settle</h3>"
        f"<div class='steps'>{blocks}</div></section>"
    )


def _case_coverage(facts: CaseFacts) -> str:
    if not facts.coverage:
        return (
            "<section class='part'><h3>What this case could not check</h3>"
            "<p class='small'>Every check ran: live re-query, published stream and retained "
            "5-minute timing.</p></section>"
        )
    items = "".join(
        f"<li><span aria-hidden='true'>⚠</span> {prose(text)}</li>" for text in facts.coverage
    )
    return (
        "<section class='part'><h3>What this case could not check</h3>"
        f"<ul class='gaps small'>{items}</ul></section>"
    )


# --- explained ledger and shadow verdicts ---------------------------------------------------------


def _appendix(results: list[CaseResult]) -> str:
    rows = "".join(
        f"<tr data-kind='{_kind(result)}'><td class='num'><a href='#case-{number}'>{number}</a>"
        f"</td><td class='mono small'>{e(result.evidence.case.indicator)}<div class='muted'>"
        f"{e(result.evidence.case.host)}</div></td><td class='small'>"
        f"{e(result.evidence.case.listing.malware)}</td><td>{_verdict_badge(result)} "
        f"{_rule_badges(result.decision.rules)}</td><td class='small'>{e(model_verdict(result))}"
        f"</td><td class='small'>{prose(would_change(result))}</td></tr>"
        for number, result in enumerate(results, 1)
    )
    check_rows = "".join(
        f"<tr><td>{e(check.name)}</td><td class='small'>{e(check.scope)}</td>"
        f"<td class='small'>{e(check.positive)}</td><td class='small'>{e(check.result)}</td></tr>"
        for check in checks(results)
    )
    counts = rule_counts(results)
    rules = "".join(
        f"<tr><td><span class='rule'>{e(rule)}</span></td><td>{e(meaning)}</td>"
        f"<td class='small muted'>{e(basis)}</td><td class='num'>{counts[rule]}</td></tr>"
        for rule, meaning, basis in RULES
    ) + (
        "<tr><td>—</td><td>review because at least one contact has no explanation</td><td></td>"
        f"<td class='num'>{counts['unexplained']}</td></tr>"
    )
    return f"""
<section class="front" aria-labelledby="appendix-heading">
  <h2 id="appendix-heading" class="section-title">Appendix</h2>
  <h3>A. Every case</h3>
  <div class="table-wrap card"><table class="dense"><thead><tr><th class="num">#</th>
  <th>Indicator / host</th><th>Listing</th><th>Code</th><th>Blind model</th>
  <th>What would change the reading</th></tr></thead><tbody>{rows}</tbody></table></div>
  <h3>B. The checks behind every verdict</h3>
  <div class="table-wrap card"><table class="dense"><thead><tr><th>Check</th><th>Scope</th>
  <th>A positive would be</th><th>Result</th></tr></thead><tbody>{check_rows}</tbody></table></div>
  <h3>C. The rules</h3>
  <div class="table-wrap card"><table class="dense"><thead><tr><th>Rule</th><th>Meaning</th>
  <th>Basis</th><th class="num">Cases</th></tr></thead><tbody>{rules}</tbody></table></div>
  {_shadow(results)}
</section>"""


def _shadow(results: list[CaseResult]) -> str:
    asked = [result for result in results if result.shadow is not None]
    if not asked:
        return ""
    shadow_model = asked[0].shadow.model if asked[0].shadow else ""
    counts = "".join(
        f"<tr><td>{e(key)}</td><td class='num'>{value}</td></tr>"
        for key, value in sorted(shadow_counts(results).items())
    )
    rows = []
    for result in shadow_worth_a_look(results):
        shadow = result.shadow
        assert shadow is not None
        case = result.evidence.case
        votes = ", ".join(sample.verdict for sample in shadow.samples) or "none"
        reason = shadow.samples[0].reasoning if shadow.samples else "; ".join(shadow.errors)
        rows.append(
            f"<tr><td class='mono small'>{e(case.indicator)}<div class='muted'>{e(case.host)}"
            f"</div></td><td>{e(result.disposition)}</td><td>{e(shadow.majority or 'split')} "
            f"<span class='muted small'>({e(votes)})</span></td><td class='small'>{e(reason)}</td>"
            "</tr>"
        )
    disagreements = (
        "<div class='table-wrap'><table><thead><tr><th>Indicator / host</th><th>Code</th>"
        "<th>Model (samples)</th><th>Model's reasoning (first sample)</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
        if rows
        else "<p>Every shadow verdict agreed with code, unanimously.</p>"
    )
    return f"""
<section class="ledger"><h2>Shadow verdicts <span class="muted small">({e(shadow_model)}, blind,
  not applied)</span></h2>
  <p class="small muted">The model read each case file with the decision and every rule outcome
  removed. Its verdicts change nothing; a disagreement marks a case worth a second look.</p>
  <div class="table-wrap card"><table><thead><tr><th>Outcome</th><th class="num">Cases</th></tr>
  </thead><tbody>{counts}</tbody></table></div>
  {disagreements}
</section>"""


# --- small pieces ---------------------------------------------------------------------------------


def _rule_badges(rules: Sequence[str]) -> str:
    return "".join(
        f"<span class='rule' title='{e(RULE_MEANING.get(rule, rule))}'>{e(rule)}</span>"
        for rule in rules
    )


def _time_cell(value: datetime) -> str:
    local = local_time(value)
    return f"{e(minute(value))} UTC" + (
        f"<div class='muted'>{e(local[0])} {e(local[1])}</div>" if local else ""
    )


def _times_note() -> str:
    zone = report_zone()
    return "Times are UTC." if zone is None else f"Times are UTC with {zone[1]} beside them."


# --- charts (inline SVG; see the dataviz method) --------------------------------------------------


def _nice_max(value: int) -> int:
    if value <= 4:
        return max(value, 1)
    magnitude = int(10 ** (len(str(value)) - 1))
    for step in (1, 2, 5, 10):
        if value <= step * magnitude:
            return step * magnitude
    return value


def _ticks(top: int) -> list[int]:
    """Every whole number up to a small top, else the top and its half: even steps either way."""
    return list(range(top + 1)) if top <= 5 else [0, top // 2, top]


def _column(x: float, y: float, width: float, height: float, rounded: bool) -> str:
    """A column from the baseline up, its data end rounded 4px, square at the baseline."""
    if height <= 0:
        return ""
    r = min(4.0, width / 2, height) if rounded else 0.0
    base = y + height
    if r <= 0:
        return f"M{x:.1f},{base:.1f}V{y:.1f}H{x + width:.1f}V{base:.1f}Z"
    return (
        f"M{x:.1f},{base:.1f}V{y + r:.1f}A{r:.1f},{r:.1f} 0 0 1 {x + r:.1f},{y:.1f}"
        f"H{x + width - r:.1f}A{r:.1f},{r:.1f} 0 0 1 {x + width:.1f},{y + r:.1f}V{base:.1f}Z"
    )


def _stack(
    x: float, baseline: float, width: float, scale: float, parts: list[tuple[int, str, str]]
) -> str:
    """Stacked segments bottom-up with a 2px surface gap; the top one carries the rounded end."""
    nonzero = [(value, css, tip) for value, css, tip in parts if value > 0]
    out = []
    top = baseline
    for index, (value, css, tip) in enumerate(nonzero):
        height = value * scale
        gap = 2.0 if index > 0 else 0.0
        y = top - height
        drawn = height - gap
        if drawn <= 0:
            drawn, gap = height, 0.0
        path = _column(x, y, width, drawn, rounded=index == len(nonzero) - 1)
        out.append(
            f"<path class='mark {css}' d='{path}' tabindex='0' data-tip='{e(tip)}' "
            f"aria-label='{e(tip)}'><title>{e(tip)}</title></path>"
        )
        top = y
    return "".join(out)


def _legend(series: Sequence[tuple[str, str]]) -> str:
    return (
        "<div class='legend'>"
        + "".join(
            f"<span class='key'><span class='swatch {css}' aria-hidden='true'></span>"
            f"{e(label)}</span>"
            for label, css in series
        )
        + "</div>"
    )


def _chart_windows(anchor: str, windows: Sequence[Window]) -> str:
    counts = [_window_counts(window) for window in windows]
    totals = [sum(c.values()) for c in counts]
    top = _nice_max(max(totals, default=0))
    width, height, left, bottom, top_pad = 520, 190, 36, 38, 14
    plot_w, plot_h = width - left - 12, height - bottom - top_pad
    band = plot_w / max(len(windows), 1)
    bar = min(24.0, band * 0.5)
    scale = plot_h / top
    baseline = top_pad + plot_h
    grid = "".join(
        f"<line class='grid' x1='{left}' x2='{width - 12}' y1='{baseline - t * scale:.1f}' "
        f"y2='{baseline - t * scale:.1f}'/><text class='tick' x='{left - 6}' "
        f"y='{baseline - t * scale + 4:.1f}' text-anchor='end'>{t}</text>"
        for t in _ticks(top)
    )
    marks = []
    for index, (window, count, total) in enumerate(zip(windows, counts, totals, strict=True)):
        x = left + band * index + (band - bar) / 2
        label = _window_label(window)
        parts = [
            (count[key], css, f"{count[key]} · {name} · {label} UTC")
            for key, name, css in WINDOW_SERIES
        ]
        marks.append(_stack(x, baseline, bar, scale, parts))
        marks.append(
            f"<text class='value' x='{x + bar / 2:.1f}' y='{baseline - total * scale - 6:.1f}' "
            f"text-anchor='middle'>{total}</text>"
        )
        marks.append(
            f"<text class='axis-label{' strong' if window.position == 'contact' else ''}' "
            f"x='{x + bar / 2:.1f}' y='{baseline + 16}' text-anchor='middle'>{e(label)}</text>"
            f"<text class='axis-sub' x='{x + bar / 2:.1f}' y='{baseline + 30}' "
            f"text-anchor='middle'>{e(window.position)}</text>"
        )
    title = "Destinations in each five-minute window around the contact"
    desc = "; ".join(
        f"{_window_label(w)} UTC ({w.position}): "
        + ", ".join(f"{c[k]} {n}" for k, n, _ in WINDOW_SERIES)
        for w, c in zip(windows, counts, strict=True)
    )
    table = "".join(
        f"<tr><td>{e(_window_label(w))} UTC</td><td>{e(w.position)}</td>"
        + "".join(f"<td class='num'>{c[k]}</td>" for k, _, _ in WINDOW_SERIES)
        + "</tr>"
        for w, c in zip(windows, counts, strict=True)
    )
    head = "".join(f"<th class='num'>{e(n)}</th>" for _, n, _ in WINDOW_SERIES)
    return f"""<figure class="chart-card">
  <figcaption>{e(title)}</figcaption>
  {_legend([(name, css) for _, name, css in WINDOW_SERIES])}
  <div class="chart-scroll"><svg class="chart" width="{width}" height="{height}"
    viewBox="0 0 {width} {height}" role="img"
    aria-labelledby="{anchor}-w-t {anchor}-w-d">
    <title id="{anchor}-w-t">{e(title)}</title><desc id="{anchor}-w-d">{e(desc)}</desc>
    {grid}<line class="axis" x1="{left}" x2="{width - 12}" y1="{baseline}" y2="{baseline}"/>
    {"".join(marks)}
  </svg></div>
  <details class="figure-data"><summary>Table</summary><div class="table-wrap"><table class="dense">
  <thead><tr><th>Window</th><th>Position</th>{head}</tr></thead><tbody>{table}</tbody></table></div>
  </details>
</figure>"""


def _chart_days(anchor: str, days: Sequence[DayPoint]) -> str:
    if not days:
        return ""
    top = _nice_max(max((d.destinations for d in days), default=0))
    width, height, left, bottom, top_pad = 680, 200, 40, 42, 16
    plot_w, plot_h = width - left - 12, height - bottom - top_pad
    band = plot_w / len(days)
    bar = min(24.0, band * 0.6)
    scale = plot_h / top
    baseline = top_pad + plot_h
    grid = "".join(
        f"<line class='grid' x1='{left}' x2='{width - 12}' y1='{baseline - t * scale:.1f}' "
        f"y2='{baseline - t * scale:.1f}'/><text class='tick' x='{left - 6}' "
        f"y='{baseline - t * scale + 4:.1f}' text-anchor='end'>{t}</text>"
        for t in _ticks(top)
    )
    marks = []
    for index, point in enumerate(days):
        x = left + band * index + (band - bar) / 2
        cx = x + bar / 2
        stamp = point.day.strftime("%m-%d")
        if point.match:
            marks.append(
                f"<rect class='match-band' x='{left + band * index:.1f}' y='{top_pad}' "
                f"width='{band:.1f}' height='{plot_h}'/>"
            )
        if point.silent:
            tip = f"no traffic with a known remote address · {point.day}"
            marks.append(
                f"<circle class='mark silent' cx='{cx:.1f}' cy='{baseline - 6}' r='4' tabindex='0' "
                f"data-tip='{e(tip)}' aria-label='{e(tip)}'><title>{e(tip)}</title></circle>"
            )
        else:
            seen = point.destinations - point.new
            marks.append(
                _stack(
                    x,
                    baseline,
                    bar,
                    scale,
                    [
                        (seen, "s0", f"{seen} · other named destinations · {point.day}"),
                        (
                            point.new,
                            "s1",
                            f"{point.new} · new to this host after the match · {point.day}",
                        ),
                    ],
                )
            )
        if point.match and not point.silent:
            label_y = baseline - point.destinations * scale - 6
            marks.append(
                f"<text class='value' x='{cx:.1f}' y='{label_y:.1f}' "
                f"text-anchor='middle'>{point.destinations}</text>"
            )
        marks.append(
            f"<text class='axis-label{' strong' if point.match else ''}' x='{cx:.1f}' "
            f"y='{baseline + 16}' text-anchor='middle'>{stamp}</text>"
        )
        if point.match:
            marks.append(
                f"<text class='axis-sub strong' x='{cx:.1f}' y='{baseline + 30}' "
                "text-anchor='middle'>match</text>"
            )
    title = "Named destinations per day, and what was new to the host after the match"
    desc = "; ".join(
        f"{d.day}: "
        + (
            "no traffic with a known remote address"
            if d.silent
            else f"{d.destinations} named, {d.new} new after match"
        )
        + (" (match day)" if d.match else "")
        for d in days
    )
    table = "".join(
        f"<tr><td>{e(d.day)}{' (match)' if d.match else ''}</td>"
        f"<td class='num'>{d.destinations}</td>"
        f"<td class='num'>{d.new}</td><td>{'yes' if d.silent else ''}</td></tr>"
        for d in days
    )
    legend = _legend(
        [
            ("other named destinations", "s0"),
            ("new to this host after the match", "s1"),
            ("no traffic with a known remote address", "silent"),
        ]
    )
    return f"""<figure class="chart-card">
  <figcaption>{e(title)}</figcaption>
  {legend}
  <div class="chart-scroll"><svg class="chart" width="{width}" height="{height}"
    viewBox="0 0 {width} {height}" role="img"
    aria-labelledby="{anchor}-d-t {anchor}-d-d">
    <title id="{anchor}-d-t">{e(title)}</title><desc id="{anchor}-d-d">{e(desc)}</desc>
    {grid}<line class="axis" x1="{left}" x2="{width - 12}" y1="{baseline}" y2="{baseline}"/>
    {"".join(marks)}
  </svg></div>
  <details class="figure-data"><summary>Table</summary><div class="table-wrap"><table class="dense">
  <thead><tr><th>Day (UTC)</th><th class="num">Named destinations</th><th class="num">New after
  the match</th><th>No traffic</th></tr></thead><tbody>{table}</tbody></table></div></details>
</figure>"""


SCRIPT = """
(function () {
  var filters = document.querySelectorAll('[data-filter]');
  function apply(filter) {
    document.querySelectorAll('[data-kind]').forEach(function (el) {
      el.hidden = !(filter === 'all' || el.dataset.kind.split(' ').indexOf(filter) >= 0);
    });
    filters.forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.dataset.filter === filter));
    });
  }
  filters.forEach(function (b) {
    b.addEventListener('click', function () { apply(b.dataset.filter); });
  });
  var tip = document.getElementById('tip');
  function show(mark, x, y) {
    var parts = (mark.getAttribute('data-tip') || '').split(' · ');
    tip.textContent = '';
    var value = document.createElement('strong');
    value.textContent = parts.shift() || '';
    var label = document.createElement('span');
    label.textContent = parts.join(' · ');
    tip.appendChild(value); tip.appendChild(document.createTextNode(' ')); tip.appendChild(label);
    tip.hidden = false;
    var w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = Math.min(window.innerWidth - w - 8, Math.max(8, x + 12)) + 'px';
    tip.style.top = Math.max(8, y - h - 12) + 'px';
  }
  function hide() { tip.hidden = true; }
  document.querySelectorAll('.mark[data-tip]').forEach(function (mark) {
    mark.addEventListener('pointermove', function (ev) { show(mark, ev.clientX, ev.clientY); });
    mark.addEventListener('pointerleave', hide);
    mark.addEventListener('focus', function () {
      var r = mark.getBoundingClientRect(); show(mark, r.left + r.width / 2, r.top);
    });
    mark.addEventListener('blur', hide);
  });
  window.addEventListener('beforeprint', function () {
    apply('all');
    document.querySelectorAll('details').forEach(function (d) { d.open = true; });
  });
})();
"""

# Colour tokens, one definition per mode: series and surfaces from the dataviz reference palette
# (validated light and dark), status colours kept apart from the series. Print always uses light.
LIGHT = """
  color-scheme: light;
  --page: #f9f9f7; --surface: #fcfcfb; --surface-2: #f2f1ec; --ink: #0b0b0b; --ink2: #52514e;
  --muted: #6f6d67; --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11,11,11,0.10);
  --accent: #1c5cab; --mast: #10213a; --mast-ink: #e8edf4; --mast-muted: #a9b6c7;
  --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a; --s0: #c3c2b7; --silent: #898781;
  --review: #4b3db8; --review-bg: #ecebfb; --warn: #8a5a00; --warn-bg: #fff4dc;
  --warn-line: #fab219; --flag-bg: #eef4fd; --match: rgba(42,120,214,0.08);
"""
DARK = """
  color-scheme: dark;
  --page: #0d0d0d; --surface: #1a1a19; --surface-2: #232321; --ink: #f0efec; --ink2: #c3c2b7;
  --muted: #9c9a92; --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10);
  --accent: #86b6ef; --mast: #0a1526; --mast-ink: #e8edf4; --mast-muted: #8fa0b6;
  --s1: #3987e5; --s2: #d95926; --s3: #199e70; --s0: #4a4a47; --silent: #898781;
  --review: #b1a8f0; --review-bg: #24203d; --warn: #f3c25a; --warn-bg: #2b2310;
  --warn-line: #8a6a1f; --flag-bg: #16263b; --match: rgba(57,135,229,0.12);
"""
THEMES = (
    f":root {{{LIGHT}}}\n"
    f'@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{{DARK}}} }}\n'
    f':root[data-theme="dark"] {{{DARK}}}\n'
)
PRINT = (
    '@media print { :root, :root:not([data-theme="light"]), :root[data-theme="dark"] {'
    + LIGHT
    + "} }"
)

CSS = (
    THEMES
    + """
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--page); color: var(--ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 0 16px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  overflow-wrap: break-word; }
.muted { color: var(--muted); } .small { font-size: 13px; } .nowrap { white-space: nowrap; }
h1, h2, h3, h4 { line-height: 1.25; }
.masthead { background: var(--mast); color: var(--mast-ink); padding: 26px 0 22px; }
.masthead-inner { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;
  flex-wrap: wrap; }
.eyebrow { text-transform: uppercase; letter-spacing: .08em; font-size: 12px;
  color: var(--mast-muted); font-weight: 600; }
.masthead h1 { margin: 4px 0 6px; font-size: 26px; font-weight: 650; }
.masthead .sub { margin: 0; color: var(--mast-muted); font-size: 14px; }
.marking { border: 1px solid var(--mast-muted); border-radius: 4px; padding: 4px 10px;
  font-size: 12px;
  font-weight: 600; text-transform: uppercase; letter-spacing: .06em; white-space: nowrap; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; }
.overview { margin: 22px 0 28px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.tile { all: unset; box-sizing: border-box; cursor: pointer; background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 14px; display: flex; flex-direction: column; gap: 2px;
  border-top: 3px solid var(--axis); }
.tile.static { cursor: default; }
.tile.review { border-top-color: var(--review); }
.tile.caveated { border-top-color: var(--warn-line); }
.tile.checked { border-top-color: var(--s3); }
.tile[aria-pressed="true"] { outline: 2px solid var(--accent); outline-offset: 1px; }
.tile:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.tile-value { font-size: 26px; font-weight: 650; line-height: 1.1; }
.tile-label { color: var(--ink2); font-size: 13px; }
.about { background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 10px 16px;
  margin-top: 12px; font-size: 14px; color: var(--ink2); }
.about > summary { cursor: pointer; font-weight: 600; color: var(--ink); }
.about ul { margin: 8px 0 4px; padding-left: 20px; } .about li { margin: 4px 0; }
.index, .ledger { margin: 28px 0; } .index h2, .ledger h2 { font-size: 19px; margin: 0 0 10px; }
.table-wrap { overflow-x: auto; } .table-wrap > table { min-width: 600px; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--grid);
  vertical-align: top; }
th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted);
  font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.card table tr:last-child td { border-bottom: 0; }
table.dense { font-size: 13px; } table.dense th, table.dense td { padding: 5px 8px; }
tr.flagged td { background: var(--flag-bg); } tr.others td { color: var(--ink2); font-size: 12.5px;
  }
.badge { display: inline-block; font-weight: 650; font-size: 12.5px; padding: 2px 10px;
  border-radius: 999px; }
.badge.review { color: var(--review); background: var(--review-bg); }
.badge.explained { color: var(--ink2); background: var(--surface-2); }
.pill { display: inline-block; font-size: 12.5px; padding: 2px 10px; border-radius: 999px;
  border: 1px solid var(--border); color: var(--ink2); white-space: nowrap; }
.pill.warn { color: var(--warn); background: var(--warn-bg); border-color: transparent; }
.rule { display: inline-block; font: 600 12px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace;
  padding: 0 6px; margin: 0 4px 2px 0; border-radius: 4px; background: var(--surface-2);
    color: var(--ink); }
.src { display: inline-block; font-size: 11.5px; font-weight: 600; text-transform: uppercase;
  letter-spacing: .03em;
  color: var(--ink2); background: var(--surface-2); border-radius: 4px; padding: 0 6px;
    margin-right: 6px; }
.case { padding: 22px 26px; margin: 0 0 26px; }
.kicker { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted);
  font-weight: 600; }
.case-title { margin: 6px 0 2px; font-size: 21px; font-weight: 600; overflow-wrap: anywhere; }
.case-sub { margin: 0 0 10px; color: var(--ink2); font-size: 14px; }
.pills { display: flex; gap: 6px; flex-wrap: wrap; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 10px 22px;
  margin: 16px 0 0;
  padding: 12px 16px; background: var(--surface-2); border-radius: 8px; }
.facts.compact { grid-template-columns: 1fr; }
.facts dt { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em;
  font-weight: 600; }
.facts dd { margin: 2px 0 0; font-size: 14px; overflow-wrap: anywhere; }
.part { margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--grid); }
.part > h3 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted);
  margin: 0 0 8px; }
.part.lead { border-top: 0; padding: 14px 18px; background: var(--surface-2); border-radius: 8px;
  border-left: 4px solid var(--review); }
ul.notable, ul.kept { margin: 6px 0 0; padding-left: 0; list-style: none; }
ul.notable li, ul.kept li { margin: 8px 0; max-width: 92ch; }
blockquote.model { margin: 6px 0; padding: 8px 14px; border-left: 3px solid var(--axis);
  color: var(--ink); max-width: 92ch; }
.background, .appendix, .figure-data { margin-top: 10px; }
.background > summary, .appendix > summary, .figure-data > summary { cursor: pointer;
  color: var(--accent); font-size: 13.5px; }
.casefile { font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap;
  background: var(--surface-2);
  border-radius: 6px; padding: 10px 12px; overflow-x: auto; }
.steps { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 8px 22px;
  }
.step-group h4 { margin: 8px 0 4px; font-size: 14px; }
ul.checklist { list-style: none; padding: 0; margin: 0; } ul.checklist li { display: flex; gap: 8px;
  margin: 6px 0; font-size: 14px; }
.box { flex: 0 0 auto; width: 14px; height: 14px; margin-top: 3px; border: 1.5px solid var(--axis);
  border-radius: 3px; }
ul.gaps { padding-left: 4px; list-style: none; } ul.gaps li { margin: 4px 0; }
details.row > summary { cursor: pointer; list-style: none; }
details.row > summary::-webkit-details-marker { display: none; }
details.row[open] { padding-bottom: 4px; }
.case-foot { margin: 16px 0 0; font-size: 13px; }
.page-foot { color: var(--muted); font-size: 13px; padding: 8px 16px 40px; }
.chart-card { margin: 10px 0 14px; }
.chart-card figcaption { font-weight: 600; font-size: 14px; }
.legend { display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 6px 0 2px; font-size: 12.5px;
  color: var(--ink2); }
.key { display: inline-flex; align-items: center; gap: 6px; }
.swatch { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
.swatch.s0 { background: var(--s0); } .swatch.s1 { background: var(--s1); }
.swatch.s2 { background: var(--s2); }
.swatch.s3 { background: var(--s3); } .swatch.silent { background: var(--surface);
  border: 1.5px solid var(--silent); border-radius: 50%; }
.chart-scroll { overflow-x: auto; } svg.chart { display: block; }
svg .grid { stroke: var(--grid); stroke-width: 1; } svg .axis { stroke: var(--axis);
  stroke-width: 1; }
svg .tick, svg .axis-sub { fill: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums;
  }
svg .axis-label { fill: var(--ink2); font-size: 11px; } svg .strong { font-weight: 700;
  fill: var(--ink); }
svg .value { fill: var(--ink2); font-size: 11px; font-weight: 600; }
svg .mark { outline: none; } svg .mark:hover, svg .mark:focus { opacity: .8; }
svg .mark:focus-visible { stroke: var(--ink); stroke-width: 1.5; }
svg .s0 { fill: var(--s0); } svg .s1 { fill: var(--s1); } svg .s2 { fill: var(--s2); }
svg .s3 { fill: var(--s3); }
svg .silent { fill: var(--surface); stroke: var(--silent); stroke-width: 1.5; }
svg .match-band { fill: var(--match); }
.tip { position: fixed; z-index: 10; pointer-events: none; background: var(--surface);
  color: var(--ink2);
  border: 1px solid var(--border); border-radius: 6px; padding: 4px 8px; font-size: 12.5px;
  box-shadow: 0 2px 8px rgba(0,0,0,.12); }
.tip strong { color: var(--ink); }
.section-title { font-size: 21px; margin: 34px 0 12px; }
.front, .cases { margin: 8px 0 26px; }
.front > h3 { font-size: 16px; margin: 20px 0 8px; }
.card.padded { padding: 14px 20px; }
.lede { padding: 14px 20px; margin: 0 0 14px; border-left: 4px solid var(--accent); }
.lede p { margin: 4px 0; max-width: 92ch; font-size: 15.5px; }
.byline { margin: 6px 0 0; font-style: italic; }
.threat + .threat { border-top: 1px solid var(--grid); }
.threat h3 { font-size: 16px; margin: 10px 0 4px; }
.threat p { margin: 4px 0 10px; max-width: 92ch; }
.group { margin: 0 0 16px; } .group h3 { font-size: 16px; margin: 4px 0 8px; }
.group > p { max-width: 92ch; }
.part.lead.explained, .part.lead.caveated, .part.lead.checked { border-left-color: var(--s3); }
.part.lead.caveated { border-left-color: var(--warn-line); }
.part.lead h4 { margin: 0 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); }
dl.story { margin: 0; }
dl.story > div { display: grid; grid-template-columns: 130px 1fr; gap: 16px; margin: 0 0 10px; }
dl.story dt { font-weight: 650; font-size: 14px; } dl.story dd { margin: 0; max-width: 88ch; }
@media (max-width: 640px) {
  dl.story > div { grid-template-columns: 1fr; gap: 2px; }
  .case { padding: 16px 14px; } .masthead h1 { font-size: 21px; }
}
@media (forced-colors: active) {
  svg .mark { forced-color-adjust: none; }
}
@media print {
  body { background: #fff; } .tiles button { pointer-events: none; } .tip { display: none; }
  .case { break-before: page; border: 0; } .masthead { background: none; color: #000; }
  .masthead .eyebrow, .masthead .sub { color: #3a3a38; }
  .marking { color: #000; border-color: #000; }
  h2, h3, figcaption { break-after: avoid; } tr, figure, .facts > div { break-inside: avoid; }
  .table-wrap, .chart-scroll { overflow: visible; } .table-wrap > table { min-width: 0; }
}
"""
    + PRINT
)
