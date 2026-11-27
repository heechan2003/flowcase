"""`ioc-report FEED.json`: one report per IOC-match feed. `ioc-case-report REPORT.json`: a short PDF
per case, from a report that run wrote."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path

import duckdb
from network_behaviour.config import ConfigurationError, SourceConfig, load_default_environment
from network_behaviour.time import UtcDay

from ioc_report import registration
from ioc_report.case_report import (
    CaseReportError,
    Written,
    load_report,
    select_cases,
    write_case_reports,
)
from ioc_report.casefile import after_contact, next_steps, observed_shapes, render_case_file
from ioc_report.contact import build_evidence
from ioc_report.digest import case_digest
from ioc_report.feed import Case, FeedError, load_feeds, load_listing_dates, with_listing_dates
from ioc_report.history import (
    HistoryError,
    ServiceKey,
    read_history,
    read_name_use,
    read_serving,
    sni_service,
)
from ioc_report.knowledge import (
    ECH_OUTER_NAMES,
    LISTINGS,
    THREATFOX,
    Listing,
    clean,
    family_profile,
    listing_for,
    name_facts,
)
from ioc_report.live import (
    MINUTE_HORIZON_DAYS,
    LiveContext,
    LiveSession,
    after_rows,
    minute_horizon,
    plan_days,
)
from ioc_report.model import ModelClient, ModelError, OllamaClient, OllamaConfig
from ioc_report.narrative import NOT_WRITTEN, Narrative, Writer, restore
from ioc_report.openrouter import OpenRouterClient, OpenRouterConfig
from ioc_report.registration import NameAge
from ioc_report.report import CaseResult, write_report
from ioc_report.rules import C2_THREAT_TYPES, REVIEW, decide
from ioc_report.shadow import SHADOW_SEEDS, ShadowVerdict, shadow_verdict
from ioc_report.summary import case_groups, feed_digest, group_digest, observed_union, ordered
from ioc_report.text import HOST_TOKEN, without_addresses

# The only external model that passed the original `evals/` run (README, "Evaluating model
# verdicts"). `.env` need not name it.
CHOSEN_MODEL = "anthropic/claude-haiku-5.5"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        load_default_environment()
        if len(args.feeds) > 1 and not args.name:
            raise ConfigurationError("several feed files make one report: name it with --name")
        feed = load_feeds(args.feeds, args.listing)
        if not feed.cases:
            raise FeedError(_no_usable_record(feed.rejected[0].reason if feed.rejected else ""))
        cases = feed.cases[: args.limit] if args.limit else feed.cases
        # The feed carries no ThreatFox dates (its first_seen/last_seen are the match window);
        # the metadata file `ioc-match` writes supplies them when present.
        if args.listing is THREATFOX:
            cases = with_listing_dates(
                cases,
                load_listing_dates(
                    Path(
                        os.environ.get("IOC_METADATA_PATH", "").strip() or "data/ioc_metadata.json"
                    )
                ),
            )
        store = _required_path("NETWORK_BEHAVIOUR_DUCKDB_PATH")
        _probe_store(store)
        if args.shadow and args.no_model:
            raise ConfigurationError("--shadow needs the model; drop --no-model")
        # The writer turns every case into prose; the verdict client gives the blind shadow
        # verdict. They differ when the evaluated remote model judges and the local one writes.
        client: ModelClient | None = None
        verdicts: ModelClient | None = None
        # Writes the case PDFs. A run already paying OpenRouter shares its client, so --budget caps
        # the whole run. With --no-model the PDFs hold code's own text, as every other page does.
        reports: ModelClient | None = None
        if not args.no_model:
            client = _model_client(os.environ, args.budget)
            verdicts = (
                _model_client(os.environ, args.budget, "SHADOW_PROVIDER")
                if args.shadow
                and _provider(os.environ, "SHADOW_PROVIDER")
                != _provider(os.environ, "MODEL_PROVIDER")
                else client
            )
            if args.case_reports:
                reports = next(
                    (found for found in (client, verdicts) if isinstance(found, OpenRouterClient)),
                    None,
                ) or _case_report_client(os.environ, args.budget)
            for found in dict.fromkeys((client, verdicts, reports)):
                if found is None:
                    continue
                found.require_model()
                if isinstance(found, OpenRouterClient):
                    _require_credit(found)
        now = datetime.now(UTC)
        # Read even with --no-live: the retention it declares shapes the advice on re-querying.
        config = SourceConfig.from_env()
        source = None if args.no_live else config
        if source is not None:
            _preflight(cases, now, minute_horizon(source))
        session = (
            LiveSession(None, retention_days=config.detail_days)
            if source is None
            else LiveSession.connect(source)
        )
    except (ConfigurationError, FeedError, HistoryError, ModelError) as exc:
        print(f"ioc-report: {exc}", file=sys.stderr)
        return 2

    with session:
        live = (
            LiveContext(status="skipped", retention_days=session.retention_days)
            if args.no_live
            else session.gather(cases, now)
        )
        if live.status == "unavailable":
            if any(isinstance(found, OpenRouterClient) for found in (client, verdicts, reports)):
                print(
                    f"ioc-report: live source unavailable ({live.error}). A paid run would spend "
                    "credit on cases missing their live contacts: load the match days into the "
                    "source, or pass --no-live to run on the feed and history alone.",
                    file=sys.stderr,
                )
                return 2
            print(
                f"ioc-report: live source unavailable ({live.error}); continuing", file=sys.stderr
            )
        try:
            history = read_history(store, cases, _live_service_keys(cases, live))
        except HistoryError as exc:
            print(f"ioc-report: {exc}", file=sys.stderr)
            return 2
        registrations = _registrations(cases, live, os.environ)
        evidence = {
            case: build_evidence(
                case, feed, live, history.cases[(case.indicator, case.host)], registrations
            )
            for case in cases
        }
        decisions = {case: decide(evidence[case], feed.domain_indicators) for case in cases}
        review = [case for case in cases if decisions[case].disposition == REVIEW]
        live = session.add_host_context(live, review)
        live = session.add_destinations(live, review)
        if requests := _context_names(review, live):
            try:
                history = replace(history, names=read_name_use(store, requests))
            except HistoryError as exc:
                print(f"ioc-report: context names left unranked ({exc})", file=sys.stderr)
        serving = {}
        if args.listing.advisories:
            # A list tied to an advisory: say which hosts serve a named site.
            try:
                serving = read_serving(store)
            except HistoryError as exc:
                print(f"ioc-report: serving not read ({exc})", file=sys.stderr)

    # The second opinion's prompt and evaluation are about ThreatFox cases.
    ask_second = bool(args.shadow) and verdicts is not None and args.listing is THREATFOX
    if args.shadow and not ask_second:
        print(
            "ioc-report: no second opinion on this list: it has only been evaluated on "
            f"{THREATFOX.source} cases",
            file=sys.stderr,
        )
    results = []
    for number, case in enumerate(cases, 1):
        decision = decisions[case]
        second: ShadowVerdict | None = None
        if ask_second and verdicts is not None:
            blind = render_case_file(evidence[case], decision, live, history, blind=True)
            second = shadow_verdict(pseudonymise(blind, case), verdicts, args.shadow)
        print(
            f"case {number}/{len(cases)}: {decision.disposition} ({', '.join(decision.rules)})"
            + (f"; shadow {second.majority or 'split'}" if second is not None else ""),
            file=sys.stderr,
        )
        steps = (
            next_steps(evidence[case], decision, after_contact(evidence[case], live, history))
            if decision.disposition == REVIEW
            else ()
        )
        results.append(
            CaseResult(
                evidence[case],
                decision,
                render_case_file(evidence[case], decision, live, history),
                next_steps=steps,
                shadow=second,
                digest=case_digest(
                    evidence[case], decision, live, history, second, serving.get(case.host)
                ),
            )
        )

    results = ordered(results)
    writer = (
        Writer(client, args.out / ".model-cache", progress=_progress)
        if client is not None
        else None
    )
    results = [
        replace(result, overview=_overview(writer, result, number, len(results)))
        for number, result in enumerate(results, 1)
    ]
    groups = case_groups(results)
    if writer is not None:
        groups = [
            replace(
                group,
                narrative=writer.group(
                    group_digest(group),
                    observed_union(group.results),
                    group.disposition,
                    f"group {index}/{len(groups)}",
                    source=args.listing.source,
                ),
            )
            for index, group in enumerate(groups, 1)
        ]
    summary = (
        writer.feed(
            feed_digest(feed, results, groups, live, history),
            observed_union(results),
            "summary",
            source=args.listing.source,
        )
        if writer is not None
        else NOT_WRITTEN
    )

    model_label = "no model (--no-model)" if client is None else client.label
    name = args.name or args.feeds[0].stem
    markdown, data = write_report(
        args.out, name, feed, results, live, history, model_label, now, groups, summary
    )
    count = sum(1 for result in results if result.disposition == REVIEW)
    print(
        f"wrote {markdown} (also {data.name}): {len(results)} case(s), "
        f"{count} review, {len(results) - count} explained"
    )
    if args.case_reports:
        try:
            saved = load_report(data)
            _say_written(
                write_case_reports(saved, select_cases(saved, None), args.out, reports, _progress),
                asked=reports is not None,
            )
        except CaseReportError as exc:
            print(f"ioc-report: {exc}", file=sys.stderr)
            return 1
    for paid in dict.fromkeys((client, verdicts, reports)):
        if isinstance(paid, OpenRouterClient):
            print(f"OpenRouter reported ${paid.spent:.4f} of the ${paid.budget:.2f} budget")
    return 0


def case_main(argv: Sequence[str] | None = None) -> int:
    """`ioc-case-report REPORT.json`: a PDF for each review case in a finished run, or for the cases
    named. It reads only that file, so it needs no live source and no retained store."""
    args = _case_parser().parse_args(argv)
    client: OpenRouterClient | None = None
    try:
        load_default_environment()
        report = load_report(args.report)
        cases = select_cases(report, args.case)
        if not cases:
            print("no review case in this report; name one with --case to write an explained one")
            return 0
        if not args.no_model:
            client = _case_report_client(os.environ, args.budget)
            client.require_model()
            _require_credit(client)
        written = write_case_reports(
            report, cases, args.out or args.report.parent, client, _progress
        )
    except (ConfigurationError, CaseReportError, ModelError) as exc:
        print(f"ioc-case-report: {exc}", file=sys.stderr)
        return 2
    _say_written(written, asked=client is not None)
    if client is not None:
        print(f"OpenRouter reported ${client.spent:.4f} of the ${client.budget:.2f} budget")
    # A PDF that fell back to code's text is not what was asked for.
    return 1 if client is not None and not all(w.narrative.by_model for w in written) else 0


def _say_written(written: Sequence[Written], *, asked: bool) -> None:
    """Counts and the folder only: what the text says stays in the files, and a review case's file
    name holds its host and indicator."""
    if not written:
        print("no review case: no case report written")
    for found in written:
        narrative = found.narrative
        author = narrative.written_by if narrative.by_model else "code's plain text"
        print(
            f"wrote a PDF and its audit file to {found.pdf.parent}: case {found.number}, "
            f"{found.disposition}, {found.words} words, by {author}"
        )
        if asked and not narrative.by_model:
            print(
                f"case report {found.number}: no reply passed the checks, so this PDF holds code's "
                "plain text. Run it again, or edit it before sending it; its audit file says why.",
                file=sys.stderr,
            )
        if not found.family_described:
            print(
                f"case report {found.number}: no cited description of its family, so its Threat "
                "paragraph rests on the listing alone; add one to knowledge.REPORT_FAMILIES.",
                file=sys.stderr,
            )
    if written and not asked:
        print(
            "these PDFs hold code's plain text (--no-model): a layout preview, not for submission"
        )


def _overview(writer: Writer | None, result: CaseResult, number: int, total: int) -> Narrative:
    """The case's overview from its digest, pseudonymised on the way out and restored after."""
    if writer is None or result.digest is None:
        return NOT_WRITTEN
    case = result.evidence.case
    found = writer.case(
        pseudonymise(result.digest.text(), case),
        observed_shapes(result.evidence),
        result.disposition,
        f"overview {number}/{total}",
        source=case.listing.source,
    )
    return restore(found, {HOST_TOKEN: case.host})


def _no_usable_record(reason: str) -> str:
    others = ", ".join(sorted(key for key in LISTINGS if key != THREATFOX.key))
    return (
        f"the feed has no usable record ({reason or 'it is empty'}). If it comes from another "
        f"list, name it with --listing (known: {others})"
    )


def _progress(message: str) -> None:
    print(f"ioc-report: {message}", file=sys.stderr)


def pseudonymise(text: str, case: Case) -> str:
    """The case's internal address never reaches a model: the model reads HOST instead."""
    return without_addresses(text, {case.host, case.source_host})


def _provider(env: Mapping[str, str], setting: str) -> str:
    """`SHADOW_PROVIDER` falls back to `MODEL_PROVIDER`, and that to the local model."""
    value = env.get(setting, "").strip().lower()
    if not value and setting == "SHADOW_PROVIDER":
        return _provider(env, "MODEL_PROVIDER")
    return value or "ollama"


def _model_client(
    env: Mapping[str, str], budget: float | None, setting: str = "MODEL_PROVIDER"
) -> ModelClient:
    provider = _provider(env, setting)
    if provider == "ollama":
        return OllamaClient(OllamaConfig.from_env(env))
    if provider == "openrouter":
        if budget is None:
            raise ConfigurationError(
                f"{setting}=openrouter needs --budget USD: the credit is fixed"
            )
        return OpenRouterClient(OpenRouterConfig.from_env(env), budget=budget)
    raise ConfigurationError(f"{setting} must be ollama or openrouter")


def _case_report_client(env: Mapping[str, str], budget: float | None) -> OpenRouterClient:
    """Case reports are written through OpenRouter, whatever writes the rest of the report."""
    if budget is None:
        raise ConfigurationError(
            "case reports use OpenRouter and need --budget USD: the credit is fixed "
            "(--no-model previews them in code's own text, free)"
        )
    model = env.get("OPENROUTER_MODEL", "").strip() or CHOSEN_MODEL
    return OpenRouterClient(
        OpenRouterConfig.from_env({**env, "OPENROUTER_MODEL": model}), budget=budget
    )


def _require_credit(client: OpenRouterClient) -> None:
    """Fail before any query if the account cannot cover the whole budget."""
    left = client.credits_remaining()
    print(f"OpenRouter credit remaining: ${left:.4f}", file=sys.stderr)
    if client.budget is None or left < client.budget:
        raise ConfigurationError("the OpenRouter credit is less than --budget; not running")


def _live_service_keys(
    cases: Sequence[Case], live: LiveContext
) -> dict[tuple[str, str], list[ServiceKey]]:
    """Names seen only in live contact still need their retained history."""
    keys: dict[tuple[str, str], list[ServiceKey]] = {}
    for case in cases:
        for server in case.server_ips:
            for found in live.contacts.get((case.source_host, server), ()):
                if (key := sni_service(server, found.sni)) is not None:
                    keys.setdefault((case.indicator, case.host), []).append(key)
    return keys


def _context_names(review: Sequence[Case], live: LiveContext) -> list[tuple[str, date, str]]:
    """(canonical host, first match day, name) for every name a review case's context lines or
    after-contact lines show: their retained use ranks and marks those lines."""
    requests: dict[tuple[str, date, str], None] = {}
    for case in review:
        names = [row.root_domain for row in (live.host_context or {}).get(case.source_host, ())]
        names += [row.root_domain for row in after_rows(live, case)]
        for name in names:
            if name:
                requests[(case.host, case.days[0], name)] = None
    return list(requests)


def _preflight(
    cases: Sequence[Case], now: datetime, horizon_days: int | None = MINUTE_HORIZON_DAYS
) -> None:
    """Say up front how much of the feed the live source can still check."""
    queried, _expired = plan_days(cases, UtcDay.latest_completed(now), horizon_days)
    inside = sum(1 for case in cases if all(day in queried for day in case.days))
    none = sum(1 for case in cases if not any(day in queried for day in case.days))
    print(
        f"ioc-report: {inside} of {len(cases)} case(s) have every match day inside the source's "
        f"minute window; {none} have none and rest on the feed's own minutes",
        file=sys.stderr,
    )


def _registrations(
    cases: Sequence[Case], live: LiveContext, env: Mapping[str, str]
) -> dict[str, NameAge] | None:
    """Registration dates over RDAP, only when `NAME_LOOKUP=rdap`. None means not looked up."""
    if not registration.enabled(env):
        return None
    cache = env.get("RDAP_CACHE_DIR", "").strip()
    lookup = registration.RdapLookup(Path(cache) if cache else registration.DEFAULT_CACHE_DIR)
    found = lookup.lookup(lookup_domains(cases, live))
    known = sum(1 for age in found.values() if age.registered is not None)
    print(
        f"ioc-report: RDAP: {len(found)} registered domain(s), {known} with a registration date; "
        f"{lookup.requests} request(s) sent",
        file=sys.stderr,
    )
    return found


def lookup_domains(cases: Sequence[Case], live: LiveContext) -> set[str]:
    """The registered domains E3 could rest on, and every flagged domain. Nothing else is sent."""
    domains: set[str] = set()
    for case in cases:
        if case.is_domain and (own := name_facts(case.indicator).registered) is not None:
            domains.add(own)
        claim = case.consistent_claim
        family = family_profile(claim.malware) if claim is not None else None
        if (
            claim is None
            or claim.threat_type not in C2_THREAT_TYPES
            or family is None
            or family.c2_tls is not False
        ):
            continue
        names = {row.sni for row in case.rows} | {
            found.sni
            for server in case.server_ips
            for found in live.contacts.get((case.source_host, server), ())
        }
        for name in names:
            if not name or clean(name) in ECH_OUTER_NAMES:
                continue
            if (domain := name_facts(name).registered) is not None:
                domains.add(domain)
    return domains


def _probe_store(path: Path) -> None:
    """Fail before any query if the retained store cannot be opened read-only."""
    if not path.is_file():
        raise HistoryError(f"retained store not found at {path}")
    try:
        duckdb.connect(str(path), read_only=True).close()
    except duckdb.Error as exc:
        raise HistoryError(
            "cannot open the retained store read-only; the publisher may be running"
        ) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc-report",
        description="Decide each IOC match in code, explain the ordinary ones in a ledger, and "
        "write the rest up for review.",
    )
    parser.add_argument(
        "feeds",
        type=Path,
        nargs="+",
        metavar="feed",
        help="IOC-match feed file(s); give both halves of a split export to run them as one",
    )
    parser.add_argument(
        "--out", type=Path, default=Path("output"), help="report directory (default: output/)"
    )
    parser.add_argument(
        "--name", help="report file name; required with several feed files (default: the feed's)"
    )
    parser.add_argument("--no-live", action="store_true", help="do not query the live source")
    parser.add_argument(
        "--no-model", action="store_true", help="no model summary; decisions are unchanged"
    )
    parser.add_argument("--limit", type=_positive, help="only the first N cases, by first match")
    parser.add_argument(
        "--shadow",
        type=_samples,
        default=0,
        metavar="N",
        help="also ask the model for a blind verdict on every case, N samples each; recorded "
        "beside the decision, never applied",
    )
    parser.add_argument(
        "--budget",
        type=_dollars,
        metavar="USD",
        help="hard cap on OpenRouter spend for this run; required with MODEL_PROVIDER=openrouter "
        "and with --case-reports",
    )
    parser.add_argument(
        "--listing",
        type=_listing,
        default=THREATFOX,
        metavar="KEY",
        help="the list these records come from, one of "
        f"{', '.join(sorted(LISTINGS))} (default: {THREATFOX.key})",
    )
    parser.add_argument(
        "--case-reports",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="also write a short PDF for each review case, through OpenRouter (default: off)",
    )
    return parser


def _case_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc-case-report",
        description="Write a short PDF for each review case in a finished ioc-report run, or for "
        "the cases named.",
    )
    parser.add_argument(
        "report", type=Path, metavar="report.json", help="the JSON file an ioc-report run wrote"
    )
    parser.add_argument(
        "--case",
        type=_positive,
        action="append",
        metavar="N",
        help="the case numbered N in that report, review or explained; repeat for several "
        "(default: every review case)",
    )
    parser.add_argument(
        "--out", type=Path, help="directory for the PDFs (default: beside the report)"
    )
    parser.add_argument(
        "--budget", type=_dollars, metavar="USD", help="hard cap on OpenRouter spend; required"
    )
    parser.add_argument(
        "--no-model",
        action="store_true",
        help="no model and no spend: a layout preview in code's own text",
    )
    return parser


def _listing(raw: str) -> Listing:
    try:
        return listing_for(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _positive(raw: str) -> int:
    value = int(raw)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def _dollars(raw: str) -> float:
    value = float(raw)
    if not value > 0:
        raise argparse.ArgumentTypeError("must be a positive amount")
    return value


def _samples(raw: str) -> int:
    value = _positive(raw)
    if value > len(SHADOW_SEEDS):
        raise argparse.ArgumentTypeError(f"at most {len(SHADOW_SEEDS)} samples")
    return value


def _required_path(name: str) -> Path:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"{name} is required (see .env.example)")
    return Path(value)


if __name__ == "__main__":
    raise SystemExit(main())
