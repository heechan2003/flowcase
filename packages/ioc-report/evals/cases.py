"""The evaluation set: synthetic cases with a known answer under the project's policy.

Every case is built the way `tests/test_rules.py` builds its fixtures, from documentation-range
hosts and invented names, so nothing here is campus data. Each case carries the answer the policy
gives (`expected`) and the rule behind it. Twins (`pair`) differ in one decisive fact. Knowledge
cases are ones the rules leave in review because `knowledge.py` has no cited profile for the
family; their expected answer comes from the cited public sources instead.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from ioc_report.casefile import Observed, observed_shapes, render_case_file
from ioc_report.cli import pseudonymise
from ioc_report.contact import build_evidence
from ioc_report.feed import Case, Feed, load_feed
from ioc_report.history import CaseHistory, Coverage, HistoryContext, ServiceHistory
from ioc_report.live import LiveContext, PairContact
from ioc_report.registration import OK, NameAge
from ioc_report.rules import SHARED_MIN_DOMAINS, decide
from tests.builders import FIRST_MATCH, established
from tests.conftest import long_flow, minute_row, record, write_feed

HOST = "192.0.2.10"
NEIGHBOUR = "192.0.2.200"
CDN = "104.16.132.229"
VPS = "45.77.10.20"
BORE = "159.223.171.199"
DAY = FIRST_MATCH.isoformat()
ORGS = {"13335": "Cloudflare, Inc.", "16509": "Amazon.com, Inc.", "20473": "The Constant Company",
        "14061": "DigitalOcean, LLC"}  # fmt: skip
ORDINARY = "www.weatherzone.com.au"
RARE = "api.kiwi-garden-supplies.com"
ASYNCRAT_SOURCES = (
    "https://censys.com/blog/asyncrat-c2-activity-at-internet-scale",
    "https://www.activecountermeasures.com/malware-of-the-day-asyncrat/",
)
NJRAT_SOURCES = (
    "https://netresec.com/?b=2541a39",
    "https://lmntrix.com/blog/the-rat-is-back-our-latest-njrat-sample-analysis/",
)


@dataclass(frozen=True, slots=True)
class EvalCase:
    id: str
    group: str
    """"must_clear", "must_review" or "knowledge"."""
    expected: str
    rule: str
    """The policy reason for `expected`."""
    case_file: str
    """Blind and pseudonymised: exactly what the model reads."""
    code: str
    """What `rules.decide` says. Equal to `expected` except on knowledge cases."""
    observed: Observed
    pair: str | None = None
    sources: tuple[str, ...] = ()


def _row(
    minute: str,
    server: str = CDN,
    *,
    asn: str = "13335",
    host: str = HOST,
    **kwargs: Any,
) -> dict[str, Any]:
    row = minute_row(f"{DAY} {minute}", host=host, server=server, asn=asn, **kwargs)
    row["asn_organization"] = ORGS.get(asn, "")
    row["country"] = "United States"
    return row


def _neighbours(server: str = CDN) -> dict[str, Any]:
    """Another feed host whose traffic makes `server` carry enough registered domains to count as
    shared hosting (CASE_STUDY §14)."""
    rows = [
        _row("07:00:00", server, host=NEIGHBOUR, sni=f"www.site{n}.com", root=f"site{n}.com")
        for n in range(SHARED_MIN_DOMAINS)
    ]
    return record(rows, indicator=f"{server}:443", indicator_type="ip:port", host=NEIGHBOUR)


def _seen(
    name: str, server: str = CDN, *, addresses: int, days: int, asn: int = 13335
) -> ServiceHistory:
    return established(name, server, addresses=addresses, days=days, asns=frozenset({asn}))


def _ip(server: str = CDN, port: int = 443) -> dict[str, Any]:
    return {"indicator": f"{server}:{port}", "indicator_type": "ip:port"}


@dataclass(frozen=True, slots=True)
class _Spec:
    id: str
    group: str
    expected: str
    rule: str
    records: Callable[[], list[dict[str, Any]]]
    services: Callable[[], Sequence[ServiceHistory]] = lambda: ()
    live: Callable[[], LiveContext | None] = lambda: None
    registrations: Callable[[], Mapping[str, NameAge] | None] = lambda: None
    pair: str | None = None
    sources: tuple[str, ...] = ()


def _specs() -> list[_Spec]:
    nano: dict[str, Any] = {"malware": "win.nanocore", "threat_type": "botnet_cc"}
    lumma: dict[str, Any] = {"malware": "win.lumma", "threat_type": "botnet_cc"}
    schedule = [f"{8 + n // 2:02d}:{30 * (n % 2):02d}:00" for n in range(21)]
    bore_flow = [
        long_flow(
            duration=10_800.0, host=HOST, server=BORE, port=7835,
            start=f"{DAY} 10:00:00.000000", finish=f"{DAY} 13:00:00.000000",
        )
    ]  # fmt: skip
    visitor_flow = [
        long_flow(
            duration=10_800.0, host=HOST, server=BORE, port=41234,
            start=f"{DAY} 10:00:00.000000", finish=f"{DAY} 13:00:00.000000",
        )
    ]  # fmt: skip
    download = [
        long_flow(
            duration=40.0, host=HOST, server=CDN,
            start=f"{DAY} 10:00:00.000000", finish=f"{DAY} 10:00:40.000000",
        )
    ]  # fmt: skip
    ordinary = lambda: [_seen(ORDINARY, addresses=40, days=30)]  # noqa: E731
    rare = lambda: [_seen(RARE, addresses=1, days=1)]  # noqa: E731
    portal = "portal.campus-printing.com.au"
    return [
        _Spec("P1a", "must_clear", "explained", "E1 (QUIC; NanoCore is TCP only)",
              lambda: [record([_row("10:00:00", transport=17, sni=ORDINARY, root="weatherzone.com.au")], **_ip(), **nano)],
              ordinary, pair="P1"),
        _Spec("P1b", "must_review", "review", "unexplained: raw TCP, no name",
              lambda: [record([_row("10:00:00")], **_ip(), **nano)], pair="P1"),
        _Spec("P2a", "must_clear", "explained", "E3 (TLS to an ordinary site; NanoCore has no TLS)",
              lambda: [record([_row("10:00:00", sni=ORDINARY, root="weatherzone.com.au")], **_ip(), **nano)],
              ordinary, pair="P2"),
        _Spec("P2b", "must_review", "review", "unexplained: dynamic-DNS name",
              lambda: [record([_row("10:00:00", sni="nc-update.duckdns.org", root="duckdns.org")], **_ip(), **nano)],
              pair="P2"),
        _Spec("P3a", "must_clear", "explained", "E3, one-off",
              lambda: [record([_row("10:00:00", sni=RARE, root="kiwi-garden-supplies.com")], **_ip(), **nano)],
              rare, pair="P3"),
        _Spec("P3b", "must_review", "review", "K4: scheduled low-volume contact",
              lambda: [record([_row(m, sni=RARE, root="kiwi-garden-supplies.com", down=900, up=300) for m in schedule], **_ip(), **nano)],
              rare, pair="P3"),
        _Spec("P4a", "must_clear", "explained", "E5: bore client on 7835",
              lambda: [record([_row(f"10:{m:02d}:00", BORE, asn="14061", port=7835, dns="bore.pub", root="bore.pub") for m in range(30)],
                              indicator="bore.pub", flows=bore_flow, **nano)],
              pair="P4"),
        _Spec("P4b", "must_review", "review", "K1+K2: visitor to a bore tunnel port",
              lambda: [record([_row(f"10:{m:02d}:00", BORE, asn="14061", port=41234, dns="bore.pub", root="bore.pub") for m in range(30)],
                              indicator="bore.pub", flows=visitor_flow, **nano)],
              pair="P4"),
        _Spec("P5a", "must_clear", "explained", "E4: established site, usual network, shared address",
              lambda: [record([_row("10:00:00", sni=portal, root="campus-printing.com.au")], **_ip(), **lumma), _neighbours()],
              lambda: [_seen(portal, addresses=60, days=40)], pair="P5"),
        _Spec("P5b", "must_review", "review", "E4c fails: name served from another network",
              lambda: [record([_row("10:00:00", asn="16509", sni=portal, root="campus-printing.com.au")], **_ip(), **lumma), _neighbours()],
              lambda: [_seen(portal, addresses=60, days=40)], pair="P5"),
        _Spec("P6a", "must_clear", "explained", "E1+E2 (QUIC with ECH; NanoCore is native, TCP only)",
              lambda: [record([_row("10:00:00", transport=17, sni="cloudflare-ech.com", root="cloudflare-ech.com")], **_ip(), **nano)],
              pair="P6"),
        _Spec("P6b", "knowledge", "review", "no profile for an unknown family: nothing explains it",
              lambda: [record([_row("10:00:00", transport=17, sni="cloudflare-ech.com", root="cloudflare-ech.com")], **_ip(),
                              malware="unknown_rat", threat_type="botnet_cc")],
              pair="P6"),
        _Spec("S1", "must_review", "review", "K5: download from a payload server; protocol says nothing",
              lambda: [record([_row("10:00:00", sni="dl.kiwi-garden-supplies.com", root="kiwi-garden-supplies.com", down=3_000_000)],
                              flows=download, **_ip(), malware="win.nanocore", threat_type="payload_delivery")],
              lambda: [_seen("dl.kiwi-garden-supplies.com", addresses=1, days=1)]),
        _Spec("S2", "must_review", "review", "platform tenant is never an established site",
              lambda: [record([_row("10:00:00", sni="abc-portal.workers.dev", root="workers.dev")], **_ip(), **lumma), _neighbours()],
              lambda: [_seen("abc-portal.workers.dev", addresses=900, days=60)]),
        _Spec("S3", "must_review", "review", "K1: visit to a flagged lure domain",
              lambda: [record([_row("10:00:00", sni="promo.smallbakery-news.com", root="smallbakery-news.com", down=4_000, up=600)],
                              indicator="promo.smallbakery-news.com", malware="js.clearfake", threat_type="payload_delivery")]),
        _Spec("S4", "must_clear", "explained", "E6: the host sent nothing",
              lambda: [record([_row("10:00:00", VPS, asn="20473", port=23, up=0, down=600)], **_ip(VPS, 23), **nano)]),
        _Spec("S5", "must_review", "review", "a second, raw-TCP contact on another port is unexplained",
              lambda: [record([_row("10:00:00", transport=17, sni=ORDINARY, root="weatherzone.com.au")], **_ip(), **nano)],
              ordinary, live=_raw_tcp_live),
        _Spec("S6", "must_review", "review", "no SNI: a DNS name alone cannot attribute the contact",
              lambda: [record([_row("10:00:00", dns=ORDINARY)], **_ip(), **nano)]),
        _Spec("P7a", "must_clear", "explained", "E3: TLS to a rare name registered years before",
              lambda: [record([_row("10:00:00", sni=RARE, root="kiwi-garden-supplies.com")], **_ip(), **nano)],
              rare, registrations=lambda: _registered(datetime(2014, 3, 2, tzinfo=UTC)), pair="P7"),
        _Spec("P7b", "must_review", "review", "E3 fails: the TLS name was registered 5 days before (CASE_STUDY §16)",
              lambda: [record([_row("10:00:00", sni=RARE, root="kiwi-garden-supplies.com")], **_ip(), **nano)],
              rare, registrations=lambda: _registered(datetime(2026, 9, 10, 9, tzinfo=UTC)), pair="P7"),
        _Spec("P8a", "must_clear", "explained", "E4: established site on a network that shares its addresses by design",
              lambda: [record([_row("10:00:00", sni=portal, root="campus-printing.com.au")], **_ip(), **lumma)],
              lambda: [_seen(portal, addresses=60, days=40)], pair="P8"),
        _Spec("P8b", "must_review", "review", "E4 fails: the same site on an ordinary network, address not shown shared",
              lambda: [record([_row("10:00:00", VPS, asn="20473", sni=portal, root="campus-printing.com.au")], **_ip(VPS), **lumma)],
              lambda: [_seen(portal, VPS, addresses=60, days=40, asn=20473)], pair="P8"),
        _Spec("S7", "must_review", "review", "K1: a shared network never clears a visit to the flagged domain, however established",
              lambda: [record([_row("10:00:00", sni=portal, root="campus-printing.com.au")], indicator=portal,
                              malware="js.clearfake", threat_type="payload_delivery")],
              lambda: [_seen(portal, addresses=60, days=40)]),
        _Spec("S8", "must_review", "review", "K5: a transfer on a shared network with no TLS name stays in review",
              lambda: [record([_row("10:00:00", down=3_000_000)], flows=download, **_ip(),
                              malware="win.nanocore", threat_type="payload_delivery")]),
        _Spec("X1", "knowledge", "explained", "AsyncRAT's channel is TLS over TCP, so QUIC cannot be it",
              lambda: [record([_row("10:00:00", transport=17, sni=RARE, root="kiwi-garden-supplies.com")], **_ip(),
                              malware="win.asyncrat", threat_type="botnet_cc")],
              rare, sources=ASYNCRAT_SOURCES),
        _Spec("X2", "knowledge", "review", "AsyncRAT does use TLS: a TLS contact to a rare name could be it",
              lambda: [record([_row("10:00:00", sni=RARE, root="kiwi-garden-supplies.com")], **_ip(),
                              malware="win.asyncrat", threat_type="botnet_cc")],
              rare, sources=ASYNCRAT_SOURCES),
        _Spec("X3", "knowledge", "explained", "njRAT is a native program on plain TCP: no TLS, no ECH",
              lambda: [record([_row("10:00:00", sni="cloudflare-ech.com", root="cloudflare-ech.com")], **_ip(),
                              malware="win.njrat", threat_type="botnet_cc")],
              sources=NJRAT_SOURCES),
    ]  # fmt: skip


def _registered(when: datetime) -> dict[str, NameAge]:
    return {"kiwi-garden-supplies.com": NameAge("kiwi-garden-supplies.com", when, OK)}


def _raw_tcp_live() -> LiveContext:
    minute = (
        int(
            datetime(
                FIRST_MATCH.year, FIRST_MATCH.month, FIRST_MATCH.day, 11, tzinfo=UTC
            ).timestamp()
        )
        // 60
    )
    contact = PairContact(
        day=FIRST_MATCH, server_ip=CDN, transport=6, port=1604, sni="", root_domain="", dns="",
        asn="13335", active_minutes=1, minute_epochs=(minute,), up_bytes=800, down_bytes=500,
        flows=1,
    )  # fmt: skip
    return LiveContext(
        status="queried",
        queried_at=datetime(2026, 9, 20, tzinfo=UTC),
        latest_day=date(2026, 9, 19),
        days_queried=(FIRST_MATCH,),
        contacts={(HOST, CDN): (contact,)},
    )


def _coverage() -> Coverage:
    days = frozenset(FIRST_MATCH - timedelta(days=offset) for offset in range(91))
    return Coverage(retained_days=days, published_days=days)


def build_cases() -> list[EvalCase]:
    cases = []
    coverage = _coverage()
    for spec in _specs():
        with tempfile.TemporaryDirectory() as directory:
            feed = load_feed(write_feed(Path(directory), spec.records()))
        case = _main_case(feed)
        live = spec.live() or LiveContext(status="skipped")
        history = CaseHistory(
            match_days_retained=case.days,
            match_days_not_retained=(),
            match_days_unpublished=(),
            services=tuple(spec.services()),
            episodes=(),
        )
        evidence = build_evidence(case, feed, live, history, spec.registrations())
        decision = decide(evidence, feed.domain_indicators)
        context = HistoryContext(Path("retained.duckdb"), coverage, {})
        text = render_case_file(evidence, decision, live, context, blind=True)
        cases.append(
            EvalCase(
                id=spec.id,
                group=spec.group,
                expected=spec.expected,
                rule=spec.rule,
                case_file=pseudonymise(text, case),
                code=decision.disposition,
                observed=observed_shapes(evidence),
                pair=spec.pair,
                sources=spec.sources,
            )
        )
    return cases


def _main_case(feed: Feed) -> Case:
    return next(case for case in feed.cases if case.host == HOST)
