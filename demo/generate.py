"""Generate the demo's synthetic network: Zeek logs, an ip2asn table, a ThreatFox export and an RDAP
cache, all seeded and byte-stable for a given seed and end day. The end day is fixed (`DEMO_END`),
so every run builds the same world and code decides the same, whatever day it runs.

Nothing here is real traffic. Local hosts are `10.30.0.0/16`; servers sit in the documentation
ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and the benchmarking range
`198.18.0.0/15`, under `.test` names. The pipeline accepts them only with
`NETWORK_BEHAVIOUR_SYNTHETIC=1`. A few public names stay because the rules know them by name: the
tunnelling service `bore.pub` and the ECH outer name `cloudflare-ech.com`, and AS13335 (whose
addresses are shared by design) labels one documentation block.

**The world.** About 400 hosts in five behaviour profiles, each sized so that every occupied peer
band holds at least 40 hosts (`bands.min_cohort`), with traffic in every minute of every day (the
day's coverage check needs all 1,440 minutes and 288 buckets). Every host keeps the same sites from
day to day, so the scored population and the service mix stay stable against the drift gates, and a
few one-off visits to long-tail sites each day make novelty ordinary.

**The scenarios.** The last `SCENARIO_DAYS` days carry the planted cases in `SCENARIOS`, each on its
own host and its own flagged address, after at least 31 days of history (`confidence.day_edges`
reaches 30). `demo/expected.json` holds what code must decide for each one.

**The small world** (`--hosts-per-profile N`, `make demo-small`) keeps the first N hosts of each
profile plus every scenario host. Each host's traffic is seeded by its address and the day alone, so
the small world is an exact subset of the full one, and the planted cases are the same traffic.

Run: `python demo/generate.py --out demo/work` (see `--help`).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import random
import shutil
import sys
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any

SEED = 20261125
DEMO_END = date(2026, 11, 24)
"""The last day of the world, unless `--end` says otherwise."""
DAYS = 35
SCENARIO_DAYS = 3
DAY_SECONDS = 86_400
MIN_COHORT = 40
"""`bands.min_cohort` in triage's parameters: a peer band with fewer hosts is not compared."""

RESOLVERS = ("192.0.2.53", "192.0.2.54")
PUSH = ("198.18.0.10", "push.notify-hub.test")

# --- servers --------------------------------------------------------------------------------------

# ip2asn rows: (first, last, asn, country, organization). Synthetic networks use the documentation
# AS numbers (64496-64511, RFC 5398) and one private-use number (64512, RFC 6996); AS13335 labels
# one documentation block so that E4's shared-network check has a real entry
# to read (`ioc_report.knowledge.SHARED_NETWORKS`).
NETWORKS = (
    ("192.0.2.0", "192.0.2.255", 64496, "AU", "Example Resolver Network"),
    ("198.18.0.0", "198.18.31.255", 64500, "US", "Example Cloud Inc."),
    ("198.18.32.0", "198.18.63.255", 64501, "US", "Example Content Delivery"),
    ("198.18.64.0", "198.18.95.255", 64502, "AU", "Example Hosting Pty Ltd"),
    ("198.18.96.0", "198.18.127.255", 64503, "DE", "Beispiel Rechenzentrum GmbH"),
    ("198.18.128.0", "198.18.159.255", 64504, "SG", "Example Asia Hosting"),
    ("198.18.160.0", "198.18.191.255", 64505, "NL", "Voorbeeld Hosting B.V."),
    ("198.18.192.0", "198.18.255.255", 64506, "US", "Example Software Distribution"),
    ("198.19.0.0", "198.19.127.255", 64507, "US", "Example Shared Hosting LLC"),
    ("198.19.128.0", "198.19.255.255", 64508, "GB", "Example Web Services Ltd"),
    ("198.51.100.0", "198.51.100.127", 64510, "NL", "Example VPS B.V."),
    ("198.51.100.128", "198.51.100.255", 64511, "US", "Example Virtual Servers LLC"),
    ("203.0.113.0", "203.0.113.63", 13335, "US", "Cloudflare, Inc."),
    ("203.0.113.64", "203.0.113.255", 64512, "RU", "Example Bulletproof Hosting"),
)

WORDS = (
    "acorn", "amber", "anchor", "apex", "arbor", "atlas", "aurora", "basil", "beacon", "birch",
    "bloom", "bolt", "breeze", "brook", "cedar", "chalk", "cinder", "clover", "comet", "coral",
    "crest", "delta", "drift", "dune", "ember", "fable", "fern", "fjord", "flint", "frost",
    "garnet", "glade", "granite", "harbor", "hazel", "heron", "indigo", "iris", "jade",
    "juniper", "kelp", "lagoon", "lark", "linen", "lotus", "maple", "marble", "meadow", "mesa",
    "mint", "nectar", "nimbus", "oak", "onyx", "orbit", "orchid", "pebble", "pine", "plume",
    "prairie", "quartz", "quill", "raven", "reef", "ridge", "river", "saffron", "sage", "slate",
    "sparrow", "spruce", "summit", "tango", "thistle", "tide", "timber", "topaz", "tundra",
    "umber", "vale", "velvet", "willow", "wren", "yarrow", "zephyr",
)  # fmt: skip
KINDS = (
    "news", "mail", "docs", "cloud", "learn", "shop", "maps", "video", "music", "games", "bank",
    "travel", "weather", "sports", "photo", "chat", "code", "books", "health", "jobs",
)  # fmt: skip
PREFIXES = ("www", "api", "cdn", "static", "app", "login", "img")


@dataclass(frozen=True, slots=True)
class Site:
    name: str
    address: str


def _sites() -> tuple[list[Site], list[Site], list[Site]]:
    """(common, cdn, tail). Common sites are what hosts visit routinely; tail sites are each
    visited now and then by somebody."""
    rng = random.Random(f"{SEED}:sites")
    names: set[str] = set()

    def fresh(words: int = 1) -> str:
        while True:
            parts = [rng.choice(WORDS) for _ in range(words)]
            base = f"{'-'.join(parts)}-{rng.choice(KINDS)}.test"
            if base not in names:
                names.add(base)
                return base

    common = []
    for n in range(160):
        block, host = divmod(n, 200)
        third = 1 + 32 * (n % 7) + block  # spread over the 198.18 networks
        common.append(Site(f"{rng.choice(PREFIXES)}.{fresh()}", f"198.18.{third}.{10 + host}"))
    # Sites behind the shared network: several names on each address.
    cdn = [Site(f"{rng.choice(PREFIXES)}.{fresh()}", f"203.0.113.{30 + n % 8}") for n in range(16)]
    tail = [
        Site(f"{rng.choice(PREFIXES)}.{fresh(2)}", f"198.19.{n // 250}.{1 + n % 250}")
        for n in range(3000)
    ]
    return common, cdn, tail


COMMON, CDN_SITES, TAIL = _sites()
UPDATES = Site("dl.soft-depot.test", "198.18.200.20")
DATASETS = (
    Site("data.open-archive.test", "198.18.40.40"),
    Site("mirror.pkg-cache.test", "198.18.200.41"),
)
BACKUP = Site("vault.store-backup.test", "198.18.70.70")
TELEMETRY = (
    Site("telemetry.cam-cloud.test", "198.18.140.15"),
    Site("fw.cam-cloud.test", "198.18.140.16"),
)
PORTAL = Site("portal.campus-print.test", "203.0.113.10")

# --- hosts ----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    block: int
    """Hosts are `10.30.<block>.<n>`."""
    hosts: int
    sites: tuple[int, int]
    """How many common sites each host keeps."""
    sessions: tuple[int, int]
    conns: tuple[int, int]
    down_median: int
    up_median: int
    tail_rate: float
    """Mean one-off long-tail visits a day."""
    weekend: float
    """Share of routine visits kept at the weekend."""
    hours: tuple[int, int]
    """UTC hours routine visits fall in."""


PROFILES = (
    Profile("office", 1, 120, (28, 40), (1, 3), (1, 3), 220_000, 9_000, 1.2, 0.35, (6, 20)),
    Profile("lab", 2, 80, (24, 34), (1, 3), (1, 3), 120_000, 15_000, 1.0, 0.6, (5, 23)),
    Profile("student", 3, 100, (7, 11), (1, 3), (1, 2), 60_000, 6_000, 0.5, 1.0, (0, 24)),
    Profile("device", 4, 50, (2, 3), (1, 1), (1, 1), 20_000, 4_000, 0.0, 1.0, (0, 24)),
    Profile("server", 5, 50, (8, 12), (2, 6), (1, 2), 300_000, 20_000, 0.0, 1.0, (0, 24)),
)


@dataclass(frozen=True, slots=True)
class Host:
    address: str
    profile: Profile
    resolver: str
    sites: tuple[Site, ...]
    portal: bool
    """Uses the established portal before the scenario days."""


def _hosts() -> list[Host]:
    hosts = []
    for profile in PROFILES:
        for n in range(1, profile.hosts + 1):
            address = f"10.30.{profile.block}.{n}"
            rng = random.Random(f"{SEED}:host:{address}")
            if profile.name == "device":
                sites: tuple[Site, ...] = TELEMETRY
            elif profile.name == "server":
                count = rng.randint(*profile.sites)
                sites = (BACKUP, DATASETS[1], UPDATES, *rng.sample(COMMON[:40], count - 3))
            else:
                count = rng.randint(*profile.sites)
                # Popular sites first: the first 40 common sites are everybody's.
                weights = [1.0 / (1 + i / 12) for i in range(len(COMMON))]
                chosen = _weighted_sample(rng, COMMON, weights, count)
                cdn = rng.sample(CDN_SITES, rng.randint(1, 3))
                sites = (*chosen, *cdn)
            portal = profile.name == "office" and n <= 50
            hosts.append(Host(address, profile, RESOLVERS[n % 2], sites, portal))
    return hosts


def _weighted_sample(
    rng: random.Random, items: list[Site], weights: list[float], k: int
) -> list[Site]:
    keyed = sorted(
        range(len(items)), key=lambda i: rng.random() ** (1.0 / weights[i]), reverse=True
    )
    return [items[i] for i in sorted(keyed[:k])]


HOSTS = _hosts()

# --- scenarios ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Scenario:
    id: str
    host: str
    indicator: str
    indicator_type: str
    malware: str
    threat_type: str
    summary: str


NANO = "win.nanocore"
SCENARIOS = (
    Scenario(
        "cdn-edge",
        "10.30.1.7",
        "203.0.113.10:443",
        "ip:port",
        "win.lumma",
        "botnet_cc",
        "an established campus site on a shared CDN address that was listed as C2",
    ),
    Scenario(
        "beacon",
        "10.30.1.33",
        "198.51.100.77:8443",
        "ip:port",
        NANO,
        "botnet_cc",
        "raw TCP to the listed C2 every 30 minutes, low volume, for three days",
    ),
    Scenario(
        "tunnel-client",
        "10.30.5.12",
        "bore.pub",
        "domain",
        NANO,
        "botnet_cc",
        "a bore client the host has run every day: it connects to bore.pub's client port 7835",
    ),
    Scenario(
        "tunnel-visitor",
        "10.30.1.58",
        "bore.pub",
        "domain",
        NANO,
        "botnet_cc",
        "the host reaches a port published through bore.pub",
    ),
    Scenario(
        "download",
        "10.30.5.21",
        "198.51.100.120:443",
        "ip:port",
        "elf.shadowv2",
        "payload_delivery",
        "a 3.2 MB download from a listed payload server",
    ),
    Scenario(
        "unanswered-inbound",
        "10.30.3.44",
        "203.0.113.200:1604",
        "ip:port",
        NANO,
        "botnet_cc",
        "the listed address sends to the host, which never answers",
    ),
    Scenario(
        "udp-to-tcp-family",
        "10.30.3.71",
        "198.51.100.140:443",
        "ip:port",
        NANO,
        "botnet_cc",
        "QUIC (UDP 443) to an address listed for a TCP-only family",
    ),
    Scenario(
        "ech-outer-name",
        "10.30.1.90",
        "203.0.113.20:443",
        "ip:port",
        NANO,
        "botnet_cc",
        "TLS with the ECH outer name, which only browsers send, to a native family's C2",
    ),
    Scenario(
        "flagged-domain",
        "10.30.1.104",
        "promo.smallbakery-news.test",
        "domain",
        "js.clearfake",
        "payload_delivery",
        "a page load from a listed lure domain",
    ),
    Scenario(
        "tls-old-name",
        "10.30.2.15",
        "198.51.100.160:443",
        "ip:port",
        NANO,
        "botnet_cc",
        "TLS to a long-registered site on an address listed for a family with no TLS",
    ),
    Scenario(
        "tls-new-name",
        "10.30.2.47",
        "198.51.100.170:443",
        "ip:port",
        NANO,
        "botnet_cc",
        "TLS to a name registered five days earlier on an address listed for a family with no TLS",
    ),
)
assert len({s.host for s in SCENARIOS}) == len(SCENARIOS)
assert {s.host for s in SCENARIOS} <= {h.address for h in HOSTS}

BORE = "198.51.100.90"
TUNNEL_CLIENT = next(s.host for s in SCENARIOS if s.id == "tunnel-client")
LURE = "198.51.100.150"
OLD_NAME = "api.kiwi-garden.test"
NEW_NAME = "cdn.fresh-parcel.test"
PAYLOAD_NAME = "dl.fresh-mirror.test"

# ThreatFox records that match nothing on campus, so the export is not only the planted cases.
UNMATCHED = (
    ("198.51.100.201:4782", "ip:port", "win.quasar_rat", "botnet_cc"),
    ("203.0.113.222:7443", "ip:port", "win.asyncrat", "botnet_cc"),
    ("login-verify.secure-update.test", "domain", "js.clearfake", "payload_delivery"),
    ("https://files.cheap-hosting.test/a/b.exe", "url", "win.lumma", "payload_delivery"),
    ("0f4f2d2bd1b4f7a1c1b4b0f6a2e9d7c3", "md5_hash", "win.lumma", "payload_delivery"),
)

# --- one day --------------------------------------------------------------------------------------


@dataclass(slots=True)
class DayLogs:
    day: date
    conn: list[str] = field(default_factory=list)
    ssl: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    counter: int = 0

    def uid(self, host: str) -> str:
        self.counter += 1
        digest = hashlib.blake2b(f"{self.day}:{host}:{self.counter}".encode(), digest_size=12)
        return "C" + digest.hexdigest()[:17]

    def connection(
        self,
        ts: float,
        orig: str,
        resp: str,
        *,
        resp_p: int,
        proto: str = "tcp",
        service: str | None = "ssl",
        duration: float,
        orig_bytes: int,
        resp_bytes: int,
        sni: str | None = None,
        orig_p: int | None = None,
        rng: random.Random,
    ) -> str:
        uid = self.uid(orig)
        orig_pkts = max(1, orig_bytes // 900 + 1)
        resp_pkts = max(1, resp_bytes // 1300 + 1) if resp_bytes else 0
        record: dict[str, Any] = {
            "ts": round(ts, 6),
            "uid": uid,
            "id.orig_h": orig,
            "id.orig_p": orig_p if orig_p is not None else rng.randint(32768, 60999),
            "id.resp_h": resp,
            "id.resp_p": resp_p,
            "proto": proto,
        }
        if service:
            record["service"] = service
        record |= {
            "duration": round(duration, 6),
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
        }
        self.conn.append(json.dumps(record, separators=(",", ":")))
        if sni:
            self.ssl.append(
                json.dumps(
                    {"ts": round(ts + 0.01, 6), "uid": uid, "server_name": sni},
                    separators=(",", ":"),
                )
            )
        return uid

    def lookup(
        self, ts: float, host: str, resolver: str, name: str, address: str, rng: random.Random
    ) -> None:
        uid = self.uid(host)
        rtt = round(rng.uniform(0.004, 0.035), 6)
        self.dns.append(
            json.dumps(
                {
                    "ts": round(ts, 6),
                    "uid": uid,
                    "id.orig_h": host,
                    "id.orig_p": rng.randint(32768, 60999),
                    "id.resp_h": resolver,
                    "id.resp_p": 53,
                    "proto": "udp",
                    "query": name,
                    "rcode": 0,
                    "rtt": rtt,
                    "answers": [address],
                    "TTLs": [300.0],
                },
                separators=(",", ":"),
            )
        )
        self.conn.append(
            json.dumps(
                {
                    "ts": round(ts, 6),
                    "uid": uid,
                    "id.orig_h": host,
                    "id.orig_p": rng.randint(32768, 60999),
                    "id.resp_h": resolver,
                    "id.resp_p": 53,
                    "proto": "udp",
                    "service": "dns",
                    "duration": rtt,
                    "orig_bytes": 30 + len(name),
                    "resp_bytes": 46 + len(name),
                    "orig_pkts": 1,
                    "resp_pkts": 1,
                },
                separators=(",", ":"),
            )
        )

    def visit(
        self,
        start: float,
        host: Host,
        site: Site,
        rng: random.Random,
        *,
        conns: int,
        down: int,
        up: int,
        port: int = 443,
    ) -> None:
        """A DNS lookup, then `conns` TLS connections to the site."""
        self.lookup(start, host.address, host.resolver, site.name, site.address, rng)
        ts = start + 0.05
        for _ in range(conns):
            duration = min(rng.expovariate(1 / 25.0), 280.0) + 0.2
            self.connection(
                ts,
                host.address,
                site.address,
                resp_p=port,
                duration=duration,
                orig_bytes=_jitter(rng, up),
                resp_bytes=_jitter(rng, down),
                sni=site.name,
                rng=rng,
            )
            ts += rng.uniform(0.5, 40.0)


def _jitter(rng: random.Random, median: int) -> int:
    return max(64, int(median * math.exp(rng.gauss(0.0, 0.6))))


def _clock(day: date) -> float:
    return datetime.combine(day, time.min, UTC).timestamp()


def _routine(logs: DayLogs, host: Host, day: date, index: int, last_background: int) -> None:
    rng = random.Random(f"{SEED}:{day}:{host.address}")
    profile = host.profile
    base = _clock(day)
    weekend = day.weekday() >= 5
    # Persistent push connections cover every minute of the day for every host.
    for quarter in range(4):
        logs.connection(
            base + quarter * 21_600 + rng.uniform(0.0, 2.0),
            host.address,
            PUSH[0],
            resp_p=443,
            duration=21_596.0,
            orig_bytes=rng.randint(18_000, 24_000),
            resp_bytes=rng.randint(26_000, 34_000),
            sni=PUSH[1],
            rng=rng,
        )
    lo, hi = profile.hours

    def moment() -> float:
        return base + rng.uniform(lo * 3600, hi * 3600 - 300)

    if profile.name == "device":
        for site in host.sites:
            offset = rng.uniform(0, 900)
            for slot in range(96):
                logs.visit(
                    base + offset + slot * 900 + rng.uniform(0, 120),
                    host,
                    site,
                    rng,
                    conns=1,
                    down=profile.down_median,
                    up=profile.up_median,
                )
        return
    keep = profile.weekend if weekend else 0.85
    for site in host.sites:
        if rng.random() > keep:
            continue
        for _ in range(rng.randint(*profile.sessions)):
            logs.visit(
                moment(),
                host,
                site,
                rng,
                conns=rng.randint(*profile.conns),
                down=profile.down_median,
                up=profile.up_median,
            )
    for _ in range(_poisson(rng, profile.tail_rate * (keep / 0.85))):
        logs.visit(
            moment(),
            host,
            rng.choice(TAIL),
            rng,
            conns=rng.randint(1, 2),
            down=profile.down_median,
            up=profile.up_median,
        )
    if host.portal and index <= last_background and rng.random() < 0.7:
        logs.visit(moment(), host, PORTAL, rng, conns=2, down=40_000, up=6_000)
    if profile.name in {"office", "lab"} and rng.random() < 0.3:
        logs.visit(
            moment(), host, UPDATES, rng, conns=1, down=rng.randint(4, 30) * 1_000_000, up=40_000
        )
    if profile.name == "lab":
        for _ in range(rng.randint(2, 4)):
            logs.visit(
                moment(),
                host,
                rng.choice(DATASETS),
                rng,
                conns=1,
                down=rng.randint(60, 200) * 1_000_000,
                up=200_000,
            )
    if host.address == TUNNEL_CLIENT:
        # A bore client that has published one of the host's ports since before the first day.
        for quarter in range(4):
            start = base + quarter * 21_600 + 30.0
            logs.lookup(start, host.address, host.resolver, "bore.pub", BORE, rng)
            logs.connection(
                start + 0.1,
                host.address,
                BORE,
                resp_p=7835,
                service=None,
                duration=21_500.0,
                orig_bytes=rng.randint(250_000, 400_000),
                resp_bytes=rng.randint(150_000, 250_000),
                rng=rng,
            )
    if profile.name == "server":
        start = base + 7200 + rng.uniform(0, 1800)
        logs.lookup(start, host.address, host.resolver, BACKUP.name, BACKUP.address, rng)
        logs.connection(
            start + 0.05,
            host.address,
            BACKUP.address,
            resp_p=443,
            duration=rng.uniform(2400, 4200),
            orig_bytes=rng.randint(1500, 2500) * 1_000_000,
            resp_bytes=rng.randint(2, 6) * 1_000_000,
            sni=BACKUP.name,
            rng=rng,
        )


def _poisson(rng: random.Random, mean: float) -> int:
    if mean <= 0:
        return 0
    limit, count, product = math.exp(-mean), 0, rng.random()
    while product > limit:
        count += 1
        product *= rng.random()
    return count


def _planted(logs: DayLogs, day: date, scenario_day: int, hosts: dict[str, Host]) -> None:
    """The scenarios, on scenario day 0, 1, 2, ... (only the beacon runs on more than one)."""
    base = _clock(day)
    by_id = {s.id: s for s in SCENARIOS}

    def host(sid: str) -> Host:
        return hosts[by_id[sid].host]

    def rng(sid: str) -> random.Random:
        return random.Random(f"{SEED}:{day}:{sid}")

    def at(hour: float) -> float:
        return base + hour * 3600

    def endpoint(sid: str) -> tuple[str, int]:
        address, _, port = by_id[sid].indicator.rpartition(":")
        return address, int(port)

    # Beacon: from 06:00 on the first scenario day to the end, every 30 minutes, to the C2 port.
    r = rng("beacon")
    address, port = endpoint("beacon")
    first = 12 if scenario_day == 0 else 0
    for slot in range(first, 48):
        logs.connection(
            at(slot / 2) + 7.0 + r.uniform(0, 1.5),
            host("beacon").address,
            address,
            resp_p=port,
            service=None,
            duration=r.uniform(0.8, 1.6),
            orig_bytes=r.randint(380, 460),
            resp_bytes=r.randint(220, 300),
            rng=r,
        )
    if scenario_day != 1:
        return
    # The rest happen once, on the middle scenario day.
    r = rng("cdn-edge")
    logs.visit(at(10.2), host("cdn-edge"), PORTAL, r, conns=2, down=40_000, up=6_000)
    r = rng("tunnel-visitor")
    h = host("tunnel-visitor")
    logs.lookup(at(13.0), h.address, h.resolver, "bore.pub", BORE, r)
    logs.connection(
        at(13.0) + 0.1,
        h.address,
        BORE,
        resp_p=41234,
        service=None,
        duration=10_800.0,
        orig_bytes=300_000,
        resp_bytes=1_800_000,
        rng=r,
    )
    r = rng("download")
    h = host("download")
    address, port = endpoint("download")
    logs.visit(at(11.5), h, Site(PAYLOAD_NAME, address), r, conns=1, down=3_200_000, up=5_000)
    r = rng("unanswered-inbound")
    address, port = endpoint("unanswered-inbound")
    for minute in (0, 7, 19):
        logs.connection(
            at(4.0) + minute * 60,
            address,
            host("unanswered-inbound").address,
            resp_p=r.randint(40000, 60000),
            orig_p=port,
            service=None,
            duration=0.4,
            orig_bytes=600,
            resp_bytes=0,
            rng=r,
        )
    r = rng("udp-to-tcp-family")
    address, port = endpoint("udp-to-tcp-family")
    for minute in (0, 3):
        logs.connection(
            at(15.0) + minute * 60,
            host("udp-to-tcp-family").address,
            address,
            resp_p=port,
            proto="udp",
            service=None,
            duration=40.0,
            orig_bytes=9_000,
            resp_bytes=120_000,
            rng=r,
        )
    r = rng("ech-outer-name")
    address, port = endpoint("ech-outer-name")
    logs.connection(
        at(16.0),
        host("ech-outer-name").address,
        address,
        resp_p=port,
        duration=30.0,
        orig_bytes=4_000,
        resp_bytes=60_000,
        sni="cloudflare-ech.com",
        rng=r,
    )
    r = rng("flagged-domain")
    logs.visit(
        at(12.0),
        host("flagged-domain"),
        Site("promo.smallbakery-news.test", LURE),
        r,
        conns=1,
        down=4_000,
        up=600,
    )
    r = rng("tls-old-name")
    address, port = endpoint("tls-old-name")
    logs.visit(
        at(14.0), host("tls-old-name"), Site(OLD_NAME, address), r, conns=1, down=30_000, up=3_000
    )
    r = rng("tls-new-name")
    address, port = endpoint("tls-new-name")
    logs.visit(
        at(14.5), host("tls-new-name"), Site(NEW_NAME, address), r, conns=1, down=30_000, up=3_000
    )


def select_hosts(per_profile: int | None) -> list[Host]:
    """Every host, or the first `per_profile` of each profile plus every scenario host."""
    if per_profile is None:
        return HOSTS
    planted = {s.host for s in SCENARIOS}
    return [
        h for h in HOSTS if int(h.address.rsplit(".", 1)[1]) <= per_profile or h.address in planted
    ]


def generate_day(args: tuple[Path, date, int, int, int | None]) -> tuple[str, int]:
    out, day, index, days, per_profile = args
    logs = DayLogs(day)
    last_background = days - SCENARIO_DAYS - 1
    hosts = select_hosts(per_profile)
    for host in hosts:
        _routine(logs, host, day, index, last_background)
    if index > last_background:
        _planted(logs, day, index - last_background - 1, {h.address: h for h in hosts})
    folder = out / day.isoformat()
    folder.mkdir(parents=True, exist_ok=True)
    for kind, lines in (("conn", logs.conn), ("ssl", logs.ssl), ("dns", logs.dns)):
        # Zeek writes connections as they end; sorting by start is close enough, and stable.
        lines.sort(key=lambda line: float(line[6 : line.index(",")]))
        with (
            (folder / f"{kind}.log.gz").open("wb") as raw,
            gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as handle,
        ):
            handle.write(("\n".join(lines) + "\n").encode())
    return day.isoformat(), len(logs.conn)


# --- the other files ------------------------------------------------------------------------------


def scenario_days(end: date, days: int = DAYS) -> list[date]:
    return [end - timedelta(days=offset) for offset in reversed(range(SCENARIO_DAYS))]


def write_asn_table(path: Path) -> None:
    lines = [f"{lo}\t{hi}\t{asn}\t{country}\t{org}" for lo, hi, asn, country, org in NETWORKS]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_export(path: Path, end: date) -> None:
    """A ThreatFox-style JSON export (keyed by id, a list of records under each)."""
    first = scenario_days(end)[0]
    records: list[tuple[str, str, str, str]] = []
    seen = set()
    for s in SCENARIOS:
        if s.indicator not in seen:
            seen.add(s.indicator)
            records.append((s.indicator, s.indicator_type, s.malware, s.threat_type))
    records.extend(UNMATCHED)
    export: dict[str, list[dict[str, Any]]] = {}
    for number, (value, kind, malware, threat) in enumerate(records, 1):
        listed = datetime.combine(first - timedelta(days=3 + number % 9), time(6, number % 60), UTC)
        export[str(1_400_000 + number)] = [
            {
                "ioc_value": value,
                "ioc_type": kind,
                "threat_type": threat,
                "malware": malware,
                "malware_printable": malware.split(".", 1)[-1],
                "confidence_level": 100 if threat == "botnet_cc" else 75,
                "first_seen_utc": f"{listed:%Y-%m-%d %H:%M:%S} UTC",
                "last_seen_utc": None,
                "reporter": "synthetic",
                "tags": "demo",
            }
        ]
    path.write_text(json.dumps(export, indent=1) + "\n", encoding="utf-8")


def write_rdap_cache(folder: Path, end: date, now: datetime) -> None:
    """A pre-filled RDAP cache, so the demo never asks the network. Its bootstrap sends every
    top-level domain the world uses to a closed loopback port, so a name missing from the cache (the
    real bore.pub among them) fails at once and is reported as a failed lookup with an unknown age,
    which changes no decision."""
    folder.mkdir(parents=True, exist_ok=True)
    stamp = now.isoformat()
    closed = ["http://127.0.0.1:9/"]
    servers = {tld: closed for tld in ("test", "pub", "com")}
    (folder / "bootstrap.json").write_text(
        json.dumps({"fetched_at": stamp, "servers": servers}, indent=1), encoding="utf-8"
    )
    new = datetime.combine(scenario_days(end)[1] - timedelta(days=5), time(9), UTC)
    registered = {
        "kiwi-garden.test": datetime(2014, 3, 2, tzinfo=UTC),
        "fresh-parcel.test": new,
        "smallbakery-news.test": datetime(2019, 6, 11, tzinfo=UTC),
    }
    cache = {
        domain: {"registered": when.isoformat(), "status": "ok", "fetched_at": stamp}
        for domain, when in registered.items()
    }
    (folder / "registrations.json").write_text(
        json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8"
    )


def remove_other_days(logs: Path, days: list[date]) -> None:
    """Delete the day folders an earlier world left outside this one: the loader reads day D+1's
    folder for day D, so a stale folder would join the world."""
    if not logs.is_dir():
        return
    keep = {day.isoformat() for day in days}
    for folder in logs.iterdir():
        try:
            date.fromisoformat(folder.name)
        except ValueError:
            continue
        if folder.is_dir() and folder.name not in keep:
            shutil.rmtree(folder)


def all_days(end: date, days: int) -> Iterator[date]:
    for offset in reversed(range(days)):
        yield end - timedelta(days=offset)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=Path("demo/work"))
    parser.add_argument(
        "--end", type=date.fromisoformat, default=DEMO_END, help=f"last day (default: {DEMO_END})"
    )
    parser.add_argument("--days", type=int, default=DAYS)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument(
        "--hosts-per-profile",
        type=int,
        help="the small world: the first N hosts of each profile plus the scenario hosts",
    )
    args = parser.parse_args(argv)
    if args.hosts_per_profile is not None and args.hosts_per_profile < MIN_COHORT:
        parser.error(f"--hosts-per-profile must keep every peer band at {MIN_COHORT} hosts or more")
    if args.days < SCENARIO_DAYS + 31:
        parser.error(
            f"--days must leave 31 days of history before the {SCENARIO_DAYS} scenario days"
        )
    now = datetime.now(UTC)
    end: date = args.end
    days = list(all_days(end, args.days))
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    remove_other_days(out / "logs", days)
    per_profile = args.hosts_per_profile
    hosts = select_hosts(per_profile)
    jobs = [(out / "logs", day, index, len(days), per_profile) for index, day in enumerate(days)]
    total = 0
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        for name, count in pool.map(generate_day, jobs):
            total += count
            print(f"  {name}: {count:,} connections", file=sys.stderr)
    write_asn_table(out / "ip2asn.tsv")
    write_export(out / "threatfox.json", end)
    write_rdap_cache(out / "rdap", end, now)
    (out / "world.json").write_text(
        json.dumps(
            {
                "seed": SEED,
                "start": days[0].isoformat(),
                "end": end.isoformat(),
                "hosts": len(hosts),
                "hosts_per_profile": per_profile,
                "scenario_days": [d.isoformat() for d in scenario_days(end)],
                "connections": total,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"generated {len(days)} days, {len(hosts)} hosts, {total:,} connections in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
