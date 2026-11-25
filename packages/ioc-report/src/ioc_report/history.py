"""Retained context from the triage repo's DuckDB: 365-day history and the published stream.

The database is opened read-only and no migration runs, so nothing here can write to it. Every
lookup is batched across all cases. History keeps hashed services, never names or addresses, so a
case's names and flagged addresses are hashed here exactly as the publisher hashes them and looked
up by hash.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import duckdb
from network_behaviour.normalization.service import SERVICE_ID_VERSION, ServiceBasis

from ioc_report.feed import Case, logical_service
from ioc_report.knowledge import ECH_OUTER_NAMES, SOFTWARE_SIGNALS, clean

# The triage repo's own prevalence reference window (`baselines/engine.py`, 90 days).
PRIOR_WINDOW_DAYS = 90

# The triage repo's scored population (`behavioural-support-v3`): addresses with at least one
# service row. 60-75% of observed addresses carry only unaddressed rows (CASE_STUDY §2, §3), so a
# campus quantile over every `history.client_day` row is mostly zeros and moves with their count.
SCORED_MIN_SERVICES = 1

# The detector generation that corrected what a family scored (CASE_STUDY, superseded values):
# primary-detectors-v8 counts as DNS clients only addresses that sent a query, DNS servers left out
# (CASE_STUDY §9); -v9 scores and pools transfer and fanout only on addresses with a service row
# (CASE_STUDY §3, the triage contract's "Observed client identity"). Published days are never
# re-scored, so an earlier episode of these families keeps the old definition.
CORRECTED_IN = {"dns": 8, "transfer": 9, "fanout": 9}
_DETECTOR_GENERATION = re.compile(r"primary-detectors-v(?P<number>[0-9]+)")

# Days before the first match a software signal counts as current for the host. An output window,
# not a threshold: the overview says "in the 30 days before", and no rule reads it.
SIGNAL_RECENT_DAYS = 30

# How many episodes and names a whole-host line lists; its counts are always complete.
WHOLE_HOST_LISTED = 8
# A public address to hash a bare name with: a domain-basis service id depends on the name alone
# (a TEST-NET address is not a public destination and hashes to nothing).
NAME_PLACEHOLDER_ADDRESS = "1.1.1.1"


# Triage CASE_STUDY §17: a named TCP service reached on remote ports of 1024 and above from at
# least this many outside addresses, in at least this many networks, in one day is the address's
# own site. At these values 99.98% of the marked addresses' measured long flows were opened by the
# remote side, and 26 of the 28 addresses serving TLS long flows were marked.
SERVING_MIN_REMOTES = 10
SERVING_MIN_NETWORKS = 3
# port-groups-v1's `other_registered` and `dynamic` groups: remote ports of 1024 and above.
HIGH_PORT_GROUPS = (65537, 65538)
# An output window, not a threshold: the days `read_serving` reads.
SERVING_WINDOW_DAYS = 30


class HistoryError(RuntimeError):
    """The retained store cannot be read safely. The run stops rather than report without it."""


@dataclass(frozen=True, slots=True)
class Coverage:
    retained_days: frozenset[date]
    published_days: frozenset[date]

    @property
    def first_day(self) -> date | None:
        return min(self.retained_days, default=None)

    @property
    def last_day(self) -> date | None:
        return max(self.retained_days, default=None)

    @property
    def gaps(self) -> tuple[date, ...]:
        if self.first_day is None or self.last_day is None:
            return ()
        span = (self.last_day - self.first_day).days + 1
        every_day = (self.first_day + timedelta(days=offset) for offset in range(span))
        return tuple(day for day in every_day if day not in self.retained_days)

    def retained_between(self, start: date, end: date) -> int:
        """Retained days in [start, end)."""
        return sum(1 for day in self.retained_days if start <= day < end)


@dataclass(frozen=True, slots=True)
class ServiceKey:
    service_id_hex: str
    label: str
    """The registered domain, or the address for a server_ip-basis service."""
    basis: str


@dataclass(frozen=True, slots=True)
class Prior:
    """Campus use of one service in the window before the case's first match day."""

    window_start: date
    window_end: date
    """Exclusive: the first match day."""
    retained_days: int
    addresses: int
    days: int
    first_day: date | None
    asn_ids: frozenset[int]
    """Networks that served the service to campus hosts in the window (0, unknown, left out)."""


@dataclass(frozen=True, slots=True)
class HostServiceDay:
    """One retained row of the host's use of a service on a match day."""

    day: date
    bitmap: bytes
    up_bytes: int
    down_bytes: int
    transport: int
    port_group: int
    asn_id: int
    large_flow_count: int
    max_large_flow_duration_sec: float
    service_rows_that_day: int
    """Rows campus-wide for this service that day: the triage repo's beacon fan-in count."""


@dataclass(frozen=True, slots=True)
class ServiceHistory:
    key: ServiceKey
    campus_addresses: int
    campus_days: int
    prior: Prior | None
    host_first_day: date | None
    host_days_before: int
    host_days_on_match: int
    host_days_after: int
    match_rows: tuple[HostServiceDay, ...]

    @property
    def domain(self) -> str:
        return self.key.label

    @property
    def service_id_hex(self) -> str:
        return self.key.service_id_hex


@dataclass(frozen=True, slots=True)
class Episode:
    day: date
    family: str
    tier: str
    service_id_hex: str | None
    service_domain: str | None
    detector: str = ""
    """The detector generation the day was published under (`feed.daily_publication`)."""

    @property
    def superseded(self) -> bool:
        return superseded(self.family, self.detector)


def superseded(family: str, detector: str) -> bool:
    """Scored before the triage repo corrected the family's population (`CORRECTED_IN`). An
    unreadable generation is never marked."""
    corrected = CORRECTED_IN.get(family)
    found = _DETECTOR_GENERATION.search(detector)
    return corrected is not None and found is not None and int(found["number"]) < corrected


@dataclass(frozen=True, slots=True)
class HostDay:
    """The host's whole day from `history.client_day`, beside that day's quantiles over the campus
    addresses with a service row (`SCORED_MIN_SERVICES`)."""

    day: date
    unique_services: int
    unique_servers: int
    total_bytes: int
    large_flow_count: int
    campus_p50_services: float | None
    campus_p90_services: float | None
    campus_p99_services: float | None
    """None only when no campus address had a service row that day."""


@dataclass(frozen=True, slots=True)
class SignalUse:
    """The host's retained use of one `knowledge.SOFTWARE_SIGNALS` product."""

    key: str
    name: str
    days: int
    """Retained days with any of the product's domains."""
    recent_days: int
    """Of them, days in the SIGNAL_RECENT_DAYS before the first match."""
    first_day: date
    last_day: date


@dataclass(frozen=True, slots=True)
class WholeHost:
    """Everything retained about the host on every day, not only the match days. Shown, never
    decided on: an IOC case is read against the host as a whole."""

    first_day: date | None
    last_day: date | None
    retained_days: int
    addressed_days: int
    """Retained days with traffic to or from a known remote address (`flow_count > 0`), in either
    direction (CASE_STUDY §3, §7)."""
    episode_counts: tuple[tuple[str, str, int], ...]
    """(family, tier, episodes) over every published day, v1 days included."""
    episode_days: int
    other_episodes: tuple[Episode, ...]
    """Episodes other than relationship, most recent first, at most WHOLE_HOST_LISTED."""
    other_episode_count: int
    services_since_match: int
    """Services the host first used on or after the first match day."""
    names_since_match: tuple[str, ...]
    """Of those, the ones the published stream resolved to a name, earliest first, capped."""
    superseded: tuple[tuple[str, int], ...] = ()
    """(family, episodes) scored before the triage repo corrected the family (`CORRECTED_IN`)."""
    signals: tuple[SignalUse, ...] = ()
    """Products with a known purpose the address used on retained days, most days first."""


@dataclass(frozen=True, slots=True)
class NameUse:
    """One name's retained use beside a case: the host's first day with it and the campus's use
    in the window before the first match. It ranks and marks the case file's context lines and
    is never decided on, so it is read apart from the case's own services."""

    host_first_day: date | None
    prior_addresses: int
    prior_days: int


@dataclass(frozen=True, slots=True)
class CaseHistory:
    match_days_retained: tuple[date, ...]
    match_days_not_retained: tuple[date, ...]
    match_days_unpublished: tuple[date, ...]
    services: tuple[ServiceHistory, ...]
    episodes: tuple[Episode, ...]
    """The host's published episodes on the match days, on any service."""
    host_days: tuple[HostDay, ...] = ()
    whole_host: WholeHost | None = None

    def service(self, service_id_hex: str) -> ServiceHistory | None:
        return next((s for s in self.services if s.service_id_hex == service_id_hex), None)

    @property
    def same_service_episodes(self) -> tuple[Episode, ...]:
        """Episodes on any service this case touched or is about."""
        known = {service.service_id_hex for service in self.services}
        return tuple(episode for episode in self.episodes if episode.service_id_hex in known)


@dataclass(frozen=True, slots=True)
class HistoryContext:
    path: Path
    coverage: Coverage
    cases: Mapping[tuple[str, str], CaseHistory]
    """Keyed by (indicator, canonical host)."""
    names: Mapping[tuple[str, date, str], NameUse] = field(default_factory=dict)
    """Read after the live phases (`read_name_use`), keyed by (canonical host, first match day,
    registered domain): the names in a review case's context lines."""


def indicator_service(case: Case) -> ServiceKey | None:
    """The flagged domain's own service. Its hash depends on the domain alone."""
    if not case.is_domain:
        return None
    for server in case.server_ips:
        service = logical_service(server, root_domain=case.indicator)
        if service is not None and service.basis is ServiceBasis.DOMAIN and service.domain:
            return ServiceKey(service.service_id.hex(), service.domain, "domain")
    return None


def address_services(case: Case) -> tuple[ServiceKey, ...]:
    """Each flagged address as a server_ip-basis service: how unnamed contact is retained."""
    keys = []
    for server in case.server_ips:
        service = logical_service(server)
        if service is not None and service.basis is ServiceBasis.SERVER_IP:
            keys.append(ServiceKey(service.service_id.hex(), server, "server_ip"))
    return tuple(keys)


def sni_service(server_ip: str, sni: str) -> ServiceKey | None:
    """The service of the name the host sent in its handshake, hashed on that name alone."""
    if not sni or clean(sni) in ECH_OUTER_NAMES:
        return None
    service = logical_service(server_ip, sni=sni)
    if service is None or service.basis is not ServiceBasis.DOMAIN or not service.domain:
        return None
    return ServiceKey(service.service_id.hex(), service.domain, "domain")


def name_key(name: str) -> ServiceKey | None:
    """A bare registered name as the publisher hashes it, for names seen without an address."""
    service = logical_service(NAME_PLACEHOLDER_ADDRESS, root_domain=name)
    if service is None or service.basis is not ServiceBasis.DOMAIN or not service.domain:
        return None
    return ServiceKey(service.service_id.hex(), service.domain, "domain")


def read_name_use(
    path: Path, requests: Sequence[tuple[str, date, str]]
) -> dict[tuple[str, date, str], NameUse]:
    """Retained use of names a review case's context lines show, for (canonical host, first match
    day, name) requests. Batched: two lookups in all. Names that do not hash as a registered
    domain are left out, as are names history never held."""
    keys = {
        (host, cutoff, name): key
        for host, cutoff, name in requests
        if (key := name_key(name)) is not None
    }
    if not keys:
        return {}
    if not path.is_file():
        raise HistoryError(f"retained store not found at {path}")
    try:
        connection = duckdb.connect(str(path), read_only=True)
    except duckdb.Error as exc:
        raise HistoryError("cannot open the retained store read-only") from exc
    try:
        pairs = sorted({(host, key.service_id_hex) for (host, _, _), key in keys.items()})
        first_use = {
            (str(row[0]), str(row[1])): row[2]
            for row in connection.execute(
                """
                SELECT key.client_ip, lower(hex(key.service_id)), min(stored.day)
                FROM (SELECT unnest(?::VARCHAR[]) AS client_ip, unnest(?::BLOB[]) AS service_id)
                     AS key
                JOIN history.client_service_day AS stored
                  ON stored.client_ip = key.client_ip AND stored.service_id = key.service_id
                GROUP BY ALL
                """,
                [[host for host, _ in pairs], _blobs([service for _, service in pairs])],
            ).fetchall()
        }
        windows = sorted({(key.service_id_hex, cutoff) for (_, cutoff, _), key in keys.items()})
        prior = {
            (str(row[0]), row[1]): (int(row[2]), int(row[3]))
            for row in connection.execute(
                """
                WITH key AS (SELECT unnest(?::BLOB[]) AS service_id, unnest(?::DATE[]) AS cutoff)
                SELECT lower(hex(key.service_id)), key.cutoff,
                       count(DISTINCT stored.client_ip), count(DISTINCT stored.day)
                FROM key
                JOIN history.client_service_day AS stored
                  ON stored.service_id = key.service_id
                 AND stored.day >= key.cutoff - ?::INTEGER AND stored.day < key.cutoff
                GROUP BY ALL
                """,
                [_blobs([s for s, _ in windows]), [d for _, d in windows], PRIOR_WINDOW_DAYS],
            ).fetchall()
        }
    finally:
        connection.close()
    return {
        request: NameUse(
            host_first_day=first_use.get((request[0], key.service_id_hex)),
            prior_addresses=prior.get((key.service_id_hex, request[1]), (0, 0))[0],
            prior_days=prior.get((key.service_id_hex, request[1]), (0, 0))[1],
        )
        for request, key in keys.items()
    }


def case_service_keys(case: Case) -> tuple[ServiceKey, ...]:
    keys: dict[str, ServiceKey] = {}
    for service in case.services:
        keys.setdefault(
            service.service_id_hex, ServiceKey(service.service_id_hex, service.domain, "domain")
        )
    for row in case.rows:
        if (key := sni_service(row.server_ip, row.sni)) is not None:
            keys.setdefault(key.service_id_hex, key)
    if (key := indicator_service(case)) is not None:
        keys.setdefault(key.service_id_hex, key)
    for key in address_services(case):
        keys.setdefault(key.service_id_hex, key)
    return tuple(keys.values())


def read_history(
    path: Path,
    cases: Sequence[Case],
    extra_keys: Mapping[tuple[str, str], Sequence[ServiceKey]] | None = None,
) -> HistoryContext:
    """`extra_keys` adds services per (indicator, host), such as names seen only in live contact."""
    if not path.is_file():
        raise HistoryError(f"retained store not found at {path}")
    try:
        connection = duckdb.connect(str(path), read_only=True)
    except duckdb.Error as exc:
        raise HistoryError(
            "cannot open the retained store read-only; the publisher may be running"
        ) from exc
    keys_by_case = {
        (case.indicator, case.host): _merge(
            case_service_keys(case), (extra_keys or {}).get((case.indicator, case.host), ())
        )
        for case in cases
    }
    try:
        _require_service_id_version(connection)
        coverage = Coverage(
            retained_days=frozenset(
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT day FROM history.client_day"
                ).fetchall()
            ),
            published_days=frozenset(
                row[0]
                for row in connection.execute("SELECT day FROM feed.daily_publication").fetchall()
            ),
        )
        all_keys = {key.service_id_hex for keys in keys_by_case.values() for key in keys}
        prevalence = _prevalence(connection, all_keys)
        prior = _prior(connection, cases, keys_by_case)
        host_days = _host_service_days(connection, cases, keys_by_case)
        match_rows = _host_match_rows(connection, cases, keys_by_case)
        episodes = _episodes(connection, cases)
        host_profile = _host_days(connection, cases)
        whole = _whole_host(connection, cases)
    finally:
        connection.close()

    return HistoryContext(
        path=path,
        coverage=coverage,
        cases={
            (case.indicator, case.host): _case_history(
                case,
                keys_by_case[(case.indicator, case.host)],
                coverage,
                prevalence,
                prior,
                host_days,
                match_rows,
                episodes,
                host_profile,
                whole.get((case.host, case.days[0])),
            )
            for case in cases
        },
    )


def _merge(first: Sequence[ServiceKey], second: Sequence[ServiceKey]) -> tuple[ServiceKey, ...]:
    keys = {key.service_id_hex: key for key in second}
    keys.update({key.service_id_hex: key for key in first})
    return tuple(keys.values())


def _require_service_id_version(connection: duckdb.DuckDBPyConnection) -> None:
    """Fail closed: a hash computed under another version would miss every join, silently."""
    versions = connection.execute(
        "SELECT DISTINCT normalization_version FROM ops.pipeline_run WHERE status = 'published'"
    ).fetchall()
    stale = [row[0] for row in versions if SERVICE_ID_VERSION not in str(row[0]).split("/")]
    if stale:
        raise HistoryError(
            "retained history was hashed under a service-id version other than "
            f"{SERVICE_ID_VERSION}"
        )


def _blobs(hexes: Sequence[str]) -> list[bytes]:
    return [bytes.fromhex(value) for value in hexes]


def _prevalence(
    connection: duckdb.DuckDBPyConnection, service_ids: set[str]
) -> dict[str, tuple[int, int]]:
    if not service_ids:
        return {}
    rows = connection.execute(
        """
        SELECT lower(hex(service_id)), count(DISTINCT client_ip), count(DISTINCT day)
        FROM history.client_service_day
        WHERE service_id IN (SELECT unnest(?::BLOB[]))
        GROUP BY service_id
        """,
        [_blobs(sorted(service_ids))],
    ).fetchall()
    return {str(row[0]): (int(row[1]), int(row[2])) for row in rows}


def _prior(
    connection: duckdb.DuckDBPyConnection,
    cases: Sequence[Case],
    keys_by_case: Mapping[tuple[str, str], Sequence[ServiceKey]],
) -> dict[tuple[str, date], tuple[int, int, date | None, frozenset[int]]]:
    """Campus use of each (service, first match day) in the window before that day."""
    pairs = sorted(
        {
            (key.service_id_hex, case.days[0])
            for case in cases
            for key in keys_by_case[(case.indicator, case.host)]
        }
    )
    if not pairs:
        return {}
    rows = connection.execute(
        """
        WITH key AS (SELECT unnest(?::BLOB[]) AS service_id, unnest(?::DATE[]) AS cutoff)
        SELECT lower(hex(key.service_id)), key.cutoff,
               count(DISTINCT stored.client_ip), count(DISTINCT stored.day), min(stored.day),
               list(DISTINCT stored.asn_id)
        FROM key
        JOIN history.client_service_day AS stored
          ON stored.service_id = key.service_id
         AND stored.day >= key.cutoff - ?::INTEGER AND stored.day < key.cutoff
        GROUP BY ALL
        """,
        [_blobs([s for s, _ in pairs]), [d for _, d in pairs], PRIOR_WINDOW_DAYS],
    ).fetchall()
    return {
        (str(row[0]), row[1]): (
            int(row[2]),
            int(row[3]),
            row[4],
            frozenset(int(asn) for asn in row[5] if asn),
        )
        for row in rows
    }


def _host_service_days(
    connection: duckdb.DuckDBPyConnection,
    cases: Sequence[Case],
    keys_by_case: Mapping[tuple[str, str], Sequence[ServiceKey]],
) -> dict[tuple[str, str], tuple[date, ...]]:
    keys = sorted(
        {
            (case.host, key.service_id_hex)
            for case in cases
            for key in keys_by_case[(case.indicator, case.host)]
        }
    )
    if not keys:
        return {}
    rows = connection.execute(
        """
        SELECT key.client_ip, lower(hex(key.service_id)), stored.day
        FROM (SELECT unnest(?::VARCHAR[]) AS client_ip, unnest(?::BLOB[]) AS service_id) AS key
        JOIN history.client_service_day AS stored
          ON stored.client_ip = key.client_ip AND stored.service_id = key.service_id
        GROUP BY ALL
        """,
        [[host for host, _ in keys], _blobs([service_id for _, service_id in keys])],
    ).fetchall()
    days: dict[tuple[str, str], list[date]] = defaultdict(list)
    for host, service_id, day in rows:
        days[(str(host), str(service_id))].append(day)
    return {key: tuple(sorted(value)) for key, value in days.items()}


def _host_match_rows(
    connection: duckdb.DuckDBPyConnection,
    cases: Sequence[Case],
    keys_by_case: Mapping[tuple[str, str], Sequence[ServiceKey]],
) -> dict[tuple[str, str], tuple[HostServiceDay, ...]]:
    """The host's retained rows for each case service on each match day, with the campus row
    count for that service and day (the fan-in `shadow.beacon_candidates` counts)."""
    keys = sorted(
        {
            (case.host, key.service_id_hex, day)
            for case in cases
            for key in keys_by_case[(case.indicator, case.host)]
            for day in case.days
        }
    )
    if not keys:
        return {}
    rows = connection.execute(
        """
        WITH key AS (
            SELECT unnest(?::VARCHAR[]) AS client_ip, unnest(?::BLOB[]) AS service_id,
                   unnest(?::DATE[]) AS day
        ),
        fanin AS (
            SELECT stored.service_id, stored.day, count(*) AS service_rows
            FROM history.client_service_day AS stored
            JOIN (SELECT DISTINCT service_id, day FROM key) AS wanted
              ON stored.service_id = wanted.service_id AND stored.day = wanted.day
            GROUP BY ALL
        )
        SELECT stored.client_ip, lower(hex(stored.service_id)), stored.day,
               stored.active_5m_bitmap, stored.up_bytes, stored.down_bytes,
               stored.transport_protocol, stored.port_group, stored.asn_id,
               stored.large_flow_count, stored.max_large_flow_duration_sec, fanin.service_rows
        FROM key
        JOIN history.client_service_day AS stored
          ON stored.client_ip = key.client_ip AND stored.service_id = key.service_id
         AND stored.day = key.day
        JOIN fanin ON fanin.service_id = stored.service_id AND fanin.day = stored.day
        """,
        [
            [host for host, _, _ in keys],
            _blobs([service_id for _, service_id, _ in keys]),
            [day for _, _, day in keys],
        ],
    ).fetchall()
    found: dict[tuple[str, str], list[HostServiceDay]] = defaultdict(list)
    for row in rows:
        found[(str(row[0]), str(row[1]))].append(
            HostServiceDay(
                day=row[2],
                bitmap=bytes(row[3]),
                up_bytes=int(row[4]),
                down_bytes=int(row[5]),
                transport=int(row[6]),
                port_group=int(row[7]),
                asn_id=int(row[8]),
                large_flow_count=int(row[9]),
                max_large_flow_duration_sec=float(row[10]),
                service_rows_that_day=int(row[11]),
            )
        )
    return {key: tuple(sorted(value, key=lambda r: r.day)) for key, value in found.items()}


def _episodes(
    connection: duckdb.DuckDBPyConnection, cases: Sequence[Case]
) -> dict[tuple[str, date], tuple[Episode, ...]]:
    keys = sorted({(case.host, day) for case in cases for day in case.days})
    if not keys:
        return {}
    # Days published under daily-candidate-feed-v1 live in feed.candidate_episode, whose service_id
    # is a 16-byte blob and whose tier is P1-P3; stream-v2 days carry E1-E3 and a hex service_id.
    rows = connection.execute(
        """
        WITH key AS (SELECT unnest(?::VARCHAR[]) AS client_ip, unnest(?::DATE[]) AS day)
        SELECT episode.client_ip, episode.day, episode.family, episode.tier, episode.service_id,
               episode.service_domain, publication.detector_version
        FROM (
            SELECT stream.client_ip, stream.day, stream.family, stream.evidence_tier AS tier,
                   stream.service_id, stream.service_domain
            FROM feed.episode AS stream
            JOIN key ON stream.client_ip = key.client_ip AND stream.day = key.day
            UNION ALL
            SELECT candidate.client_ip, candidate.day, candidate.family, candidate.priority_tier,
                   lower(hex(candidate.service_id)), NULL::VARCHAR
            FROM feed.candidate_episode AS candidate
            JOIN key ON candidate.client_ip = key.client_ip AND candidate.day = key.day
        ) AS episode
        LEFT JOIN feed.daily_publication AS publication ON publication.day = episode.day
        """,
        [[host for host, _ in keys], [day for _, day in keys]],
    ).fetchall()
    grouped: dict[tuple[str, date], list[Episode]] = defaultdict(list)
    for host, day, family, tier, service_id, service_domain, detector in rows:
        grouped[(str(host), day)].append(
            Episode(
                day=day,
                family=str(family),
                tier=str(tier),
                service_id_hex=str(service_id) if service_id else None,
                service_domain=str(service_domain) if service_domain else None,
                detector=str(detector or ""),
            )
        )
    return {
        key: tuple(sorted(value, key=lambda episode: (episode.tier, episode.family)))
        for key, value in grouped.items()
    }


def _host_days(
    connection: duckdb.DuckDBPyConnection, cases: Sequence[Case]
) -> dict[tuple[str, date], HostDay]:
    keys = sorted({(case.host, day) for case in cases for day in case.days})
    if not keys:
        return {}
    rows = connection.execute(
        """
        WITH key AS (SELECT unnest(?::VARCHAR[]) AS client_ip, unnest(?::DATE[]) AS day),
        campus AS (
            SELECT stored.day,
                   quantile_cont(stored.unique_services, 0.5)
                       FILTER (WHERE stored.unique_services >= ?) AS p50,
                   quantile_cont(stored.unique_services, 0.9)
                       FILTER (WHERE stored.unique_services >= ?) AS p90,
                   quantile_cont(stored.unique_services, 0.99)
                       FILTER (WHERE stored.unique_services >= ?) AS p99
            FROM history.client_day AS stored
            WHERE stored.day IN (SELECT DISTINCT day FROM key)
            GROUP BY stored.day
        )
        SELECT stored.client_ip, stored.day, stored.unique_services, stored.unique_servers,
               stored.up_bytes + stored.down_bytes, stored.large_flow_count,
               campus.p50, campus.p90, campus.p99
        FROM key
        JOIN history.client_day AS stored
          ON stored.client_ip = key.client_ip AND stored.day = key.day
        JOIN campus ON campus.day = stored.day
        """,
        [[host for host, _ in keys], [day for _, day in keys], *[SCORED_MIN_SERVICES] * 3],
    ).fetchall()
    return {
        (str(row[0]), row[1]): HostDay(
            day=row[1],
            unique_services=int(row[2]),
            unique_servers=int(row[3]),
            total_bytes=int(row[4]),
            large_flow_count=int(row[5]),
            campus_p50_services=_optional_float(row[6]),
            campus_p90_services=_optional_float(row[7]),
            campus_p99_services=_optional_float(row[8]),
        )
        for row in rows
    }


def _optional_float(value: object) -> float | None:
    return None if value is None else float(str(value))


def _case_history(
    case: Case,
    keys: Sequence[ServiceKey],
    coverage: Coverage,
    prevalence: Mapping[str, tuple[int, int]],
    prior: Mapping[tuple[str, date], tuple[int, int, date | None, frozenset[int]]],
    host_days: Mapping[tuple[str, str], tuple[date, ...]],
    match_rows: Mapping[tuple[str, str], tuple[HostServiceDay, ...]],
    episodes: Mapping[tuple[str, date], tuple[Episode, ...]],
    host_profile: Mapping[tuple[str, date], HostDay],
    whole_host: WholeHost | None = None,
) -> CaseHistory:
    match_days = case.days
    window_end = match_days[0]
    window_start = window_end - timedelta(days=PRIOR_WINDOW_DAYS)
    retained = coverage.retained_between(window_start, window_end)
    services = []
    for key in keys:
        days = host_days.get((case.host, key.service_id_hex), ())
        addresses, campus_days = prevalence.get(key.service_id_hex, (0, 0))
        before = prior.get((key.service_id_hex, window_end), (0, 0, None, frozenset()))
        services.append(
            ServiceHistory(
                key=key,
                campus_addresses=addresses,
                campus_days=campus_days,
                prior=Prior(
                    window_start=window_start,
                    window_end=window_end,
                    retained_days=retained,
                    addresses=before[0],
                    days=before[1],
                    first_day=before[2],
                    asn_ids=before[3],
                ),
                host_first_day=days[0] if days else None,
                host_days_before=sum(1 for day in days if day < match_days[0]),
                host_days_on_match=sum(1 for day in days if day in match_days),
                host_days_after=sum(1 for day in days if day > match_days[-1]),
                match_rows=match_rows.get((case.host, key.service_id_hex), ()),
            )
        )
    return CaseHistory(
        match_days_retained=tuple(day for day in match_days if day in coverage.retained_days),
        match_days_not_retained=tuple(
            day for day in match_days if day not in coverage.retained_days
        ),
        match_days_unpublished=tuple(
            day for day in match_days if day not in coverage.published_days
        ),
        services=tuple(services),
        episodes=tuple(
            episode for day in match_days for episode in episodes.get((case.host, day), ())
        ),
        host_days=tuple(
            host_profile[(case.host, day)] for day in match_days if (case.host, day) in host_profile
        ),
        whole_host=whole_host,
    )


def _whole_host(
    connection: duckdb.DuckDBPyConnection, cases: Sequence[Case]
) -> dict[tuple[str, date], WholeHost]:
    """Every retained day of each case's host: its span, the stream's episodes on any day, and
    the services it first used on or after the case's first match day. Batched across cases."""
    keys = sorted({(case.host, case.days[0]) for case in cases})
    hosts = sorted({host for host, _ in keys})
    if not hosts:
        return {}
    spans = {
        str(row[0]): (row[1], row[2], int(row[3]), int(row[4]))
        for row in connection.execute(
            """
            SELECT client_ip, min(day), max(day), count(*), count(*) FILTER (WHERE flow_count > 0)
            FROM history.client_day
            WHERE client_ip IN (SELECT unnest(?::VARCHAR[]))
            GROUP BY client_ip
            """,
            [hosts],
        ).fetchall()
    }
    episodes_sql = """
        SELECT client_ip, day, family, evidence_tier AS tier, service_id, service_domain
        FROM feed.episode WHERE client_ip IN (SELECT unnest(?::VARCHAR[]))
        UNION ALL
        SELECT client_ip, day, family, priority_tier, lower(hex(service_id)), NULL::VARCHAR
        FROM feed.candidate_episode WHERE client_ip IN (SELECT unnest(?::VARCHAR[]))
    """
    counts: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    episode_days: dict[str, int] = {}
    for host, family, tier, number in connection.execute(
        f"SELECT client_ip, family, tier, count(*) FROM ({episodes_sql}) AS episode GROUP BY ALL",
        [hosts, hosts],
    ).fetchall():
        counts[str(host)].append((str(family), str(tier), int(number)))
    for host, days in connection.execute(
        f"SELECT client_ip, count(DISTINCT day) FROM ({episodes_sql}) AS episode GROUP BY ALL",
        [hosts, hosts],
    ).fetchall():
        episode_days[str(host)] = int(days)
    superseded_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for host, family, detector, number in connection.execute(
        f"""
        SELECT episode.client_ip, episode.family, publication.detector_version, count(*)
        FROM ({episodes_sql}) AS episode
        JOIN feed.daily_publication AS publication ON publication.day = episode.day
        WHERE episode.family IN (SELECT unnest(?::VARCHAR[]))
        GROUP BY ALL
        """,
        [hosts, hosts, sorted(CORRECTED_IN)],
    ).fetchall():
        if superseded(str(family), str(detector)):
            superseded_counts[str(host)][str(family)] += int(number)
    others: dict[str, list[Episode]] = defaultdict(list)
    for host, day, family, tier, service_id, domain in connection.execute(
        f"""
        SELECT client_ip, day, family, tier, service_id, service_domain
        FROM ({episodes_sql}) AS episode
        WHERE family <> 'relationship'
        QUALIFY row_number() OVER (
            PARTITION BY client_ip ORDER BY day DESC, family, tier, service_id, service_domain
        ) <= ?
        ORDER BY client_ip, day DESC, family, tier, service_id, service_domain
        """,
        [hosts, hosts, WHOLE_HOST_LISTED],
    ).fetchall():
        others[str(host)].append(
            Episode(
                day=day,
                family=str(family),
                tier=str(tier),
                service_id_hex=str(service_id) if service_id else None,
                service_domain=str(domain) if domain else None,
            )
        )
    since: dict[tuple[str, date], tuple[int, list[str]]] = {}
    for host, cutoff, number, services in connection.execute(
        """
        WITH key AS (SELECT unnest(?::VARCHAR[]) AS client_ip, unnest(?::DATE[]) AS cutoff),
        first_use AS (
            SELECT client_ip, service_id, min(day) AS first_day
            FROM history.client_service_day
            WHERE client_ip IN (SELECT client_ip FROM key)
            GROUP BY ALL
        )
        SELECT key.client_ip, key.cutoff, count(*),
               list(lower(hex(first_use.service_id)) ORDER BY first_use.first_day,
                    first_use.service_id)[1:200]
        FROM key
        JOIN first_use ON first_use.client_ip = key.client_ip AND first_use.first_day >= key.cutoff
        GROUP BY ALL
        """,
        [[host for host, _ in keys], [cutoff for _, cutoff in keys]],
    ).fetchall():
        since[(str(host), cutoff)] = (int(number), [str(s) for s in services])
    wanted = sorted({service for _, services in since.values() for service in services})
    names = (
        {
            str(row[0]): str(row[1])
            for row in connection.execute(
                """
                SELECT service_id, min(service_domain)
                FROM feed.episode
                WHERE service_id IN (SELECT unnest(?::VARCHAR[])) AND service_domain IS NOT NULL
                GROUP BY service_id
                """,
                [wanted],
            ).fetchall()
        }
        if wanted
        else {}
    )
    signals = _signals(connection, keys)
    found: dict[tuple[str, date], WholeHost] = {}
    for host, cutoff in keys:
        first, last, retained, addressed = spans.get(host, (None, None, 0, 0))
        number, services = since.get((host, cutoff), (0, []))
        listed = list(dict.fromkeys(names[s] for s in services if s in names))
        found[(host, cutoff)] = WholeHost(
            first_day=first,
            last_day=last,
            retained_days=retained,
            addressed_days=addressed,
            episode_counts=tuple(sorted(counts.get(host, []), key=lambda c: (-c[2], c[0], c[1]))),
            episode_days=episode_days.get(host, 0),
            other_episodes=tuple(others.get(host, [])),
            other_episode_count=sum(
                n for family, _, n in counts.get(host, []) if family != "relationship"
            ),
            services_since_match=number,
            names_since_match=tuple(listed[:WHOLE_HOST_LISTED]),
            superseded=tuple(sorted(superseded_counts.get(host, Counter()).items())),
            signals=signals.get((host, cutoff), ()),
        )
    return found


def _signals(
    connection: duckdb.DuckDBPyConnection, keys: Sequence[tuple[str, date]]
) -> dict[tuple[str, date], tuple[SignalUse, ...]]:
    """Each host's retained use of the cited software signals, batched: one query for all hosts.
    A signal's domains are hashed as the publisher hashes a bare name (`name_key`)."""
    hashed = [
        (service.service_id_hex, signal.key)
        for signal in SOFTWARE_SIGNALS
        for domain in signal.domains
        if (service := name_key(domain)) is not None
    ]
    if not keys or not hashed:
        return {}
    names = {signal.key: signal.name for signal in SOFTWARE_SIGNALS}
    rows = connection.execute(
        """
        WITH wanted AS (SELECT unnest(?::VARCHAR[]) AS client_ip, unnest(?::DATE[]) AS cutoff),
        signal AS (SELECT unnest(?::BLOB[]) AS service_id, unnest(?::VARCHAR[]) AS key)
        SELECT wanted.client_ip, wanted.cutoff, signal.key, count(DISTINCT stored.day),
               count(DISTINCT stored.day) FILTER (
                   WHERE stored.day >= wanted.cutoff - ?::INTEGER AND stored.day < wanted.cutoff
               ),
               min(stored.day), max(stored.day)
        FROM wanted
        JOIN history.client_service_day AS stored ON stored.client_ip = wanted.client_ip
        JOIN signal ON signal.service_id = stored.service_id
        GROUP BY ALL
        """,
        [
            [host for host, _ in keys],
            [cutoff for _, cutoff in keys],
            _blobs([service for service, _ in hashed]),
            [key for _, key in hashed],
            SIGNAL_RECENT_DAYS,
        ],
    ).fetchall()
    found: dict[tuple[str, date], list[SignalUse]] = defaultdict(list)
    for host, cutoff, key, days, recent, first, last in rows:
        found[(str(host), cutoff)].append(
            SignalUse(str(key), names[str(key)], int(days), int(recent), first, last)
        )
    return {
        key: tuple(sorted(uses, key=lambda use: (-use.days, use.key)))
        for key, uses in found.items()
    }


# --- serving addresses ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ServingAddress:
    """An address that met the serving mark (`SERVING_MIN_REMOTES`) on at least one day in the
    window."""

    address: str
    days: int
    first_day: date
    last_day: date
    peak_remotes: int
    """The most outside addresses summed over one day's high-port rows of one served service."""


def read_serving(path: Path, end: date | None = None) -> dict[str, ServingAddress]:
    """Every address that met the serving mark in the `SERVING_WINDOW_DAYS` before `end` (by
    default the store's last retained day), keyed by address. One batched query."""
    if not path.is_file():
        raise HistoryError(f"retained store not found at {path}")
    try:
        connection = duckdb.connect(str(path), read_only=True)
    except duckdb.Error as exc:
        raise HistoryError(
            "cannot open the retained store read-only; the publisher may be running"
        ) from exc
    try:
        _require_service_id_version(connection)
        found = connection.execute(
            "SELECT max(day) FROM history.client_service_day WHERE day <= ?",
            [end or date.max],
        ).fetchone()
        last = found[0] if found else None
        if last is None:
            raise HistoryError("the retained store holds no service row to read")
        return _serving(connection, last - timedelta(days=SERVING_WINDOW_DAYS - 1), last)
    finally:
        connection.close()


def _serving(
    connection: duckdb.DuckDBPyConnection, first: date, last: date
) -> dict[str, ServingAddress]:
    rows = connection.execute(
        """
        SELECT client_ip, count(DISTINCT day), min(day), max(day), max(remotes)
        FROM (
            SELECT day, client_ip, service_id, sum(unique_servers) AS remotes
            FROM history.client_service_day
            WHERE day BETWEEN ? AND ? AND service_basis = 'domain' AND transport_protocol = ?
              AND port_group IN (SELECT unnest(?::UINTEGER[]))
            GROUP BY day, client_ip, service_id
            HAVING sum(unique_servers) >= ? AND count(DISTINCT asn_id) >= ?
        )
        GROUP BY client_ip
        """,
        [first, last, 6, list(HIGH_PORT_GROUPS), SERVING_MIN_REMOTES, SERVING_MIN_NETWORKS],
    ).fetchall()
    return {
        str(host): ServingAddress(str(host), int(days), start, finish, int(peak))
        for host, days, start, finish, peak in rows
    }
