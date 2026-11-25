"""Bounded direct DNS source reader and transient DNS change calibration."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any

from network_behaviour.baselines.models import ClientBaselineContext
from network_behaviour.baselines.statistics import (
    empirical_percentile,
    positive_residual,
    robust_summary,
)
from network_behaviour.detectors.models import DetectorPolicy
from network_behaviour.source.client import QueryAudit, ReadOnlyQueryRunner
from network_behaviour.source.sql import SqlKind, SqlLoader
from network_behaviour.time import UtcBounds, UtcDay, partition_utc_bounds

DNS_QUERY_VERSION = 1
DNS_LOOKBACK_DAYS = 90
DNS_QUERY_SLICE = timedelta(days=7)


class DnsSourceError(ValueError):
    """Raised when the bounded aggregate DNS result is malformed."""


@dataclass(frozen=True, slots=True)
class DnsDailyObservation:
    day: date
    client_ip: str
    resolver_id: str
    complete_sessions: int
    unanswered_sessions: int
    unsolicited_sessions: int
    query_packets: int
    response_packets: int
    unanswered_query_packets: int
    unsolicited_response_packets: int
    weighted_service_nanos: float
    weighted_service_sessions: int

    def __post_init__(self) -> None:
        counters = (
            self.complete_sessions,
            self.unanswered_sessions,
            self.unsolicited_sessions,
            self.query_packets,
            self.response_packets,
            self.unanswered_query_packets,
            self.unsolicited_response_packets,
            self.weighted_service_sessions,
        )
        if any(value < 0 for value in counters) or self.weighted_service_nanos < 0:
            raise DnsSourceError("DNS aggregate values must be non-negative")
        if not self.client_ip or not self.resolver_id:
            raise DnsSourceError("DNS aggregate keys cannot be empty")


@dataclass(frozen=True, slots=True)
class DnsReadResult:
    observations: tuple[DnsDailyObservation, ...]
    audits: tuple[QueryAudit, ...]


@dataclass(frozen=True, slots=True)
class DnsPopulation:
    """Who the DNS family scores on one day, and who it leaves out as a DNS server.

    A DNS client is an address that sent at least one query that day. `dns_pairs` also carries
    addresses that sent none and only received an unsolicited response — 804 of 1,057 on
    2026-08-30, 10,669 on 2026-10-03, none on 2026-10-21 (`CASE_STUDY` §9). They have no
    resolver, no behaviour to score and no place in a denominator. A client that queried at least
    `DetectorPolicy.dns_server_min_resolvers` resolvers is a DNS server, not a stub client.
    """

    day: date
    clients: frozenset[str]
    servers: frozenset[str]


@dataclass(frozen=True, slots=True)
class DnsCalibration:
    metrics: dict[str, tuple[DnsMetric, ...]]
    servers: frozenset[str]


@dataclass(frozen=True, slots=True)
class DnsMetric:
    client_ip: str
    name: str
    observed_value: float
    baseline_value: float | None
    self_strength: float | None
    peer_strength: float | None
    strength: float | None
    support_count: int


class DnsSourceReader:
    """Read D and its source-resident baseline in bounded aggregate-only slices."""

    def __init__(
        self,
        runner: ReadOnlyQueryRunner,
        sql_root: Path,
        *,
        timeout_seconds: int,
    ) -> None:
        self._runner = runner
        self._loader = SqlLoader(sql_root)
        self._timeout_seconds = timeout_seconds

    def read(self, day: UtcDay) -> DnsReadResult:
        query = self._loader.load(
            "dns_daily_observations",
            DNS_QUERY_VERSION,
            timeout_seconds=self._timeout_seconds,
            kind=SqlKind.DATA,
        )
        start = datetime.combine(day.value - timedelta(days=DNS_LOOKBACK_DAYS), time.min, UTC)
        bounds = UtcBounds(start, day.bounds.end)
        observations: list[DnsDailyObservation] = []

        def consume(columns: tuple[str, ...], rows: Sequence[Sequence[Any]]) -> None:
            indexes = _indexes(
                columns,
                {
                    "day",
                    "client_ip",
                    "resolver_id",
                    "complete_sessions",
                    "unanswered_sessions",
                    "unsolicited_sessions",
                    "query_packets",
                    "response_packets",
                    "unanswered_query_packets",
                    "unsolicited_response_packets",
                    "weighted_service_nanos",
                    "weighted_service_sessions",
                },
            )
            observations.extend(_observation(row, indexes) for row in rows)

        audits = tuple(
            self._runner.run_blocks(query, consume, bounds=query_bounds)
            for query_bounds in partition_utc_bounds(bounds, DNS_QUERY_SLICE)
        )
        if any(not start.date() <= row.day <= day.value for row in observations):
            raise DnsSourceError("DNS result contains a day outside its bounded window")
        return DnsReadResult(tuple(observations), audits)


def dns_population_by_day(
    observations: tuple[DnsDailyObservation, ...],
    policy: DetectorPolicy,
) -> dict[date, DnsPopulation]:
    """The DNS population of every day the observations cover. The one definition of it."""
    clients: dict[date, set[str]] = defaultdict(set)
    servers: dict[date, set[str]] = defaultdict(set)
    for row in _aggregate_client_days(observations):
        if not row.query_packets:
            continue
        if len(row.resolvers) >= policy.dns_server_min_resolvers:
            servers[row.day].add(row.client_ip)
        else:
            clients[row.day].add(row.client_ip)
    return {
        day: DnsPopulation(day, frozenset(clients[day]), frozenset(servers[day]))
        for day in sorted(set(clients) | set(servers))
    }


def calibrate_dns_metrics(
    day: UtcDay,
    observations: tuple[DnsDailyObservation, ...],
    clients: Mapping[str, ClientBaselineContext],
    policy: DetectorPolicy,
) -> DnsCalibration:
    """Build transient DNS metric changes without retaining resolver identifiers.

    Only client-days in the DNS population take part, on day D and in history alike: an address
    whose only DNS row was an unsolicited response has no prior DNS day, and a DNS server's day is
    nobody's peer and no part of the denominator.
    """
    if any(row.day > day.value for row in observations):
        raise DnsSourceError("DNS observations cannot be later than day D")
    populations = dns_population_by_day(observations, policy)
    daily = tuple(
        row
        for row in _aggregate_client_days(observations)
        if row.day in populations and row.client_ip in populations[row.day].clients
    )
    today = populations.get(day.value)
    servers = today.servers if today is not None else frozenset()
    history_by_client: dict[str, list[_DnsClientDay]] = defaultdict(list)
    current: dict[str, _DnsClientDay] = {}
    for row in daily:
        if row.day < day.value:
            history_by_client[row.client_ip].append(row)
        elif row.day == day.value:
            current[row.client_ip] = row
    for client_history in history_by_client.values():
        client_history.sort(key=lambda item: item.day)

    current_values: dict[str, dict[str, float]] = {
        client_ip: _metric_values(row) for client_ip, row in current.items()
    }
    pools = _historical_residual_pools(history_by_client, clients)
    peer_lists: dict[tuple[str, str], list[float]] = defaultdict(list)
    for client_ip, metric_values in current_values.items():
        context = clients.get(client_ip)
        if context is None:
            continue
        for name in _DNS_METRIC_NAMES:
            peer_lists[(context.activity_band, name)].append(metric_values[name])
    peer_values = {key: tuple(values) for key, values in peer_lists.items()}
    resolver_clients: dict[str, set[str]] = defaultdict(set)
    for observation in observations:
        if (
            observation.day == day.value
            and observation.query_packets
            and observation.client_ip in current
        ):
            resolver_clients[observation.resolver_id].add(observation.client_ip)
    current_client_count = len(current)

    result: dict[str, tuple[DnsMetric, ...]] = {}
    for client_ip, row in sorted(current.items()):
        if client_ip not in clients:
            continue
        activity_band = clients[client_ip].activity_band
        history = history_by_client.get(client_ip, [])
        metric_values = current_values[client_ip]
        metrics: list[DnsMetric] = []
        prior_resolvers = set().union(*(item.resolvers for item in history)) if history else set()
        sessions = dict(row.resolver_sessions)
        # Novelty is measured against something. A client with no prior DNS day has an empty
        # prior set, so every resolver it used is trivially new. On 2026-08-30 that described 647
        # of the 668 addresses the metric fired for — most of them addresses that had sent no
        # query at all, which the DNS population above now leaves out
        # (`CASE_STUDY.md`, superseded values). A first appearance is still not an observation about
        # the client's behaviour.
        qualifying = (
            sorted(
                value
                for value in row.resolvers - prior_resolvers
                if sessions.get(value, 0) >= policy.dns_new_resolver_min_sessions
            )
            if prior_resolvers
            else []
        )
        if qualifying:
            broadest = max(len(resolver_clients[value]) for value in qualifying)
            novelty_strength = 100.0 * (1.0 - broadest / current_client_count)
            metrics.append(
                DnsMetric(
                    client_ip,
                    "new_resolver",
                    float(len(qualifying)),
                    float(len(prior_resolvers)),
                    None,
                    novelty_strength,
                    novelty_strength,
                    # The sessions the new resolvers carried, not how many there were. A count
                    # of resolvers is what the metric observed, never how much observation is
                    # behind it, and every other DNS metric reports the latter here.
                    sum(sessions.get(value, 0) for value in qualifying),
                )
            )
        for name in _DNS_METRIC_NAMES:
            support = _metric_support(row, name)
            if name in _RATIO_METRICS and not _ratio_supported(row, name, policy):
                continue
            if metric_values[name] <= 0:
                continue
            prior_values = tuple(_metric_values(item)[name] for item in history[-7:])
            summary = robust_summary(prior_values)
            residual = positive_residual(metric_values[name], summary)
            if residual is not None and residual <= 0:
                residual = None
            self_rank = empirical_percentile(residual, pools.get((activity_band, name), ()))
            peers = peer_values.get((activity_band, name), ())
            peer_rank = (
                empirical_percentile(metric_values[name], peers) if len(peers) >= 2 else None
            )
            # DNS-only history can be cold even when retained activity history is mature.
            strength = (
                100.0 * min(self_rank, peer_rank)
                if self_rank is not None and peer_rank is not None
                else (
                    100.0 * peer_rank
                    if peer_rank is not None
                    and len(history) < 8
                    and metric_values[name] > min(peers)
                    else None
                )
            )
            metrics.append(
                DnsMetric(
                    client_ip,
                    name,
                    metric_values[name],
                    summary.median_raw if summary is not None else None,
                    100.0 * self_rank if self_rank is not None else None,
                    100.0 * peer_rank if peer_rank is not None else None,
                    strength,
                    support,
                )
            )
        result[client_ip] = tuple(metrics)
    return DnsCalibration(result, servers)


@dataclass(frozen=True, slots=True)
class _DnsClientDay:
    day: date
    client_ip: str
    # The resolvers this client sent a query to, never one that only answered unasked.
    resolvers: frozenset[str]
    # Sessions observed with each resolver on this day alone, sorted, so a new resolver can be
    # placed against its own volume rather than against the client-day total. The source query
    # already returns this grain; nothing extra is read to keep it.
    resolver_sessions: tuple[tuple[str, int], ...]
    complete_sessions: int
    unanswered_sessions: int
    unsolicited_sessions: int
    query_packets: int
    response_packets: int
    unanswered_query_packets: int
    unsolicited_response_packets: int
    weighted_service_nanos: float
    weighted_service_sessions: int


_DNS_METRIC_NAMES = (
    "session_volume",
    "query_volume",
    "unanswered_session_ratio",
    "unanswered_query_ratio",
    "unsolicited_session_ratio",
    "unsolicited_response_ratio",
    "mean_service_nanos",
)
_RATIO_METRICS = {
    "unanswered_session_ratio",
    "unanswered_query_ratio",
    "unsolicited_session_ratio",
    "unsolicited_response_ratio",
}

DNS_SHARED_CONTEXT_METRICS = frozenset({"mean_service_nanos"})
"""Metrics that describe the resolver rather than the client behind it.

Service time is what a resolver did, measured through whichever of its clients happened to ask:
56.5% of the variance in per-(client, resolver) mean service time on 2026-08-30 sat between
resolvers rather than within them (`CASE_STUDY.md`, superseded values). When a resolver slows, every
client behind it deviates on the same day, so attributing the deviation to a client turns one
resolver incident into a burst of candidates. The detector engine still reports these metrics as
evidence; since `primary-detectors-v7` they no longer establish eligibility or set the family
strength.
"""


def _aggregate_client_days(
    rows: tuple[DnsDailyObservation, ...],
) -> tuple[_DnsClientDay, ...]:
    values: dict[tuple[date, str], dict[str, Any]] = {}
    for row in rows:
        key = (row.day, row.client_ip)
        state = values.setdefault(
            key,
            {
                "resolvers": set(),
                "resolver_sessions": defaultdict(int),
                "complete_sessions": 0,
                "unanswered_sessions": 0,
                "unsolicited_sessions": 0,
                "query_packets": 0,
                "response_packets": 0,
                "unanswered_query_packets": 0,
                "unsolicited_response_packets": 0,
                "weighted_service_nanos": 0.0,
                "weighted_service_sessions": 0,
            },
        )
        # A resolver is something the client asked. A tuple with no query is an unsolicited
        # response arriving from an address the client never used.
        if row.query_packets:
            state["resolvers"].add(row.resolver_id)
        state["resolver_sessions"][row.resolver_id] += (
            row.complete_sessions + row.unanswered_sessions + row.unsolicited_sessions
        )
        for name in (
            "complete_sessions",
            "unanswered_sessions",
            "unsolicited_sessions",
            "query_packets",
            "response_packets",
            "unanswered_query_packets",
            "unsolicited_response_packets",
            "weighted_service_sessions",
        ):
            state[name] += getattr(row, name)
        state["weighted_service_nanos"] += row.weighted_service_nanos
    return tuple(
        _DnsClientDay(
            day=key[0],
            client_ip=key[1],
            resolvers=frozenset(state["resolvers"]),
            resolver_sessions=tuple(sorted(state["resolver_sessions"].items())),
            complete_sessions=int(state["complete_sessions"]),
            unanswered_sessions=int(state["unanswered_sessions"]),
            unsolicited_sessions=int(state["unsolicited_sessions"]),
            query_packets=int(state["query_packets"]),
            response_packets=int(state["response_packets"]),
            unanswered_query_packets=int(state["unanswered_query_packets"]),
            unsolicited_response_packets=int(state["unsolicited_response_packets"]),
            weighted_service_nanos=float(state["weighted_service_nanos"]),
            weighted_service_sessions=int(state["weighted_service_sessions"]),
        )
        for key, state in sorted(values.items())
    )


def _metric_values(row: _DnsClientDay) -> dict[str, float]:
    session_total = row.complete_sessions + row.unanswered_sessions + row.unsolicited_sessions
    unanswered_session_total = row.complete_sessions + row.unanswered_sessions
    unsolicited_session_total = row.complete_sessions + row.unsolicited_sessions
    return {
        "session_volume": float(session_total),
        "query_volume": float(row.query_packets),
        "unanswered_session_ratio": _ratio(row.unanswered_sessions, unanswered_session_total),
        "unanswered_query_ratio": _ratio(row.unanswered_query_packets, row.query_packets),
        "unsolicited_session_ratio": _ratio(row.unsolicited_sessions, unsolicited_session_total),
        "unsolicited_response_ratio": _ratio(
            row.unsolicited_response_packets, row.response_packets
        ),
        "mean_service_nanos": _ratio(row.weighted_service_nanos, row.weighted_service_sessions),
    }


def _historical_residual_pools(
    history_by_client: Mapping[str, list[_DnsClientDay]],
    clients: Mapping[str, ClientBaselineContext],
) -> dict[tuple[str, str], tuple[float, ...]]:
    pools: dict[tuple[str, str], list[float]] = defaultdict(list)
    for client_ip, history in history_by_client.items():
        context = clients.get(client_ip)
        if context is None:
            continue
        for index, row in enumerate(history):
            if index < 8:
                continue
            prior = history[max(0, index - 7) : index]
            current_values = _metric_values(row)
            for name in _DNS_METRIC_NAMES:
                summary = robust_summary(tuple(_metric_values(item)[name] for item in prior))
                residual = positive_residual(current_values[name], summary)
                if residual is not None:
                    pools[(context.activity_band, name)].append(residual)
    return {key: tuple(values) for key, values in pools.items()}


def _ratio(numerator: float, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _ratio_supported(row: _DnsClientDay, name: str, policy: DetectorPolicy) -> bool:
    if name == "unanswered_session_ratio":
        return row.complete_sessions + row.unanswered_sessions >= policy.dns_min_sessions
    if name == "unsolicited_session_ratio":
        return row.complete_sessions + row.unsolicited_sessions >= policy.dns_min_sessions
    if name == "unanswered_query_ratio":
        return row.query_packets >= policy.dns_min_packets
    return row.response_packets >= policy.dns_min_packets


def _metric_support(row: _DnsClientDay, name: str) -> int:
    if name in {"session_volume", "unanswered_session_ratio", "unsolicited_session_ratio"}:
        return row.complete_sessions + row.unanswered_sessions + row.unsolicited_sessions
    if name in {"query_volume", "unanswered_query_ratio"}:
        return row.query_packets
    if name == "unsolicited_response_ratio":
        return row.response_packets
    return row.weighted_service_sessions


def _indexes(columns: Sequence[str], expected: set[str]) -> dict[str, int]:
    missing = expected - set(columns)
    if missing:
        raise DnsSourceError(f"DNS result omitted column {sorted(missing)[0]}")
    return {name: columns.index(name) for name in expected}


def _observation(row: Sequence[Any], indexes: Mapping[str, int]) -> DnsDailyObservation:
    raw_day = row[indexes["day"]]
    if isinstance(raw_day, datetime):
        parsed_day = raw_day.date()
    elif isinstance(raw_day, date):
        parsed_day = raw_day
    else:
        try:
            parsed_day = date.fromisoformat(str(raw_day))
        except ValueError as exc:
            raise DnsSourceError("DNS day is malformed") from exc
    return DnsDailyObservation(
        parsed_day,
        str(row[indexes["client_ip"]]),
        str(row[indexes["resolver_id"]]),
        _integer(row, indexes, "complete_sessions"),
        _integer(row, indexes, "unanswered_sessions"),
        _integer(row, indexes, "unsolicited_sessions"),
        _integer(row, indexes, "query_packets"),
        _integer(row, indexes, "response_packets"),
        _integer(row, indexes, "unanswered_query_packets"),
        _integer(row, indexes, "unsolicited_response_packets"),
        _floating(row, indexes, "weighted_service_nanos"),
        _integer(row, indexes, "weighted_service_sessions"),
    )


def _integer(row: Sequence[Any], indexes: Mapping[str, int], name: str) -> int:
    try:
        value = int(row[indexes[name]])
    except (TypeError, ValueError) as exc:
        raise DnsSourceError(f"DNS {name} is not an integer") from exc
    if value < 0:
        raise DnsSourceError(f"DNS {name} cannot be negative")
    return value


def _floating(row: Sequence[Any], indexes: Mapping[str, int], name: str) -> float:
    try:
        value = float(row[indexes[name]])
    except (TypeError, ValueError) as exc:
        raise DnsSourceError(f"DNS {name} is not numeric") from exc
    if value < 0:
        raise DnsSourceError(f"DNS {name} cannot be negative")
    return value
