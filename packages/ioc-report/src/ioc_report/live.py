"""Live context from the flow source: bounded, batched, aggregate-only and read-only.

Every query covers all cases at once and goes through the triage repo's SQL guard
(`SqlLoader`/`validate_sql`: four authorized tables, no forbidden identifiers, typed half-open UTC
bounds) and its read-only runner. Nothing here queries one host at a time.

Three phases share one connection. Phase 1 gathers what the decision reads, for every case. Phases
2 and 3 run after the decision and only for review cases, and the decision never reads them: what
else the host did around its contact (2), and every destination it exchanged traffic with on each
day the source still holds, so the case file can show what was new after the contact (3).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import astuple, dataclass, field, replace
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from types import TracebackType

from network_behaviour.config import SourceConfig
from network_behaviour.source.client import (
    ClientLike,
    QueryAudit,
    ReadOnlyQueryRunner,
    SourceQueryError,
    create_source_client,
)
from network_behaviour.source.sql import SqlKind, SqlLoader, SqlQuery
from network_behaviour.time import UtcBounds, UtcDay

from ioc_report.feed import HELD_OPEN_SECONDS, Case
from ioc_report.knowledge import ECH_OUTER_NAMES, THREATFOX

SQL_ROOT = Path(__file__).with_name("sql")

# CASE_STUDY §1: the original probe kept activity_1m for about fifteen days. Two days' margin, so a
# day at the retention edge is labelled expired rather than reported as "no contact". A source that
# says its retention (`SourceConfig.detail_days`) sets the horizon instead (`minute_horizon`); one
# that keeps every loaded day has none, and each case reads the same span after its first match.
MINUTE_HORIZON_DAYS = 13
RETENTION_MARGIN_DAYS = 2
DEFAULT_RETENTION_DAYS = MINUTE_HORIZON_DAYS + RETENTION_MARGIN_DAYS
QUERY_TIMEOUT_SECONDS = 540
CONTEXT_WINDOW_SECONDS = 300

Pair = tuple[str, str]
"""(host as the source writes it, flagged server IP)."""


@dataclass(frozen=True, slots=True)
class PairContact:
    """One kind of contact between a case pair on one day: a transport, port and set of names."""

    day: date
    server_ip: str
    transport: int
    port: int
    sni: str
    root_domain: str
    dns: str
    asn: str
    active_minutes: int
    minute_epochs: tuple[int, ...]
    """Active minutes as Unix minutes (seconds // 60)."""
    up_bytes: int
    down_bytes: int
    flows: int


@dataclass(frozen=True, slots=True)
class AddressDay:
    """How shared one flagged address was on one day (the CASE_STUDY §14 quantity)."""

    day: date
    server_ip: str
    campus_clients: int
    registered_domains: int
    ech_clients: int
    udp_clients: int
    asns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PairFlows:
    """Long flows of one pair on one port and protocol, started on one day."""

    day: date
    server_ip: str
    port: int
    transport: int
    flows: int
    longest_sec: float
    held_open_flows: int
    up_bytes: int
    down_bytes: int
    first_start: datetime
    last_finish: datetime


@dataclass(frozen=True, slots=True)
class ContextRow:
    """One registered domain the host used in a five-minute window around its contact."""

    window_start: datetime
    root_domain: str
    flagged: bool
    active_minutes: int
    addresses: int
    up_bytes: int
    down_bytes: int


@dataclass(frozen=True, slots=True)
class DestinationDay:
    """One destination a review host exchanged traffic with on one day, in either direction: a
    registered domain, or the serving network (ASN) of traffic that carried no name."""

    day: date
    root_domain: str
    network: str
    """The ASN, only when `root_domain` is empty."""
    first_minute: datetime
    active_minutes: int
    up_bytes: int
    down_bytes: int


@dataclass(frozen=True, slots=True)
class LiveContext:
    status: str
    """"queried", "skipped" (--no-live) or "unavailable"."""
    queried_at: datetime | None = None
    latest_day: date | None = None
    """The last complete day the source holds: the wall-clock day, or the source's last loaded day
    when that is earlier and the source keeps every loaded day."""
    retention_days: int | None = DEFAULT_RETENTION_DAYS
    """Days of minute detail the source keeps; None when it keeps every loaded day."""
    days_queried: tuple[date, ...] = ()
    days_expired: tuple[date, ...] = ()
    long_flow_window: UtcBounds | None = None
    contacts: Mapping[Pair, tuple[PairContact, ...]] = field(default_factory=dict)
    addresses: Mapping[str, tuple[AddressDay, ...]] = field(default_factory=dict)
    long_flows: Mapping[Pair, tuple[PairFlows, ...]] = field(default_factory=dict)
    host_context: Mapping[str, tuple[ContextRow, ...]] | None = None
    """Phase 2, keyed by host as the source writes it. None when it was not gathered."""
    context_days: tuple[date, ...] = ()
    destinations: Mapping[str, tuple[DestinationDay, ...]] | None = None
    """Phase 3, keyed by host as the source writes it. None when it was not gathered."""
    destination_days: tuple[date, ...] = ()
    """The days phase 3 read: a host absent from one of them had no traffic with a known remote
    address that day."""
    audits: tuple[QueryAudit, ...] = ()
    error: str | None = None


class _CollectingSink:
    def __init__(self) -> None:
        self.audits: list[QueryAudit] = []

    def record(self, audit: QueryAudit) -> None:
        self.audits.append(audit)


def minute_horizon(config: SourceConfig) -> int | None:
    """Days of minute detail worth querying: the source's retention less the margin, or None when
    the source keeps every loaded day."""
    return horizon_for(config.detail_days)


def horizon_for(retention_days: int | None) -> int | None:
    if retention_days is None:
        return None
    return max(retention_days - RETENTION_MARGIN_DAYS, 0)


def after_days(live: LiveContext, case: Case) -> tuple[date, ...]:
    """The phase 3 days this case's after view reads. Under a retention horizon every case shares
    the horizon's days; with none, each case has its own span from the day before its first match
    (`LiveSession.add_destinations`)."""
    if live.retention_days is not None:
        return live.destination_days
    start = case.days[0] - timedelta(days=1)
    end = start + timedelta(days=MINUTE_HORIZON_DAYS)
    return tuple(day for day in live.destination_days if start <= day <= end)


def after_rows(live: LiveContext, case: Case) -> tuple[DestinationDay, ...]:
    """The host's phase 3 rows on this case's `after_days`."""
    rows = (live.destinations or {}).get(case.source_host, ())
    if live.retention_days is not None:
        return rows
    days = set(after_days(live, case))
    return tuple(row for row in rows if row.day in days)


def plan_days(
    cases: Sequence[Case], latest: UtcDay, horizon_days: int | None = MINUTE_HORIZON_DAYS
) -> tuple[tuple[date, ...], tuple[date, ...]]:
    """Match days still inside the minute horizon, plus the latest complete day; and the rest.
    With no horizon nothing has expired."""
    match_days = {day for case in cases for day in case.days}
    if horizon_days is None:
        return tuple(sorted(match_days | {latest.value})), ()
    horizon = latest.value - timedelta(days=horizon_days)
    queried = sorted({day for day in match_days if day >= horizon} | {latest.value})
    expired = sorted(day for day in match_days if day < horizon)
    return tuple(queried), tuple(expired)


def is_address_fragment(name: str) -> bool:
    """A TLS name that was an address (a visitor asking for the server by its address, perhaps with
    a port) reaches the source's root_domain as its last octets: `2.10`, `10:80`. A name with no
    letter names nothing, and on an inbound list it is a piece of the campus host's own address,
    which must not reach a model."""
    return bool(name) and not any(character.isalpha() for character in name)


def _from_another_list(review: Sequence[Case]) -> bool:
    """One list per run. ThreatFox rows stay as they are: its case files are the evaluated input."""
    return bool(review) and review[0].listing.source != THREATFOX.source


def reads_after_view(case: Case, horizon: date) -> bool:
    """Whether the days after a case can be read. On ThreatFox, its first match day must be inside
    the horizon, as its evaluated case files assume. On another list a later match day is enough:
    the days around that contact are readable, and retained use says what is new to the host."""
    if case.listing.source == THREATFOX.source:
        return case.days[0] >= horizon
    return case.days[-1] >= horizon


class LiveSession:
    """One read-only connection for both phases. A failure is labelled, never raised."""

    def __init__(
        self,
        client: ClientLike | None,
        error: str | None = None,
        *,
        retention_days: int | None = DEFAULT_RETENTION_DAYS,
    ) -> None:
        self._sink = _CollectingSink()
        self._runner = ReadOnlyQueryRunner(client, self._sink) if client is not None else None
        self._error = error
        self._loader = SqlLoader(SQL_ROOT)
        self.retention_days = retention_days
        """Days of minute detail the source keeps; None when it keeps every loaded day."""
        self.horizon_days = horizon_for(retention_days)
        """Days of minute detail worth querying, back from the latest day; None with no limit."""

    @classmethod
    def connect(cls, config: SourceConfig) -> LiveSession:
        try:
            return cls(create_source_client(config), retention_days=config.detail_days)
        except Exception as exc:
            return cls(
                None,
                f"could not connect to the source ({exc.__class__.__name__})",
                retention_days=config.detail_days,
            )

    def __enter__(self) -> LiveSession:
        return self

    def __exit__(
        self,
        _type: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        if self._runner is not None:
            self._runner.close()

    def gather(self, cases: Sequence[Case], now: datetime) -> LiveContext:
        """Phase 1: minute contact, address sharing and long flows for every case."""
        latest = UtcDay.latest_completed(now)
        days_queried, days_expired = plan_days(cases, latest, self.horizon_days)
        if self._runner is None:
            return LiveContext(
                status="unavailable",
                queried_at=now,
                latest_day=latest.value,
                retention_days=self.retention_days,
                days_expired=days_expired,
                error=self._error,
            )
        pairs = sorted({(case.source_host, server) for case in cases for server in case.server_ips})
        pair_keys = [f"{host} {server}" for host, server in pairs]
        servers = sorted({server for _host, server in pairs})
        first_day = min(case.first.date() for case in cases) - timedelta(days=1)
        window = UtcBounds(datetime.combine(first_day, time.min, tzinfo=UTC), now)
        minutes_sql = self._load("ioc_pair_minutes", 2)
        address_sql = self._load("ioc_address_profile", 1)
        flows_sql = self._load("ioc_pair_long_flows", 2)
        contacts: dict[Pair, list[PairContact]] = defaultdict(list)
        addresses: dict[str, list[AddressDay]] = defaultdict(list)
        long_flows: dict[Pair, list[PairFlows]] = defaultdict(list)
        try:
            if self.horizon_days is None:
                # A source that keeps every loaded day may end before the wall clock does (older
                # logs, a pinned demo): read and report no day it never loaded.
                latest = self._loaded_through(latest, window)
                days_queried, days_expired = plan_days(cases, latest, self.horizon_days)
            for day in days_queried:
                bounds = UtcDay(day).bounds
                outcome = self._runner.run(
                    minutes_sql, bounds=bounds, parameters={"servers": servers, "pairs": pair_keys}
                )
                for row in outcome.dictionaries():
                    contacts[(str(row["client_ip"]), str(row["server_ip"]))].append(
                        PairContact(
                            day=day,
                            server_ip=str(row["server_ip"]),
                            transport=int(row["transport_protocol"]),
                            port=int(row["server_port"]),
                            sni=str(row["sni"] or ""),
                            root_domain=str(row["root_domain"] or ""),
                            dns=str(row["dns"] or ""),
                            asn=str(row["asn"] or ""),
                            active_minutes=int(row["active_minutes"]),
                            minute_epochs=tuple(int(value) for value in row["minute_epochs"]),
                            up_bytes=int(row["sent_bytes"]),
                            down_bytes=int(row["received_bytes"]),
                            flows=int(row["flows"]),
                        )
                    )
                outcome = self._runner.run(
                    address_sql,
                    bounds=bounds,
                    parameters={"servers": servers, "ech_names": sorted(ECH_OUTER_NAMES)},
                )
                for row in outcome.dictionaries():
                    addresses[str(row["server_ip"])].append(
                        AddressDay(
                            day=day,
                            server_ip=str(row["server_ip"]),
                            campus_clients=int(row["campus_clients"]),
                            registered_domains=int(row["registered_domains"]),
                            ech_clients=int(row["ech_clients"]),
                            udp_clients=int(row["udp_clients"]),
                            asns=tuple(str(asn) for asn in row["asns"] if asn),
                        )
                    )
            outcome = self._runner.run(
                flows_sql,
                bounds=window,
                parameters={"pairs": pair_keys, "held_open_sec": HELD_OPEN_SECONDS},
            )
            for row in outcome.dictionaries():
                long_flows[(str(row["client_ip"]), str(row["server_ip"]))].append(
                    PairFlows(
                        day=_as_date(row["start_day"]),
                        server_ip=str(row["server_ip"]),
                        port=int(row["server_port"]),
                        transport=int(row["protocol"]),
                        flows=int(row["flows"]),
                        longest_sec=float(row["longest_sec"]),
                        held_open_flows=int(row["held_open_flows"]),
                        up_bytes=int(row["flow_up_bytes"]),
                        down_bytes=int(row["flow_down_bytes"]),
                        first_start=_from_micros(row["first_start_us"]),
                        last_finish=_from_micros(row["last_finish_us"]),
                    )
                )
        except SourceQueryError as exc:
            return LiveContext(
                status="unavailable",
                queried_at=now,
                latest_day=latest.value,
                retention_days=self.retention_days,
                days_expired=days_expired,
                audits=tuple(self._sink.audits),
                error=str(exc),
            )
        return LiveContext(
            status="queried",
            queried_at=now,
            latest_day=latest.value,
            retention_days=self.retention_days,
            days_queried=days_queried,
            days_expired=days_expired,
            long_flow_window=window,
            contacts={
                pair: tuple(sorted(rows, key=_contact_order)) for pair, rows in contacts.items()
            },
            addresses={
                server: tuple(sorted(rows, key=astuple)) for server, rows in addresses.items()
            },
            long_flows={
                pair: tuple(sorted(rows, key=astuple)) for pair, rows in long_flows.items()
            },
            audits=tuple(self._sink.audits),
        )

    def add_host_context(self, live: LiveContext, review: Sequence[Case]) -> LiveContext:
        """Phase 2, review cases only: the host's other destinations around each contact minute
        on match days still inside the minute horizon."""
        if self._runner is None or live.status != "queried" or not review:
            return live
        windows: dict[date, set[str]] = defaultdict(set)
        for case in review:
            for minute in case.minutes:
                if minute.date() not in live.days_queried:
                    continue
                bucket = int(minute.timestamp()) // CONTEXT_WINDOW_SECONDS
                for offset in (-1, 0, 1):
                    windows[minute.date()].add(f"{case.source_host} {bucket + offset}")
        if not windows:
            return replace(live, host_context={})
        query = self._load("ioc_host_context", 2)
        hosts = sorted({case.source_host for case in review})
        servers = sorted({server for case in review for server in case.server_ips})
        rows: dict[str, list[ContextRow]] = defaultdict(list)
        drop_fragments = _from_another_list(review)
        try:
            for day, keys in sorted(windows.items()):
                outcome = self._runner.run(
                    query,
                    bounds=UtcDay(day).bounds,
                    parameters={"hosts": hosts, "servers": servers, "windows": sorted(keys)},
                )
                for row in outcome.dictionaries():
                    if drop_fragments and is_address_fragment(str(row["root_domain"] or "")):
                        continue
                    rows[str(row["client_ip"])].append(
                        ContextRow(
                            window_start=datetime.fromtimestamp(
                                int(row["bucket"]) * CONTEXT_WINDOW_SECONDS, UTC
                            ),
                            root_domain=str(row["root_domain"] or ""),
                            flagged=bool(row["flagged"]),
                            active_minutes=int(row["active_minutes"]),
                            addresses=int(row["addresses"]),
                            up_bytes=int(row["sent_bytes"]),
                            down_bytes=int(row["received_bytes"]),
                        )
                    )
        except SourceQueryError as exc:
            return replace(
                live,
                audits=tuple(self._sink.audits),
                error=f"host context unavailable: {exc}",
            )
        return replace(
            live,
            host_context={host: tuple(found) for host, found in rows.items()},
            context_days=tuple(sorted(windows)),
            audits=tuple(self._sink.audits),
        )

    def add_destinations(self, live: LiveContext, review: Sequence[Case]) -> LiveContext:
        """Phase 3, review cases only: every destination each host exchanged traffic with on every
        day it reads, one query per day so none reads more than a day of the source.

        Under a retention horizon the days are the horizon's, and only cases whose first match day
        is still inside it are read: without the days around the contact there is nothing to
        compare. A source that keeps every loaded day has no horizon: each case reads the span the
        original horizon gave, from the day before its first match to 13 days later or the latest
        day, so an old match costs no more queries and a later case still sees its own after-days.
        The days read are the union of those spans (`after_days` gives each case its own)."""
        if self._runner is None or live.status != "queried" or not review or not live.latest_day:
            return live
        latest = live.latest_day
        # (first day, last day) of the span each readable case's host is read on.
        spans: list[tuple[str, date, date]] = []
        if self.horizon_days is None:
            for case in review:
                start = case.days[0] - timedelta(days=1)
                if start <= latest:
                    last = min(latest, start + timedelta(days=MINUTE_HORIZON_DAYS))
                    spans.append((case.source_host, start, last))
        else:
            horizon = latest - timedelta(days=self.horizon_days)
            spans = [
                (case.source_host, horizon, latest)
                for case in review
                if reads_after_view(case, horizon)
            ]
        # Each day reads only the hosts whose span covers it, still one batched query per day.
        hosts_on: dict[date, set[str]] = defaultdict(set)
        for host, start, last in spans:
            for offset in range((last - start).days + 1):
                hosts_on[start + timedelta(days=offset)].add(host)
        if not hosts_on:
            return replace(live, destinations={})
        days = tuple(sorted(hosts_on))
        query = self._load("ioc_host_after", 1)
        rows: dict[str, list[DestinationDay]] = defaultdict(list)
        drop_fragments = _from_another_list(review)
        try:
            for day in days:
                outcome = self._runner.run(
                    query, bounds=UtcDay(day).bounds, parameters={"hosts": sorted(hosts_on[day])}
                )
                for row in outcome.dictionaries():
                    if drop_fragments and is_address_fragment(str(row["root_domain"] or "")):
                        continue
                    rows[str(row["client_ip"])].append(
                        DestinationDay(
                            day=day,
                            root_domain=str(row["root_domain"] or ""),
                            network=str(row["network"] or ""),
                            first_minute=_as_utc(row["first_minute"]),
                            active_minutes=int(row["active_minutes"]),
                            up_bytes=int(row["sent_bytes"]),
                            down_bytes=int(row["received_bytes"]),
                        )
                    )
        except SourceQueryError as exc:
            return replace(
                live,
                audits=tuple(self._sink.audits),
                error=f"destinations unavailable: {exc}",
            )
        return replace(
            live,
            destinations={host: tuple(sorted(found, key=astuple)) for host, found in rows.items()},
            destination_days=days,
            audits=tuple(self._sink.audits),
        )

    def _loaded_through(self, latest: UtcDay, window: UtcBounds) -> UtcDay:
        """The earlier of `latest` and the last day the source holds minute detail for in the
        window; `latest` when it holds none."""
        assert self._runner is not None
        outcome = self._runner.run(self._load("ioc_source_extent", 1), bounds=window)
        rows = list(outcome.dictionaries())
        last = rows[0]["last_minute"] if rows else None
        if last is None:
            return latest
        loaded = _as_utc(last).date()
        return UtcDay(loaded) if loaded < latest.value else latest

    def _load(self, name: str, version: int) -> SqlQuery:
        return self._loader.load(
            name, version, timeout_seconds=QUERY_TIMEOUT_SECONDS, kind=SqlKind.DATA
        )


def _from_micros(value: object) -> datetime:
    return datetime.fromtimestamp(int(str(value)) / 1_000_000, UTC)


def _contact_order(contact: PairContact) -> tuple[object, ...]:
    """The source returns grouped rows in no fixed order. Sorting them, by first active minute and
    then by every field, keeps the case file the model reads identical between runs on the same
    data."""
    return (contact.day, contact.minute_epochs[:1], astuple(contact))


def _as_utc(value: object) -> datetime:
    """A source `DateTime` column: naive values are UTC, as the source stores them."""
    found = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return found.replace(tzinfo=UTC) if found.tzinfo is None else found.astimezone(UTC)


def _as_date(value: object) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))
