"""Load an IOC-match feed and group it into (indicator, host) cases.

Pure: reads the feed file and nothing else. Every fact here comes from the feed's own copy of the
matched rows, which the report labels as taken from the IOC feed and not re-queried.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from network_behaviour.normalization.ip import IpNormalizationError, NormalizedIp
from network_behaviour.normalization.service import (
    LogicalService,
    ServiceBasis,
    build_logical_service,
)

from ioc_report.knowledge import ECH_OUTER_NAMES, THREATFOX, Listing, clean, under

HOST_KEY = "affected_host"

# CASE_STUDY §8: a long flow of an hour or more was in the top ~5% of long-flow service-days on
# 2026-08-09.
HELD_OPEN_SECONDS = 3600.0

TRANSPORTS = {6: "TCP", 17: "UDP"}


class FeedError(ValueError):
    """The feed file as a whole cannot be read."""


class _RecordError(ValueError):
    """One record cannot be used. Reported, never silently dropped."""


@dataclass(frozen=True, slots=True)
class ListingClaim:
    """What the list says about the indicator. It says nothing about the host."""

    malware: str
    threat_type: str
    confidence: int | None
    source: str = THREATFOX.source
    inbound: bool = False
    """The list names addresses that connect in to their targets (`knowledge.Listing`)."""


@dataclass(frozen=True, slots=True)
class MinuteRow:
    time: datetime
    server_ip: str
    server_port: int
    transport: int
    sni: str
    dns: str
    root_domain: str
    up_bytes: int
    down_bytes: int
    flow_count: int
    asn: str
    asn_org: str
    country: str


@dataclass(frozen=True, slots=True)
class LongFlow:
    flow_id: str
    start: datetime
    finish: datetime
    duration_sec: float
    server_ip: str
    server_port: int
    """0 when the feed does not say (unknown, as in the source)."""
    transport: int
    up_bytes: int
    down_bytes: int
    up_packets: int
    down_packets: int
    label: str
    """The source's own application type for the flow. Shown, never decided on."""


@dataclass(frozen=True, slots=True)
class Service:
    """A destination the host named, hashed exactly as the publisher hashes it."""

    domain: str
    service_id_hex: str
    minutes: int


@dataclass(frozen=True, slots=True)
class Case:
    indicator: str
    indicator_type: str
    host: str
    """Canonical address, as retained history stores it."""
    source_host: str
    """The address exactly as the source writes it, for live queries."""
    listing: ListingClaim
    rows: tuple[MinuteRow, ...]
    long_flows: tuple[LongFlow, ...]
    match_ids: tuple[str, ...]
    other_hosts_same_indicator: int
    claims: tuple[ListingClaim, ...] = ()
    """Every distinct claim the case's records carry. More than one means the records disagree."""
    domains_same_indicator: int = 0
    """Registered domains seen across every host in the feed that matched this indicator, this one
    included. One flagged address carrying many different sites for different hosts is shared
    hosting, which no single case shows on its own."""
    other_indicators: tuple[tuple[str, str], ...] = ()
    """(indicator, ThreatFox malware) of this host's other cases in the feed."""
    matched_first: datetime | None = None
    """The feed's `threatfox.first_seen_utc`, earliest across the case's records. Despite the
    name it is the matched flow's start, not a ThreatFox date (`match.py`, as IOC_Processor's
    `agent/evidence.py` before it).
    Shown, never decided on."""
    matched_last: datetime | None = None
    """The feed's `threatfox.last_seen_utc`, latest across the records: the matched flow's
    finish."""
    threatfox_first_seen: datetime | None = None
    """ThreatFox's own first-seen date, only from the metadata file `ioc-match` writes."""
    threatfox_last_seen: datetime | None = None
    """ThreatFox's own last-seen date, only from the metadata file `ioc-match` writes."""

    @property
    def is_domain(self) -> bool:
        return self.indicator_type == "domain"

    def names_flagged(self, name: str) -> bool:
        """The name is the indicator domain or under it."""
        return self.is_domain and bool(name) and under(name, self.indicator)

    @property
    def consistent_claim(self) -> ListingClaim | None:
        """The claim when every record agrees on malware and threat type, else None."""
        kinds = {(claim.malware, claim.threat_type) for claim in self.claims or (self.listing,)}
        return self.listing if len(kinds) == 1 else None

    @property
    def minutes(self) -> tuple[datetime, ...]:
        return tuple(sorted({row.time for row in self.rows}))

    @property
    def days(self) -> tuple[date, ...]:
        return tuple(sorted({row.time.date() for row in self.rows}))

    @property
    def first(self) -> datetime:
        return min(row.time for row in self.rows)

    @property
    def held_open(self) -> bool:
        return any(flow.duration_sec >= HELD_OPEN_SECONDS for flow in self.long_flows)

    @property
    def server_ips(self) -> tuple[str, ...]:
        return tuple(sorted({row.server_ip for row in self.rows}))

    @property
    def networks(self) -> tuple[str, ...]:
        return tuple(sorted({_network(row) for row in self.rows if row.asn or row.asn_org}))

    def names(self, field: str) -> tuple[str, ...]:
        return tuple(sorted({getattr(row, field) for row in self.rows} - {""}))

    @property
    def ech_names(self) -> tuple[str, ...]:
        return tuple(name for name in self.names("sni") if clean(name) in ECH_OUTER_NAMES)

    @property
    def up_bytes(self) -> int:
        return sum(row.up_bytes for row in self.rows)

    @property
    def down_bytes(self) -> int:
        return sum(row.down_bytes for row in self.rows)

    @property
    def services(self) -> tuple[Service, ...]:
        """Domain-basis services, most-used first. Other bases need fields the feed lacks."""
        minutes: Counter[tuple[str, str]] = Counter()
        for row in self.rows:
            service = logical_service(row.server_ip, row.root_domain, row.sni, row.dns)
            if service is not None and service.basis is ServiceBasis.DOMAIN and service.domain:
                minutes[(service.domain, service.service_id.hex())] += 1
        return tuple(
            Service(domain, service_id, count)
            for (domain, service_id), count in sorted(
                minutes.items(), key=lambda item: (-item[1], item[0])
            )
        )


@dataclass(frozen=True, slots=True)
class Rejected:
    match_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class Feed:
    paths: tuple[Path, ...]
    """Every file read. Several when one export is split into domain and ip:port files."""
    record_count: int
    cases: tuple[Case, ...]
    rejected: tuple[Rejected, ...]
    created_first: str | None
    created_last: str | None
    domains_by_address: Mapping[str, int] | None = None
    """Registered domains (the source's root domain, ECH outer names left out) each server address
    carried across every record in the feed: a lower bound on how many sites it serves."""
    listing: Listing = THREATFOX
    """The list the run read its records as."""

    @property
    def hosts(self) -> int:
        return len({case.host for case in self.cases})

    @property
    def indicators(self) -> int:
        return len({case.indicator for case in self.cases})

    @property
    def domain_indicators(self) -> frozenset[str]:
        return frozenset(clean(case.indicator) for case in self.cases if case.is_domain)


def logical_service(
    server_ip: str, root_domain: str = "", sni: str = "", dns: str = ""
) -> LogicalService | None:
    """The service exactly as the publisher hashes it, from the fields the feed carries."""
    try:
        server = NormalizedIp.parse(server_ip)
    except IpNormalizationError:
        return None
    return build_logical_service(
        server_ip=server,
        root_domain=root_domain or None,
        sni=sni or None,
        dns=dns or None,
        application=None,
        asn=None,
    )


@dataclass(frozen=True, slots=True)
class _Record:
    match_id: str
    created_at: str
    indicator: str
    indicator_type: str
    host: str
    source_host: str
    listing: ListingClaim
    rows: tuple[MinuteRow, ...]
    long_flows: tuple[LongFlow, ...]
    matched_first: datetime | None = None
    matched_last: datetime | None = None


def load_feed(path: Path, listing: Listing = THREATFOX) -> Feed:
    """A JSON array of match records, or JSON Lines (`.jsonl`, one record per line)."""
    return load_feeds([path], listing)


def load_feeds(paths: Sequence[Path], listing: Listing = THREATFOX) -> Feed:
    """Several files read as one feed: the domain and ip:port halves of one export, so that the
    rules see every indicator of the export when they ask whether a name is another indicator.
    `listing` says where the records keep what their list says; one list per run."""
    if not paths:
        raise FeedError("no feed file given")
    records: list[_Record] = []
    rejected: list[Rejected] = []
    count = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise FeedError(f"cannot read feed {path}: {exc.strerror}") from exc
        suffix = path.suffix.lower()
        raw = _json_lines(path, text) if suffix == ".jsonl" else _json_array(path, text)
        count += len(raw)
        for index, item in enumerate(raw):
            try:
                records.append(_parse_record(item, listing))
            except _RecordError as exc:
                match_id = item.get("match_id") if isinstance(item, Mapping) else None
                label = match_id if isinstance(match_id, str) and match_id else f"record {index}"
                if len(paths) > 1:
                    label = f"{path.name}: {label}"
                rejected.append(Rejected(label, str(exc)))

    created = sorted(record.created_at for record in records if record.created_at)
    domains: dict[str, set[str]] = defaultdict(set)
    for row in (row for record in records for row in record.rows):
        if row.root_domain and clean(row.root_domain) not in ECH_OUTER_NAMES:
            domains[row.server_ip].add(clean(row.root_domain))
    return Feed(
        paths=tuple(paths),
        record_count=count,
        cases=_group(records),
        rejected=tuple(rejected),
        created_first=created[0] if created else None,
        created_last=created[-1] if created else None,
        domains_by_address={address: len(names) for address, names in domains.items()},
        listing=listing,
    )


def load_listing_dates(path: Path) -> dict[str, tuple[datetime | None, datetime | None]]:
    """ThreatFox's own first and last seen dates per indicator, from the `ioc_metadata.json` that
    `ioc-match` writes (`match.write_metadata`):
    `{"indicator": {"threatfox_first_seen": ..., "threatfox_last_seen": ...}}`. The feed carries no
    ThreatFox dates, so these are the only ones. A missing file means none; a malformed date is
    unknown, as in the feed."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FeedError(f"{path} is not readable JSON") from exc
    if not isinstance(data, Mapping):
        raise FeedError(f"{path} must be a JSON object keyed by indicator")
    dates: dict[str, tuple[datetime | None, datetime | None]] = {}
    for indicator, fields in data.items():
        if not isinstance(fields, Mapping):
            continue
        first = _optional_utc(fields, "threatfox_first_seen")
        last = _optional_utc(fields, "threatfox_last_seen")
        if first is not None or last is not None:
            dates[clean(str(indicator))] = (first, last)
    return dates


def with_listing_dates(
    cases: Sequence[Case], dates: Mapping[str, tuple[datetime | None, datetime | None]]
) -> tuple[Case, ...]:
    if not dates:
        return tuple(cases)
    return tuple(
        replace(case, threatfox_first_seen=found[0], threatfox_last_seen=found[1])
        if (found := dates.get(clean(case.indicator))) is not None
        else case
        for case in cases
    )


def _json_array(path: Path, text: str) -> list[Any]:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FeedError(f"feed {path.name} is not valid JSON ({exc.msg})") from exc
    if not isinstance(raw, list):
        raise FeedError("the feed must be a JSON array of match records, or a .jsonl file")
    return raw


def _json_lines(path: Path, text: str) -> list[Any]:
    """A line that is not JSON fails the whole feed, naming the line: a silently skipped line
    would be a silently dropped match."""
    raw = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise FeedError(
                f"feed {path.name} line {number} is not valid JSON ({exc.msg})"
            ) from exc
    return raw


def _group(records: list[_Record]) -> tuple[Case, ...]:
    grouped: dict[tuple[str, str], list[_Record]] = defaultdict(list)
    for record in records:
        grouped[(record.indicator, record.host)].append(record)
    hosts_per_indicator = Counter(indicator for indicator, _host in grouped)

    cases = []
    for (indicator, host), members in grouped.items():
        members.sort(key=lambda record: (record.created_at, record.match_id))
        flows: dict[str, LongFlow] = {}
        for flow in (flow for record in members for flow in record.long_flows):
            kept = flows.get(flow.flow_id)
            if kept is None or flow.duration_sec > kept.duration_sec:
                flows[flow.flow_id] = flow
        cases.append(
            Case(
                indicator=indicator,
                indicator_type=members[0].indicator_type,
                host=host,
                source_host=members[0].source_host,
                listing=members[-1].listing,
                rows=tuple(
                    sorted(
                        (row for record in members for row in record.rows),
                        key=lambda row: (row.time, row.server_ip, row.server_port),
                    )
                ),
                long_flows=tuple(
                    sorted(flows.values(), key=lambda flow: (flow.start, flow.flow_id))
                ),
                match_ids=tuple(record.match_id for record in members),
                other_hosts_same_indicator=hosts_per_indicator[indicator] - 1,
                claims=tuple(dict.fromkeys(record.listing for record in members)),
                matched_first=min(
                    (r.matched_first for r in members if r.matched_first is not None), default=None
                ),
                matched_last=max(
                    (r.matched_last for r in members if r.matched_last is not None), default=None
                ),
            )
        )
    domains: dict[str, set[str]] = defaultdict(set)
    for case in cases:
        domains[case.indicator].update(
            clean(row.root_domain)
            for row in case.rows
            if row.root_domain and clean(row.root_domain) not in ECH_OUTER_NAMES
        )
    by_host: dict[str, list[Case]] = defaultdict(list)
    for case in cases:
        by_host[case.host].append(case)
    cases = [
        replace(
            case,
            domains_same_indicator=len(domains[case.indicator]),
            other_indicators=tuple(
                sorted(
                    (other.indicator, other.listing.malware)
                    for other in by_host[case.host]
                    if other.indicator != case.indicator
                )
            ),
        )
        for case in cases
    ]
    return tuple(sorted(cases, key=lambda case: (case.first, case.indicator, case.host)))


def _network(row: MinuteRow) -> str:
    label = " ".join(part for part in (f"AS{row.asn}" if row.asn else "", row.asn_org) if part)
    return f"{label} ({row.country})" if row.country else label


def _parse_record(item: Any, listing: Listing = THREATFOX) -> _Record:
    if not isinstance(item, Mapping):
        raise _RecordError("record is not an object")
    source_host = _text(item, HOST_KEY)
    try:
        host = NormalizedIp.parse(source_host).value
    except IpNormalizationError as exc:
        raise _RecordError(f"{HOST_KEY} is not an IP address") from exc

    claim = _object(item, listing.claim_field) if listing.claim_field else {}
    evidence = _object(item, "evidence")
    rows = tuple(_minute_row(row, source_host) for row in _list(evidence, "activity"))
    if not rows:
        raise _RecordError("record carries no matched traffic row")
    confidence = claim.get("confidence")
    indicator = _text(item, listing.indicator_field)
    indicator_type = _text(item, "indicator_type")
    if listing.address_only and indicator_type == "ip:port":
        indicator, indicator_type = indicator.rpartition(":")[0].strip("[]"), "ip"
    return _Record(
        match_id=_text(item, "match_id"),
        created_at=_optional_text(item, "created_at"),
        indicator=indicator,
        indicator_type=indicator_type,
        host=host,
        source_host=source_host,
        listing=ListingClaim(
            malware=_optional_text(claim, "malware") or listing.family,
            threat_type=_optional_text(claim, "threat_type") or listing.threat_type,
            confidence=confidence if isinstance(confidence, int) else None,
            source=listing.source,
            inbound=listing.inbound,
        ),
        rows=rows,
        long_flows=tuple(_long_flow(flow) for flow in _list(evidence, "long_flows")),
        matched_first=_optional_utc(claim, "first_seen_utc"),
        matched_last=_optional_utc(claim, "last_seen_utc"),
    )


def _minute_row(row: Any, source_host: str) -> MinuteRow:
    if not isinstance(row, Mapping):
        raise _RecordError("activity row is not an object")
    if _text(row, "client_ip") != source_host:
        raise _RecordError("an evidence row names a different client than the record")
    return MinuteRow(
        time=_utc(_text(row, "time")),
        server_ip=_text(row, "server_ip"),
        server_port=_number(row, "server_port"),
        transport=_number(row, "transport_protocol"),
        sni=_optional_text(row, "sni"),
        dns=_optional_text(row, "dns"),
        root_domain=_optional_text(row, "root_domain"),
        up_bytes=_number(row, "up_bytes"),
        down_bytes=_number(row, "down_bytes"),
        flow_count=_optional_number(row, "flow_count"),
        asn=_optional_text(row, "asn"),
        asn_org=_optional_text(row, "asn_organization"),
        country=_optional_text(row, "country"),
    )


def _long_flow(flow: Any) -> LongFlow:
    if not isinstance(flow, Mapping):
        raise _RecordError("long_flows row is not an object")
    duration = flow.get("duration_sec")
    if not isinstance(duration, int | float) or isinstance(duration, bool):
        raise _RecordError("long_flows row has no duration_sec")
    return LongFlow(
        flow_id=_text(flow, "flow_id"),
        start=_utc(_text(flow, "start")),
        finish=_utc(_text(flow, "finish")),
        duration_sec=float(duration),
        server_ip=_text(flow, "server_ip"),
        server_port=_optional_number(flow, "server_port"),
        transport=_optional_number(flow, "protocol"),
        up_bytes=_number(flow, "up_bytes"),
        down_bytes=_number(flow, "down_bytes"),
        up_packets=_optional_number(flow, "up_packets"),
        down_packets=_optional_number(flow, "down_packets"),
        label=_optional_text(flow, "type"),
    )


def _utc(raw: str) -> datetime:
    try:
        value = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise _RecordError("a timestamp is not ISO formatted") from exc
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _optional_utc(mapping: Mapping[str, Any], key: str) -> datetime | None:
    """A timestamp the decision does not need: missing or malformed means unknown."""
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return _utc(value.strip().replace("Z", "+00:00"))
    except _RecordError:
        return None


def _object(mapping: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = mapping.get(key)
    if not isinstance(value, Mapping):
        raise _RecordError(f"missing or invalid {key}")
    return value


def _list(mapping: Mapping[str, Any], key: str) -> list[Any]:
    value = mapping.get(key, [])
    if not isinstance(value, list):
        raise _RecordError(f"invalid {key}")
    return value


def _text(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _RecordError(f"missing or invalid {key}")
    return value.strip()


def _optional_text(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    return value.strip() if isinstance(value, str) else ""


def _optional_number(mapping: Mapping[str, Any], key: str) -> int:
    """A count the decision does not need: absent means 0, unknown, as the source writes it."""
    if mapping.get(key) is None:
        return 0
    return _number(mapping, key)


def _number(mapping: Mapping[str, Any], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _RecordError(f"missing or invalid {key}")
    return value
