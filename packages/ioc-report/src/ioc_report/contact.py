"""What the host actually did with the flagged address, as separate contacts the rules can judge.

A contact is the minute rows of one kind: one address, transport, port and set of names. The feed
gives the matched minutes; the live source adds every contact with the same addresses on the days
it still holds. Long flows are kept apart and attributed to the contacts they overlap. Timing is
measured at both grains this deployment has fitted: minute buckets on the pair (CASE_STUDY §10)
and the retained 5-minute bitmap on a service (§13).
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from itertools import pairwise

from network_behaviour.evaluation.shadow import BeaconPolicy
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.normalization.service import normalize_asn

from ioc_report.feed import HELD_OPEN_SECONDS, TRANSPORTS, Case, Feed
from ioc_report.history import CaseHistory, HostServiceDay
from ioc_report.knowledge import ECH_OUTER_NAMES, SHARED_NETWORKS, SharedNetwork, clean
from ioc_report.live import AddressDay, LiveContext
from ioc_report.registration import NameAge

# CASE_STUDY §10, measured on (client_ip, server_ip) minute buckets: among pairs with 12-400
# active minutes in a day, CV < 0.15 with a mean gap of at least 1.5 minutes and a span of at
# least 6 h separates a schedule from a contiguous session, and under 50 KB per active minute
# leaves the low-volume channels (74 pairs of 173,707 on 2026-08-18 and 110 of 176,119 on
# 2026-10-21, before the fan-in stage).
REGULAR_MIN_MINUTES = 12
REGULAR_MAX_MINUTES = 400
REGULAR_MAX_CV = 0.15
REGULAR_MIN_MEAN_GAP_MINUTES = 1.5
REGULAR_MIN_SPAN_HOURS = 6.0
LOW_VOLUME_MAX_BYTES_PER_MINUTE = 50_000

# CASE_STUDY §13: the triage repo's fitted 5-minute beacon profile, imported, not copied.
BEACON_POLICY = BeaconPolicy()


def asn_number(raw: str) -> int:
    """The network number in a record's ASN field; 0 when it is empty or unreadable."""
    try:
        return normalize_asn(raw or None)
    except ValueError:
        return 0


@dataclass(frozen=True, slots=True)
class Contact:
    source: str
    """"feed" (the matched minutes) or "live" (re-queried from the source)."""
    server_ip: str
    transport: int
    port: int
    sni: str
    dns: str
    root_domain: str
    asn: str
    minutes: tuple[datetime, ...]
    up_bytes: int
    down_bytes: int
    flows: int

    @property
    def days(self) -> tuple[date, ...]:
        return tuple(sorted({minute.date() for minute in self.minutes}))

    @property
    def ech(self) -> bool:
        return clean(self.sni) in ECH_OUTER_NAMES

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for name in (self.sni, self.dns, self.root_domain) if name)

    @property
    def label(self) -> str:
        transport = TRANSPORTS.get(self.transport, str(self.transport))
        if self.sni:
            name = f"SNI {self.sni}" + (" (ECH outer name)" if self.ech else "")
        elif self.dns:
            name = f"DNS {self.dns}, no SNI"
        elif self.root_domain:
            name = f"root domain {self.root_domain}, no SNI"
        else:
            name = "no name"
        return f"{self.server_ip} {self.port}/{transport}, {name}"


@dataclass(frozen=True, slots=True)
class FlowContact:
    source: str
    server_ip: str
    port: int
    transport: int
    start: datetime
    finish: datetime
    flows: int
    longest_sec: float
    held_open_flows: int
    up_bytes: int
    down_bytes: int
    label: str = ""

    @property
    def day(self) -> date:
        return self.start.date()

    @property
    def text(self) -> str:
        transport = TRANSPORTS.get(self.transport, str(self.transport) or "unknown")
        port = str(self.port) if self.port else "unknown port"
        return f"{self.server_ip} {port}/{transport}"


@dataclass(frozen=True, slots=True)
class PairDay:
    """Minute-grain timing of one pair on one day (CASE_STUDY §10)."""

    server_ip: str
    day: date
    minutes: int
    runs: int
    span_hours: float
    mean_gap_minutes: float | None
    cv: float | None
    total_bytes: int

    @property
    def regular(self) -> bool:
        return (
            REGULAR_MIN_MINUTES <= self.minutes <= REGULAR_MAX_MINUTES
            and self.cv is not None
            and self.mean_gap_minutes is not None
            and self.cv < REGULAR_MAX_CV
            and self.mean_gap_minutes >= REGULAR_MIN_MEAN_GAP_MINUTES
            and self.span_hours >= REGULAR_MIN_SPAN_HOURS
        )

    @property
    def scheduled(self) -> bool:
        """Regular and low volume: §10's stages up to, not including, destination fan-in."""
        return self.regular and self.total_bytes / self.minutes < LOW_VOLUME_MAX_BYTES_PER_MINUTE


@dataclass(frozen=True, slots=True)
class BitmapTiming:
    """The §13 beacon profile on one retained (host, service, day) row."""

    day: date
    active_buckets: int
    mean_gap_minutes: float | None
    cv: float | None
    span_hours: float
    bytes_per_bucket: float
    fanin: int
    regular: bool
    """Contact count, timing variation and span stages passed."""
    beacon: bool
    """Every stage passed, volume and fan-in included."""


@dataclass(frozen=True, slots=True)
class AddressSharing:
    server_ip: str
    feed_domains: int
    """Registered domains this address carried across every host in the feed."""
    live_days: tuple[AddressDay, ...]
    feed_asn: str

    @property
    def most_domains(self) -> int:
        return max([self.feed_domains, *(d.registered_domains for d in self.live_days)])

    @property
    def shared_by_design(self) -> SharedNetwork | None:
        """The network this address is on, where that network shares its addresses by design."""
        for raw in (self.feed_asn, *(asn for day in self.live_days for asn in day.asns)):
            if (network := SHARED_NETWORKS.get(asn_number(raw))) is not None:
                return network
        return None


@dataclass(frozen=True, slots=True)
class Evidence:
    case: Case
    contacts: tuple[Contact, ...]
    flows: tuple[FlowContact, ...]
    """Long flows the decision reads: the feed's, and live ones on days with minute detail."""
    other_flows: tuple[FlowContact, ...]
    """Live long flows on days without minute detail: shown, never attributed or decided on."""
    pair_days: tuple[PairDay, ...]
    addresses: Mapping[str, AddressSharing]
    history: CaseHistory
    live_status: str
    flow_attribution: Mapping[int, tuple[int, ...]] = field(default_factory=dict)
    """Index in `flows` → indexes in `contacts` it overlaps."""
    live_days: tuple[date, ...] = ()
    """Days the live source was re-queried for minute contact."""
    registrations: Mapping[str, NameAge] | None = None
    """Registration dates by registered domain (RDAP). None when the run did not look them up."""
    contact_duplicates: Mapping[int, int] = field(default_factory=dict)
    """Index in `contacts` of a feed contact the live re-query holds in full → the live contact
    with the same traffic. Both are judged, so no decision changes; the traffic is shown once."""
    flow_duplicates: Mapping[int, int] = field(default_factory=dict)
    """Index in `flows` of a feed long flow → the live aggregate that is exactly the same flow."""
    other_flow_duplicates: Mapping[int, int] = field(default_factory=dict)
    """Index in `other_flows` of a live aggregate that repeats feed long flows → the index in
    `flows` of one of those feed flows."""

    def hidden_contact(self, index: int) -> bool:
        return index in self.contact_duplicates

    def hidden_flow(self, index: int) -> bool:
        return index in self.flow_duplicates


def build_evidence(
    case: Case,
    feed: Feed,
    live: LiveContext,
    history: CaseHistory,
    registrations: Mapping[str, NameAge] | None = None,
) -> Evidence:
    contacts = [*_feed_contacts(case), *_live_contacts(case, live)]
    minute_days = set(live.days_queried)
    flows = [
        FlowContact(
            source="feed",
            server_ip=flow.server_ip,
            port=flow.server_port,
            transport=flow.transport,
            start=flow.start,
            finish=flow.finish,
            flows=1,
            longest_sec=flow.duration_sec,
            held_open_flows=int(flow.duration_sec >= HELD_OPEN_SECONDS),
            up_bytes=flow.up_bytes,
            down_bytes=flow.down_bytes,
            label=flow.label,
        )
        for flow in case.long_flows
    ]
    other_flows: list[FlowContact] = []
    for server in case.server_ips:
        for found in live.long_flows.get((case.source_host, server), ()):
            flow = FlowContact(
                source="live",
                server_ip=found.server_ip,
                port=found.port,
                transport=found.transport,
                start=found.first_start,
                finish=found.last_finish,
                flows=found.flows,
                longest_sec=found.longest_sec,
                held_open_flows=found.held_open_flows,
                up_bytes=found.up_bytes,
                down_bytes=found.down_bytes,
            )
            (flows if found.day in minute_days else other_flows).append(flow)
    attribution = {
        index: tuple(
            position
            for position, contact in enumerate(contacts)
            if _overlaps(flow, contact, exact=flow.source == "feed")
        )
        for index, flow in enumerate(flows)
    }
    asns = {row.server_ip: row.asn for row in case.rows if row.asn}
    flow_duplicates, other_duplicates = _duplicate_flows(flows, other_flows)
    return Evidence(
        case=case,
        contacts=tuple(contacts),
        flows=tuple(flows),
        other_flows=tuple(other_flows),
        pair_days=_pair_days(contacts),
        addresses={
            server: AddressSharing(
                server_ip=server,
                feed_domains=(feed.domains_by_address or {}).get(server, 0),
                live_days=live.addresses.get(server, ()),
                feed_asn=asns.get(server, ""),
            )
            for server in case.server_ips
        },
        history=history,
        live_status=live.status,
        flow_attribution=attribution,
        live_days=live.days_queried,
        registrations=registrations,
        contact_duplicates=_duplicate_contacts(contacts, minute_days),
        flow_duplicates=flow_duplicates,
        other_flow_duplicates=other_duplicates,
    )


def _same_kind(left: Contact, right: Contact) -> bool:
    return (left.server_ip, left.transport, left.port, left.sni, left.dns, left.root_domain) == (
        right.server_ip,
        right.transport,
        right.port,
        right.sni,
        right.dns,
        right.root_domain,
    )


def _duplicate_contacts(contacts: Sequence[Contact], minute_days: set[date]) -> dict[int, int]:
    """Feed contacts the live source re-read in full. The live source holds every contact on the
    days it still has, the feed only the matched ones (`_pair_days` reads them the same way), so a
    feed contact whose every day was re-queried and whose every minute a live contact of the same
    kind holds is the same traffic seen twice. Anything less is kept as its own contact."""
    live = [(index, contact) for index, contact in enumerate(contacts) if contact.source == "live"]
    found: dict[int, int] = {}
    for index, contact in enumerate(contacts):
        if contact.source != "feed" or not all(day in minute_days for day in contact.days):
            continue
        same = [(position, other) for position, other in live if _same_kind(other, contact)]
        held = {minute for _, other in same for minute in other.minutes}
        if same and set(contact.minutes) <= held:
            found[index] = next(
                position for position, other in same if set(contact.minutes) & set(other.minutes)
            )
    return found


def _duplicate_flows(
    flows: Sequence[FlowContact], other_flows: Sequence[FlowContact]
) -> tuple[dict[int, int], dict[int, int]]:
    """Feed long flows the live source returned again: per (address, port, transport, day), the
    live aggregate counts exactly as many flows with exactly the same bytes. Only an exact match
    counts; a live day with more flows than the feed matched is shown beside it, as before."""
    groups: dict[tuple[str, int, int, date], list[int]] = defaultdict(list)
    for index, flow in enumerate(flows):
        if flow.source == "feed":
            groups[(flow.server_ip, flow.port, flow.transport, flow.day)].append(index)
    in_flows: dict[int, int] = {}
    in_other: dict[int, int] = {}
    for key, members in groups.items():
        totals = (
            sum(flows[index].flows for index in members),
            sum(flows[index].up_bytes for index in members),
            sum(flows[index].down_bytes for index in members),
        )
        match = next(
            (
                position
                for position, flow in enumerate(flows)
                if flow.source == "live" and _flow_key(flow) == key and _flow_totals(flow) == totals
            ),
            None,
        )
        if match is not None:
            in_flows.update(dict.fromkeys(members, match))
            continue
        other = next(
            (
                position
                for position, flow in enumerate(other_flows)
                if _flow_key(flow) == key and _flow_totals(flow) == totals
            ),
            None,
        )
        if other is not None:
            in_other[other] = members[0]
    return in_flows, in_other


def _flow_key(flow: FlowContact) -> tuple[str, int, int, date]:
    return (flow.server_ip, flow.port, flow.transport, flow.day)


def _flow_totals(flow: FlowContact) -> tuple[int, int, int]:
    return (flow.flows, flow.up_bytes, flow.down_bytes)


def bitmap_timing(row: HostServiceDay, policy: BeaconPolicy = BEACON_POLICY) -> BitmapTiming:
    """`shadow.beacon_candidates`' stages on one row, with its fan-in counted the same way."""
    buckets = ActivityBitmap(row.bitmap).active_buckets()
    count = len(buckets)
    gaps = [right - left for left, right in pairwise(buckets)]
    mean_gap = sum(gaps) / len(gaps) if gaps else None
    cv = None
    if mean_gap:
        cv = (sum((gap - mean_gap) ** 2 for gap in gaps) / len(gaps)) ** 0.5 / mean_gap
    span_hours = (buckets[-1] - buckets[0]) * 5 / 60 if buckets else 0.0
    per_bucket = (row.up_bytes + row.down_bytes) / count if count else 0.0
    regular = (
        policy.min_active_buckets <= count <= policy.max_active_buckets
        and mean_gap is not None
        and cv is not None
        and cv < policy.max_cv
        and mean_gap >= policy.min_mean_gap_buckets
        and span_hours >= policy.min_span_hours
    )
    return BitmapTiming(
        day=row.day,
        active_buckets=count,
        mean_gap_minutes=mean_gap * 5 if mean_gap is not None else None,
        cv=cv,
        span_hours=span_hours,
        bytes_per_bucket=per_bucket,
        fanin=row.service_rows_that_day,
        regular=regular,
        beacon=regular
        and per_bucket < policy.max_bytes_per_active_bucket
        and row.service_rows_that_day <= policy.max_campus_fanin,
    )


def _feed_contacts(case: Case) -> list[Contact]:
    groups: dict[tuple[str, int, int, str, str, str], list[int]] = defaultdict(list)
    for index, row in enumerate(case.rows):
        key = (row.server_ip, row.transport, row.server_port, row.sni, row.dns, row.root_domain)
        groups[key].append(index)
    contacts = []
    ordered = sorted(groups.items(), key=lambda item: (case.rows[item[1][0]].time, item[0]))
    for (server, transport, port, sni, dns, root), indexes in ordered:
        rows = [case.rows[index] for index in indexes]
        contacts.append(
            Contact(
                source="feed",
                server_ip=server,
                transport=transport,
                port=port,
                sni=sni,
                dns=dns,
                root_domain=root,
                asn=next((row.asn for row in rows if row.asn), ""),
                minutes=tuple(sorted({row.time for row in rows})),
                up_bytes=sum(row.up_bytes for row in rows),
                down_bytes=sum(row.down_bytes for row in rows),
                flows=sum(row.flow_count for row in rows),
            )
        )
    return contacts


def _live_contacts(case: Case, live: LiveContext) -> list[Contact]:
    contacts = []
    for server in case.server_ips:
        for found in live.contacts.get((case.source_host, server), ()):
            contacts.append(
                Contact(
                    source="live",
                    server_ip=found.server_ip,
                    transport=found.transport,
                    port=found.port,
                    sni=found.sni,
                    dns=found.dns,
                    root_domain=found.root_domain,
                    asn=found.asn,
                    minutes=tuple(
                        datetime.fromtimestamp(epoch * 60, UTC) for epoch in found.minute_epochs
                    ),
                    up_bytes=found.up_bytes,
                    down_bytes=found.down_bytes,
                    flows=found.flows,
                )
            )
    return contacts


def _overlaps(flow: FlowContact, contact: Contact, *, exact: bool) -> bool:
    if contact.server_ip != flow.server_ip:
        return False
    if flow.port and contact.port and flow.port != contact.port:
        return False
    if flow.transport and contact.transport and flow.transport != contact.transport:
        return False
    if not exact:
        return flow.day in contact.days
    start = flow.start.replace(second=0, microsecond=0)
    return any(start <= minute <= flow.finish for minute in contact.minutes)


def _pair_days(contacts: Sequence[Contact]) -> tuple[PairDay, ...]:
    minutes: dict[tuple[str, date], set[datetime]] = defaultdict(set)
    volume: dict[tuple[str, date, str], int] = defaultdict(int)
    for contact in contacts:
        for minute in contact.minutes:
            minutes[(contact.server_ip, minute.date())].add(minute)
        if len(contact.days) == 1:
            key = (contact.server_ip, contact.days[0], contact.source)
            volume[key] += contact.up_bytes + contact.down_bytes
        else:
            # A feed contact spanning days: spread its bytes by its minutes per day.
            for day in contact.days:
                share = sum(1 for m in contact.minutes if m.date() == day) / len(contact.minutes)
                key = (contact.server_ip, day, contact.source)
                volume[key] += int((contact.up_bytes + contact.down_bytes) * share)
    timings = []
    for (server, day), found in sorted(minutes.items()):
        ordered = sorted(found)
        offsets = [int(minute.timestamp() // 60) for minute in ordered]
        gaps = [right - left for left, right in pairwise(offsets)]
        mean_gap = statistics.fmean(gaps) if gaps else None
        timings.append(
            PairDay(
                server_ip=server,
                day=day,
                minutes=len(offsets),
                runs=1 + sum(1 for gap in gaps if gap > 1),
                span_hours=(offsets[-1] - offsets[0]) / 60,
                mean_gap_minutes=mean_gap,
                cv=statistics.pstdev(gaps) / mean_gap if mean_gap else None,
                # The live source holds every contact that day; the feed only matched ones.
                total_bytes=max(
                    volume.get((server, day, "live"), 0), volume.get((server, day, "feed"), 0)
                ),
            )
        )
    return tuple(timings)
