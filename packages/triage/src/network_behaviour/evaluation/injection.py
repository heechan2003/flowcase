"""§1 sensitivity envelope: synthesise a behaviour, inject it, see whether it surfaces.

`docs/EVALUATION.md` §1 sets four requirements and this module holds itself to all four.

**Synthesise at the source grain.** `activity_1m` records occupied minute buckets with
volumes, not connection events (`CASE_STUDY` §10). An implant is therefore built as
`ActivityObservation` values — five-minute buckets carrying which minutes inside them were
occupied — and folded through the real `DayAggregator`. Nothing here writes a staged row directly.

**Hold out the days.** The injected day is day D and baselines are built from `day < D`, so an
implant can never enter the history it is measured against. `evaluation.replay.seed_history_before`
takes `exclude_days` when a stricter hold-out is wanted.

**Sweep, do not spot-check.** `sweep_profiles` takes grids of amplitude and period. A single
amplitude is a claim, not an envelope, and this module offers no way to report one as the latter.

**Include jitter.** `ImplantProfile.jitter_minutes` perturbs every contact independently. A
schedule with no jitter is the easy case; leave the default and the report says so.

## What the merge can and cannot reproduce

An implant is aggregated on its own and merged into the target host's existing staged rows, because
the day's source observations are transient and are not retained. Merging at the aggregate grain
is exact for anything additive and approximate for anything that needed the underlying sets. The
merge reports which is which per field, and `InjectionFidelity` travels with every result so a
bundle cannot quote a number without the caveat attached.

- **exact** — byte, packet and flow counters, opaque bytes, large-flow counters: additive.
- **exact** — service rows, and every field of a host that was absent from the day: inserted
  verbatim, so an implant on an unobserved host is reproduced faithfully.
- **upper bound** — `unique_*` counters: a synthetic destination and service are new by
  construction, but its ASN and port group may already be among the host's.
- **bounded** — `active_minutes`, `active_5m_buckets`: unioned against the host's service
  bitmaps, which exclude opaque traffic, so occupancy can be slightly overstated.
- **lower bound** — `max_5m_*`, `top_service_*`, `max_large_flow_*`: a maximum of the two, not
  recomputed over merged buckets.
- **unchanged** — `p95_*`: the per-bucket distribution is not recoverable from a staged row.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import timedelta
from random import Random

from network_behaviour.aggregation import (
    ActivityObservation,
    ClientDayRow,
    DayAggregator,
    StagedDay,
)
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.time import UtcDay

MINUTES_PER_DAY = 1440
BUCKETS_PER_DAY = 288

_EXACT_FIELDS = (
    "up_bytes",
    "down_bytes",
    "up_packets",
    "down_packets",
    "flow_count",
    "opaque_bytes",
    "large_flow_count",
    "large_flow_up_bytes",
)
_UPPER_BOUND_FIELDS = (
    "unique_servers",
    "unique_services",
    "unique_routes",
    "unique_asns",
    "unique_port_groups",
)
_BOUNDED_FIELDS = ("active_minutes", "active_5m_buckets")
_LOWER_BOUND_FIELDS = (
    "top_service_up_bytes",
    "top_service_total_bytes",
    "max_5m_up_bytes",
    "max_large_flow_bytes",
    "max_large_flow_duration_sec",
)
_UNCHANGED_FIELDS = (
    "p95_5m_up_bytes",
    "p95_5m_unique_servers",
    "max_5m_unique_servers",
    "p95_5m_unique_services",
    "max_5m_unique_services",
    "p95_5m_unique_port_groups",
    "max_5m_unique_port_groups",
    "p95_bucket_up_rate_p95_bps",
    "max_bucket_up_rate_p95_bps",
)


class InjectionError(ValueError):
    """Raised when an implant cannot be synthesised or merged without misstating the result."""


@dataclass(frozen=True, slots=True)
class ImplantProfile:
    """A synthesised behaviour, described in the terms the envelope is reported in."""

    name: str
    period_minutes: int
    occurrences: int
    up_bytes_per_contact: int
    down_bytes_per_contact: int = 0
    jitter_minutes: int = 0
    minutes_per_contact: int = 1
    flows_per_contact: int = 1
    packets_per_contact: int = 1
    first_contact_minute: int = 0
    domain: str | None = None
    server_ip: str = "192.88.99.1"
    asn: int = 64512
    server_port: int = 443
    transport_protocol: int = 6
    application: str | None = None

    def __post_init__(self) -> None:
        if self.period_minutes <= 0 or self.occurrences <= 0:
            raise InjectionError("an implant needs a positive period and at least one contact")
        if self.minutes_per_contact <= 0 or self.minutes_per_contact > 5:
            raise InjectionError("occupied minutes per contact must fall inside one bucket")
        if self.jitter_minutes < 0:
            raise InjectionError("jitter cannot be negative")
        if self.up_bytes_per_contact < 0 or self.down_bytes_per_contact < 0:
            raise InjectionError("contact volumes cannot be negative")
        if not 0 <= self.first_contact_minute < MINUTES_PER_DAY:
            raise InjectionError("the first contact must fall inside the day")

    @property
    def total_up_bytes(self) -> int:
        return self.up_bytes_per_contact * self.occurrences

    def for_host(self, index: int) -> ImplantProfile:
        """A distinct synthetic destination per host, so implants do not share a service.

        Two hosts contacting the same synthetic service would make it prevalent, and population
        rarity is exactly what the relationship family scores. Batched injection would then
        measure the batch rather than the behaviour.

        The default basis is the ASN, from the private-use range in RFC 6996: it yields a distinct
        `service_id` per host without fabricating a registrable domain, and it carries MEDIUM
        service confidence, so an implant is not capped at E3 the way a `server_ip`-basis service
        is. The address is from the deprecated 6to4 relay prefix — globally unicast, so it passes
        the public-destination check, and assigned to nothing, so it cannot collide with observed
        traffic. Nothing here is ever resolved or contacted.
        """
        if not 0 <= index < 1000:
            raise InjectionError("synthetic destination index is outside the private-use range")
        return replace(
            self,
            name=f"{self.name}#{index}",
            server_ip=f"192.88.99.{1 + index % 254}",
            asn=64512 + index,
            domain=None if self.domain is None else f"implant-{index}-{self.domain}",
        )

    def describe(self) -> str:
        jitter = f"±{self.jitter_minutes}m jitter" if self.jitter_minutes else "no jitter"
        return (
            f"{self.name}: {self.occurrences} contacts every {self.period_minutes}m, "
            f"{self.up_bytes_per_contact:,} up bytes each, {jitter}"
        )


@dataclass(frozen=True, slots=True)
class InjectionFidelity:
    """Which staged fields the merge reproduced, and which it only bounded."""

    host_was_present: bool
    exact: tuple[str, ...]
    upper_bound: tuple[str, ...]
    bounded: tuple[str, ...]
    lower_bound: tuple[str, ...]
    unchanged: tuple[str, ...]

    def render(self) -> str:
        if not self.host_was_present:
            return "exact: the host was absent from the day, so its implant rows are the whole host"
        return "\n".join(
            (
                f"exact:       {', '.join(self.exact)}",
                f"upper bound: {', '.join(self.upper_bound)}",
                f"bounded:     {', '.join(self.bounded)}",
                f"lower bound: {', '.join(self.lower_bound)}",
                f"unchanged:   {', '.join(self.unchanged)}",
            )
        )


@dataclass(frozen=True, slots=True)
class Injection:
    """A staged day with one implant merged in, and the honest account of that merge."""

    staged: StagedDay
    client_ip: str
    profile: ImplantProfile
    service_id_hex: str
    contact_minutes: tuple[int, ...]
    fidelity: InjectionFidelity


def synthesise_activity(
    day: UtcDay,
    client_ip: str,
    profile: ImplantProfile,
    rng: Random,
) -> tuple[tuple[ActivityObservation, ...], tuple[int, ...]]:
    """Build one implant at the source grain. Returns the observations and the occupied minutes."""

    minutes: set[int] = set()
    for index in range(profile.occurrences):
        scheduled = profile.first_contact_minute + index * profile.period_minutes
        if profile.jitter_minutes:
            scheduled += rng.randint(-profile.jitter_minutes, profile.jitter_minutes)
        if not 0 <= scheduled < MINUTES_PER_DAY:
            continue
        for offset in range(profile.minutes_per_contact):
            minute = scheduled + offset
            if minute < MINUTES_PER_DAY:
                minutes.add(minute)
    if not minutes:
        raise InjectionError("the implant schedule placed no contact inside the day")

    contacts = sorted(minutes)
    per_minute_up = max(1, profile.up_bytes_per_contact // profile.minutes_per_contact)
    per_minute_down = profile.down_bytes_per_contact // profile.minutes_per_contact
    by_bucket: dict[int, list[int]] = {}
    for minute in contacts:
        by_bucket.setdefault(minute // 5, []).append(minute % 5)

    observations = tuple(
        ActivityObservation(
            bucket_start=day.bounds.start + timedelta(minutes=5 * bucket),
            client_ip=client_ip,
            server_ip=profile.server_ip,
            server_port=profile.server_port,
            transport_protocol=profile.transport_protocol,
            root_domain=profile.domain,
            sni=None,
            dns=None,
            application=profile.application,
            application_category=None,
            asn=profile.asn,
            up_bytes=per_minute_up * len(offsets),
            down_bytes=per_minute_down * len(offsets),
            up_packets=profile.packets_per_contact * len(offsets),
            down_packets=profile.packets_per_contact * len(offsets),
            flow_count=profile.flows_per_contact * len(offsets),
            minute_offsets=tuple(sorted(offsets)),
        )
        for bucket, offsets in sorted(by_bucket.items())
    )
    return observations, tuple(contacts)


def inject(
    staged: StagedDay,
    client_ip: str,
    profile: ImplantProfile,
    rng: Random,
) -> Injection:
    """Synthesise an implant for `client_ip` and merge it into the staged day."""

    observations, contacts = synthesise_activity(staged.day, client_ip, profile, rng)
    implant = DayAggregator().aggregate(staged.day, observations, (), ())
    if len(implant.client_rows) != 1 or len(implant.service_rows) != 1:
        raise InjectionError("an implant must aggregate to exactly one client and one service row")
    implant_client = implant.client_rows[0]
    implant_service = implant.service_rows[0]

    existing = next((row for row in staged.client_rows if row.client_ip == client_ip), None)
    if any(
        row.client_ip == client_ip and row.service_id == implant_service.service_id
        for row in staged.service_rows
    ):
        raise InjectionError("the implant destination is already a service of this host")

    if existing is None:
        client_rows = (*staged.client_rows, implant_client)
        fidelity = InjectionFidelity(False, (), (), (), (), ())
    else:
        implant_buckets = ActivityBitmap(implant_service.active_5m_bitmap)
        host_buckets = ActivityBitmap()
        for row in staged.service_rows:
            if row.client_ip == client_ip:
                host_buckets = host_buckets | ActivityBitmap(row.active_5m_bitmap)
        client_rows = tuple(
            _merge_client(row, implant_client, implant_buckets, host_buckets)
            if row.client_ip == client_ip
            else row
            for row in staged.client_rows
        )
        fidelity = InjectionFidelity(
            True,
            _EXACT_FIELDS,
            _UPPER_BOUND_FIELDS,
            _BOUNDED_FIELDS,
            _LOWER_BOUND_FIELDS,
            _UNCHANGED_FIELDS,
        )

    merged = replace(
        staged,
        client_rows=tuple(sorted(client_rows, key=lambda row: row.client_ip)),
        service_rows=tuple(
            sorted(
                (*staged.service_rows, implant_service),
                key=lambda row: (
                    row.client_ip,
                    row.service_id,
                    row.asn_id,
                    row.application_category_id,
                    row.transport_protocol,
                    row.port_group,
                ),
            )
        ),
        service_domains={**dict(staged.service_domains), **dict(implant.service_domains)},
    )
    return Injection(
        merged, client_ip, profile, implant_service.service_id.hex(), contacts, fidelity
    )


def _merge_client(
    existing: ClientDayRow,
    implant: ClientDayRow,
    implant_buckets: ActivityBitmap,
    host_buckets: ActivityBitmap,
) -> ClientDayRow:
    """Merge implant totals into a host's staged row, field by field, per the fidelity note."""

    occupied = frozenset(host_buckets.active_buckets())
    new_buckets = sum(1 for index in implant_buckets.active_buckets() if index not in occupied)
    return ClientDayRow(
        day=existing.day,
        client_ip=existing.client_ip,
        # exact — additive
        up_bytes=existing.up_bytes + implant.up_bytes,
        down_bytes=existing.down_bytes + implant.down_bytes,
        up_packets=existing.up_packets + implant.up_packets,
        down_packets=existing.down_packets + implant.down_packets,
        flow_count=existing.flow_count + implant.flow_count,
        opaque_bytes=existing.opaque_bytes + implant.opaque_bytes,
        large_flow_count=existing.large_flow_count + implant.large_flow_count,
        large_flow_up_bytes=existing.large_flow_up_bytes + implant.large_flow_up_bytes,
        # bounded — the host's minute set is not retained, only its service bitmaps
        active_minutes=min(
            MINUTES_PER_DAY,
            existing.active_minutes + min(implant.active_minutes, new_buckets * 5),
        ),
        active_5m_buckets=min(BUCKETS_PER_DAY, existing.active_5m_buckets + new_buckets),
        # upper bound — the destination is new, its ASN and port group may not be
        unique_servers=existing.unique_servers + implant.unique_servers,
        unique_services=existing.unique_services + implant.unique_services,
        unique_routes=existing.unique_routes + implant.unique_routes,
        unique_asns=existing.unique_asns + implant.unique_asns,
        unique_port_groups=existing.unique_port_groups + implant.unique_port_groups,
        # lower bound — a maximum, not recomputed over merged buckets
        top_service_up_bytes=max(existing.top_service_up_bytes, implant.top_service_up_bytes),
        top_service_total_bytes=max(
            existing.top_service_total_bytes, implant.top_service_total_bytes
        ),
        max_5m_up_bytes=max(existing.max_5m_up_bytes, implant.max_5m_up_bytes),
        max_large_flow_bytes=max(existing.max_large_flow_bytes, implant.max_large_flow_bytes),
        max_large_flow_duration_sec=max(
            existing.max_large_flow_duration_sec, implant.max_large_flow_duration_sec
        ),
        # unchanged — the per-bucket distribution is not recoverable from a staged row
        p95_5m_up_bytes=existing.p95_5m_up_bytes,
        p95_5m_unique_servers=existing.p95_5m_unique_servers,
        max_5m_unique_servers=existing.max_5m_unique_servers,
        p95_5m_unique_services=existing.p95_5m_unique_services,
        max_5m_unique_services=existing.max_5m_unique_services,
        p95_5m_unique_port_groups=existing.p95_5m_unique_port_groups,
        max_5m_unique_port_groups=existing.max_5m_unique_port_groups,
        p95_bucket_up_rate_p95_bps=existing.p95_bucket_up_rate_p95_bps,
        max_bucket_up_rate_p95_bps=existing.max_bucket_up_rate_p95_bps,
    )


def sweep_profiles(
    name: str,
    *,
    periods: Sequence[int],
    occurrences: Sequence[int],
    amplitudes: Sequence[int],
    jitter_minutes: int,
    **fixed: object,
) -> tuple[ImplantProfile, ...]:
    """The grid §1 requires: one profile per point of period, occurrence count and amplitude."""

    return tuple(
        ImplantProfile(
            name=f"{name}/p{period}/n{count}/a{amplitude}",
            period_minutes=period,
            occurrences=count,
            up_bytes_per_contact=amplitude,
            jitter_minutes=jitter_minutes,
            **fixed,  # type: ignore[arg-type]
        )
        for period in periods
        for count in occurrences
        for amplitude in amplitudes
    )
