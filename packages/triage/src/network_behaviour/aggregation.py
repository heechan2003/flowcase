"""Deterministic day-D aggregation over transient source observations."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from math import isfinite

from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.normalization.ip import IpNormalizationError, NormalizedIp
from network_behaviour.normalization.network import PortGroup, normalize_transport, port_group
from network_behaviour.normalization.service import (
    LogicalService,
    ServiceBasis,
    build_logical_service,
    category_id,
    normalize_asn,
)
from network_behaviour.time import UtcDay

AGGREGATION_VERSION = "day-aggregation-v2"
# Aggregation generations a published day may carry and still stream back. An allow-list for the
# reason `COMPATIBLE_BASELINE_VERSIONS` is one: a published day cannot be re-derived once its source
# has expired, so strict equality would strand the archive the moment this constant moved.
COMPATIBLE_AGGREGATION_VERSIONS = frozenset({AGGREGATION_VERSION})


class AggregationError(ValueError):
    """Raised when transient observations cannot form valid retained rows."""


@dataclass(frozen=True, slots=True)
class ActivityObservation:
    bucket_start: datetime
    client_ip: str
    server_ip: str
    server_port: int | str | None
    transport_protocol: int | str | None
    root_domain: str | None
    sni: str | None
    dns: str | None
    application: str | None
    application_category: str | None
    asn: int | str | None
    up_bytes: int
    down_bytes: int
    up_packets: int
    down_packets: int
    flow_count: int
    minute_offsets: tuple[int, ...]

    def __post_init__(self) -> None:
        _require_non_negative(
            up_bytes=self.up_bytes,
            down_bytes=self.down_bytes,
            up_packets=self.up_packets,
            down_packets=self.down_packets,
            flow_count=self.flow_count,
        )
        if any(not 0 <= offset < 5 for offset in self.minute_offsets):
            raise AggregationError("minute offsets must be between zero and four")


@dataclass(frozen=True, slots=True)
class RateObservation:
    bucket_start: datetime
    client_ip: str
    up_rate_p95_bps: float

    def __post_init__(self) -> None:
        if not isfinite(self.up_rate_p95_bps) or self.up_rate_p95_bps < 0:
            raise AggregationError("rate observation must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class LongFlowObservation:
    start: datetime
    finish: datetime
    client_ip: str
    server_ip: str
    protocol: int | str | None
    server_port: int | str | None
    large_flow_count: int
    large_flow_up_bytes: int
    max_large_flow_bytes: int
    max_large_flow_duration_sec: float

    def __post_init__(self) -> None:
        _require_non_negative(
            large_flow_count=self.large_flow_count,
            large_flow_up_bytes=self.large_flow_up_bytes,
            max_large_flow_bytes=self.max_large_flow_bytes,
        )
        if not isfinite(self.max_large_flow_duration_sec) or self.max_large_flow_duration_sec < 0:
            raise AggregationError("long-flow duration must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class ClientDayRow:
    day: date
    client_ip: str
    up_bytes: int
    down_bytes: int
    up_packets: int
    down_packets: int
    flow_count: int
    active_minutes: int
    active_5m_buckets: int
    unique_servers: int
    unique_services: int
    unique_routes: int
    unique_asns: int
    unique_port_groups: int
    top_service_up_bytes: int
    top_service_total_bytes: int
    opaque_bytes: int
    p95_5m_up_bytes: float
    max_5m_up_bytes: int
    p95_5m_unique_servers: float
    max_5m_unique_servers: int
    p95_5m_unique_services: float
    max_5m_unique_services: int
    p95_5m_unique_port_groups: float
    max_5m_unique_port_groups: int
    p95_bucket_up_rate_p95_bps: float
    max_bucket_up_rate_p95_bps: float
    large_flow_count: int
    large_flow_up_bytes: int
    max_large_flow_bytes: int
    max_large_flow_duration_sec: float

    def values(self) -> tuple[object, ...]:
        return tuple(getattr(self, name) for name in self.__dataclass_fields__)


@dataclass(frozen=True, slots=True)
class ClientServiceDayRow:
    day: date
    client_ip: str
    service_id: bytes
    service_basis: str
    asn_id: int
    application_category_id: int
    transport_protocol: int
    port_group: int
    active_5m_bitmap: bytes
    up_bytes: int
    down_bytes: int
    flow_count: int
    unique_servers: int
    large_flow_count: int
    large_flow_up_bytes: int
    max_large_flow_bytes: int
    max_large_flow_duration_sec: float

    def values(self) -> tuple[object, ...]:
        return tuple(getattr(self, name) for name in self.__dataclass_fields__)


@dataclass(frozen=True, slots=True)
class StagedDay:
    day: UtcDay
    client_rows: tuple[ClientDayRow, ...]
    service_rows: tuple[ClientServiceDayRow, ...]
    aggregation_version: str = AGGREGATION_VERSION
    service_domains: Mapping[bytes, str] = field(default_factory=dict)
    """Current-day `service_id` -> registered domain, for domain-basis services only.

    Deliberately not a field on `ClientServiceDayRow`: that row is bulk-persisted into
    `history.client_service_day`, which must stay hashed for 365 days. This map is read by the
    stream builder and discarded with the run.
    """


@dataclass(frozen=True, slots=True)
class _ServiceKey:
    service_id: bytes
    service_basis: ServiceBasis
    asn_id: int
    application_category_id: int
    transport_protocol: int
    port_group: int


@dataclass(slots=True)
class _ServiceState:
    key: _ServiceKey
    bucket_mask: int = 0
    servers: set[str] = field(default_factory=set)
    up_bytes: int = 0
    down_bytes: int = 0
    flow_count: int = 0
    large_flow_count: int = 0
    large_flow_up_bytes: int = 0
    max_large_flow_bytes: int = 0
    max_large_flow_duration_sec: float = 0


@dataclass(frozen=True, slots=True)
class _ServiceBucket:
    protocol: int
    server_port: int
    key: _ServiceKey


@dataclass(frozen=True, slots=True)
class _ActivityDimensions:
    destination: NormalizedIp | None
    service: LogicalService | None
    asn_id: int
    category_id: int
    transport: int
    port: PortGroup
    raw_port: int


@dataclass(slots=True)
class _ClientState:
    minutes: set[int] = field(default_factory=set)
    buckets: set[int] = field(default_factory=set)
    servers: set[str] = field(default_factory=set)
    services: set[bytes] = field(default_factory=set)
    routes: set[tuple[bytes, int]] = field(default_factory=set)
    asns: set[int] = field(default_factory=set)
    port_groups: set[int] = field(default_factory=set)
    bucket_up: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    bucket_servers: dict[int, set[str]] = field(default_factory=lambda: defaultdict(set))
    bucket_services: dict[int, set[bytes]] = field(default_factory=lambda: defaultdict(set))
    bucket_ports: dict[int, set[int]] = field(default_factory=lambda: defaultdict(set))
    rate_values: dict[int, float] = field(default_factory=dict)
    service_up: dict[bytes, int] = field(default_factory=lambda: defaultdict(int))
    service_total: dict[bytes, int] = field(default_factory=lambda: defaultdict(int))
    up_bytes: int = 0
    down_bytes: int = 0
    up_packets: int = 0
    down_packets: int = 0
    flow_count: int = 0
    opaque_bytes: int = 0
    large_flow_count: int = 0
    large_flow_up_bytes: int = 0
    max_large_flow_bytes: int = 0
    max_large_flow_duration_sec: float = 0


class DayAggregator:
    """Build only the two authoritative retained grains from transient inputs."""

    def aggregate(
        self,
        day: UtcDay,
        activity: tuple[ActivityObservation, ...],
        rates: tuple[RateObservation, ...],
        long_flows: tuple[LongFlowObservation, ...],
    ) -> StagedDay:
        accumulator = DayAccumulator(day)
        for observation in activity:
            accumulator.consume_activity(observation)
        for rate_observation in rates:
            accumulator.consume_rate(rate_observation)
        for long_flow in long_flows:
            accumulator.consume_long_flow(long_flow)
        return accumulator.finish()


class DayAccumulator:
    """Incrementally fold transient blocks into the two authoritative daily grains."""

    def __init__(self, day: UtcDay) -> None:
        self._day = day
        self._bounds = day.bounds
        self._clients: dict[str, _ClientState] = {}
        self._services: dict[tuple[str, _ServiceKey], _ServiceState] = {}
        self._service_domains: dict[bytes, str] = {}
        self._service_buckets: dict[tuple[str, str, int], set[_ServiceBucket]] = defaultdict(set)
        self._client_ip_cache: dict[str, str] = {}
        self._destination_cache: dict[str, NormalizedIp | None] = {}
        self._dimension_cache: dict[tuple[object, ...], _ActivityDimensions] = {}

    def consume_activity(self, observation: ActivityObservation) -> None:
        bucket = self._bucket_index(observation.bucket_start)
        client_ip = self._normalized_client(observation.client_ip)
        client = self._clients.get(client_ip)
        if client is None:
            client = _ClientState()
            self._clients[client_ip] = client
        client.buckets.add(bucket)
        client.minutes.update(bucket * 5 + offset for offset in observation.minute_offsets)
        client.up_bytes += observation.up_bytes
        client.down_bytes += observation.down_bytes
        client.up_packets += observation.up_packets
        client.down_packets += observation.down_packets
        client.flow_count += observation.flow_count
        client.bucket_up[bucket] += observation.up_bytes

        dimensions = self._activity_dimensions(observation)
        destination = dimensions.destination
        if destination is not None:
            client.servers.add(destination.value)
            client.bucket_servers[bucket].add(destination.value)
        service = dimensions.service
        if service is None:
            client.opaque_bytes += observation.up_bytes + observation.down_bytes
            return
        if destination is None:
            raise AssertionError("a logical service requires a destination")
        if service.domain is not None:
            self._service_domains.setdefault(service.service_id, service.domain)

        key = _ServiceKey(
            service.service_id,
            service.basis,
            dimensions.asn_id,
            dimensions.category_id,
            dimensions.transport,
            dimensions.port.code,
        )
        service_index = (client_ip, key)
        state = self._services.get(service_index)
        if state is None:
            state = _ServiceState(key)
            self._services[service_index] = state
        state.bucket_mask |= 1 << bucket
        state.servers.add(destination.value)
        state.up_bytes += observation.up_bytes
        state.down_bytes += observation.down_bytes
        state.flow_count += observation.flow_count
        client.services.add(service.service_id)
        client.routes.add((service.service_id, dimensions.asn_id))
        client.bucket_services[bucket].add(service.service_id)
        client.service_up[service.service_id] += observation.up_bytes
        client.service_total[service.service_id] += observation.up_bytes + observation.down_bytes
        if dimensions.asn_id:
            client.asns.add(dimensions.asn_id)
        if dimensions.port.is_meaningful:
            client.port_groups.add(dimensions.port.code)
            client.bucket_ports[bucket].add(dimensions.port.code)
        self._service_buckets[(client_ip, destination.value, bucket)].add(
            _ServiceBucket(dimensions.transport, dimensions.raw_port, key)
        )

    def consume_rate(self, observation: RateObservation) -> None:
        bucket = self._bucket_index(observation.bucket_start)
        client = self._clients.get(self._normalized_client(observation.client_ip))
        if client is not None:
            client.rate_values[bucket] = max(
                client.rate_values.get(bucket, 0), observation.up_rate_p95_bps
            )

    def consume_long_flow(self, observation: LongFlowObservation) -> None:
        _require_utc_interval(self._day, observation.start, observation.finish)
        client_ip = self._normalized_client(observation.client_ip)
        client = self._clients.get(client_ip)
        if client is None:
            return
        client.large_flow_count += observation.large_flow_count
        client.large_flow_up_bytes += observation.large_flow_up_bytes
        client.max_large_flow_bytes = max(
            client.max_large_flow_bytes, observation.max_large_flow_bytes
        )
        client.max_large_flow_duration_sec = max(
            client.max_large_flow_duration_sec, observation.max_large_flow_duration_sec
        )

        destination = self._normalized_destination(observation.server_ip)
        if destination is None or observation.finish <= observation.start:
            return
        protocol = _normalize_transport(observation.protocol)
        server_port = _raw_port(observation.server_port)
        matches: set[_ServiceKey] = set()
        for bucket in self._overlapping_buckets(observation.start, observation.finish):
            matches.update(
                item.key
                for item in self._service_buckets.get((client_ip, destination.value, bucket), ())
                if (not protocol or not item.protocol or protocol == item.protocol)
                and (not server_port or not item.server_port or server_port == item.server_port)
            )
        if len(matches) != 1:
            return
        state = self._services[(client_ip, matches.pop())]
        state.large_flow_count += observation.large_flow_count
        state.large_flow_up_bytes += observation.large_flow_up_bytes
        state.max_large_flow_bytes = max(
            state.max_large_flow_bytes, observation.max_large_flow_bytes
        )
        state.max_large_flow_duration_sec = max(
            state.max_large_flow_duration_sec, observation.max_large_flow_duration_sec
        )

    def finish(self) -> StagedDay:
        client_rows = tuple(
            self._client_row(self._day, client_ip, state)
            for client_ip, state in sorted(self._clients.items())
        )
        service_rows = tuple(
            self._service_row(self._day, client_ip, state)
            for (client_ip, _key), state in sorted(
                self._services.items(),
                key=lambda item: (item[0][0], _service_sort_key(item[0][1])),
            )
        )
        return StagedDay(
            self._day,
            client_rows,
            service_rows,
            service_domains=dict(self._service_domains),
        )

    def _bucket_index(self, timestamp: datetime) -> int:
        if timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0):
            raise AggregationError("observation timestamps must be timezone-aware UTC")
        if timestamp.second or timestamp.microsecond or timestamp.minute % 5:
            raise AggregationError("activity and rate timestamps must be aligned to five minutes")
        if not self._bounds.start <= timestamp < self._bounds.end:
            raise AggregationError("observation timestamp is outside day D")
        return int((timestamp - self._bounds.start).total_seconds()) // 300

    def _normalized_client(self, raw: str) -> str:
        cached = self._client_ip_cache.get(raw)
        if cached is not None:
            return cached
        normalized = _client_ip(raw)
        self._client_ip_cache[raw] = normalized
        return normalized

    def _normalized_destination(self, raw: str) -> NormalizedIp | None:
        if raw in self._destination_cache:
            return self._destination_cache[raw]
        destination = _destination_ip(raw)
        self._destination_cache[raw] = destination
        return destination

    def _activity_dimensions(self, observation: ActivityObservation) -> _ActivityDimensions:
        cache_key = (
            observation.server_ip,
            observation.server_port,
            observation.transport_protocol,
            observation.root_domain,
            observation.sni,
            observation.dns,
            observation.application,
            observation.application_category,
            observation.asn,
        )
        cached = self._dimension_cache.get(cache_key)
        if cached is not None:
            return cached
        destination = self._normalized_destination(observation.server_ip)
        service = _build_service(observation, destination)
        if service is None:
            result = _ActivityDimensions(destination, None, 0, 0, 0, PortGroup(0), 0)
        else:
            result = _ActivityDimensions(
                destination,
                service,
                _normalize_asn(observation.asn),
                category_id(observation.application_category),
                _normalize_transport(observation.transport_protocol),
                _port_group(observation.server_port),
                _raw_port(observation.server_port),
            )
        self._dimension_cache[cache_key] = result
        return result

    def _overlapping_buckets(self, start: datetime, finish: datetime) -> range:
        first = max(0, int((start - self._bounds.start).total_seconds()) // 300)
        clipped_finish = min(finish, self._bounds.end)
        finish_microseconds = int((clipped_finish - self._bounds.start) / timedelta(microseconds=1))
        width = 300_000_000
        last_exclusive = min(288, (finish_microseconds + width - 1) // width)
        return range(first, last_exclusive)

    @staticmethod
    def _client_row(day: UtcDay, client_ip: str, state: _ClientState) -> ClientDayRow:
        bucket_ids = sorted(state.buckets)
        up_values = [state.bucket_up[bucket] for bucket in bucket_ids]
        server_counts = [len(state.bucket_servers[bucket]) for bucket in bucket_ids]
        service_counts = [len(state.bucket_services[bucket]) for bucket in bucket_ids]
        port_counts = [len(state.bucket_ports[bucket]) for bucket in bucket_ids]
        rates = [state.rate_values[bucket] for bucket in sorted(state.rate_values)]
        return ClientDayRow(
            day.value,
            client_ip,
            state.up_bytes,
            state.down_bytes,
            state.up_packets,
            state.down_packets,
            state.flow_count,
            len(state.minutes),
            len(state.buckets),
            len(state.servers),
            len(state.services),
            len(state.routes),
            len(state.asns),
            len(state.port_groups),
            max(state.service_up.values(), default=0),
            max(state.service_total.values(), default=0),
            state.opaque_bytes,
            _p95(up_values),
            max(up_values, default=0),
            _p95(server_counts),
            max(server_counts, default=0),
            _p95(service_counts),
            max(service_counts, default=0),
            _p95(port_counts),
            max(port_counts, default=0),
            _p95(rates),
            max(rates, default=0),
            state.large_flow_count,
            state.large_flow_up_bytes,
            state.max_large_flow_bytes,
            state.max_large_flow_duration_sec,
        )

    @staticmethod
    def _service_row(day: UtcDay, client_ip: str, state: _ServiceState) -> ClientServiceDayRow:
        return ClientServiceDayRow(
            day.value,
            client_ip,
            state.key.service_id,
            state.key.service_basis.value,
            state.key.asn_id,
            state.key.application_category_id,
            state.key.transport_protocol,
            state.key.port_group,
            ActivityBitmap(state.bucket_mask.to_bytes(36, "little")).value,
            state.up_bytes,
            state.down_bytes,
            state.flow_count,
            len(state.servers),
            state.large_flow_count,
            state.large_flow_up_bytes,
            state.max_large_flow_bytes,
            state.max_large_flow_duration_sec,
        )


def _bucket_index(day: UtcDay, timestamp: datetime) -> int:
    if timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0):
        raise AggregationError("observation timestamps must be timezone-aware UTC")
    if timestamp.second or timestamp.microsecond or timestamp.minute % 5:
        raise AggregationError("activity and rate timestamps must be aligned to five minutes")
    if not day.bounds.start <= timestamp < day.bounds.end:
        raise AggregationError("observation timestamp is outside day D")
    return int((timestamp - day.bounds.start).total_seconds()) // 300


def _require_utc_interval(day: UtcDay, start: datetime, finish: datetime) -> None:
    if (
        start.tzinfo is None
        or finish.tzinfo is None
        or start.utcoffset() != timedelta(0)
        or finish.utcoffset() != timedelta(0)
    ):
        raise AggregationError("long-flow timestamps must be timezone-aware UTC")
    if finish < start:
        raise AggregationError("long-flow finish cannot precede start")
    if not day.bounds.start <= start < day.bounds.end:
        raise AggregationError("long-flow start is outside day D")


def _client_ip(raw: str) -> str:
    try:
        return NormalizedIp.parse(raw).value
    except IpNormalizationError as exc:
        raise AggregationError("client IP cannot be normalized") from exc


def _destination_ip(raw: str) -> NormalizedIp | None:
    try:
        return NormalizedIp.parse(raw)
    except IpNormalizationError:
        return None


def _build_service(
    observation: ActivityObservation, destination: NormalizedIp | None
) -> LogicalService | None:
    if destination is None:
        return None
    try:
        return build_logical_service(
            server_ip=destination,
            root_domain=observation.root_domain,
            sni=observation.sni,
            dns=observation.dns,
            application=observation.application,
            asn=observation.asn,
        )
    except ValueError as exc:
        raise AggregationError("service dimensions cannot be normalized") from exc


def _normalize_asn(raw: int | str | None) -> int:
    try:
        return normalize_asn(raw)
    except ValueError as exc:
        raise AggregationError("ASN cannot be normalized") from exc


def _normalize_transport(raw: int | str | None) -> int:
    try:
        return normalize_transport(raw)
    except ValueError as exc:
        raise AggregationError("transport protocol cannot be normalized") from exc


def _port_group(raw: int | str | None) -> PortGroup:
    try:
        return port_group(raw)
    except ValueError as exc:
        raise AggregationError("server port cannot be normalized") from exc


def _raw_port(raw: int | str | None) -> int:
    if raw is None or str(raw).strip() == "":
        return 0
    try:
        value = int(raw)
    except ValueError as exc:
        raise AggregationError("server port cannot be normalized") from exc
    if not 0 <= value <= 65_535:
        raise AggregationError("server port is outside the UInt16 range")
    return value


def _p95(values: list[int] | list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    position = (len(ordered) - 1) * 0.95
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _service_sort_key(key: _ServiceKey) -> tuple[object, ...]:
    return (
        key.service_id,
        key.asn_id,
        key.application_category_id,
        key.transport_protocol,
        key.port_group,
    )


def _require_non_negative(**values: int) -> None:
    if any(value < 0 for value in values.values()):
        raise AggregationError("additive observations must be non-negative")


def utc_from_epoch(seconds: int) -> datetime:
    """Convert a source integer epoch without depending on local timezone."""
    return datetime.fromtimestamp(seconds, tz=UTC)


def utc_from_epoch_microseconds(microseconds: int) -> datetime:
    return datetime.fromtimestamp(microseconds / 1_000_000, tz=UTC)
