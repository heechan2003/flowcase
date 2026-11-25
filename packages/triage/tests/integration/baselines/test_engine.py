from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path

import duckdb
import pytest

from network_behaviour.aggregation import ClientDayRow, ClientServiceDayRow
from network_behaviour.baselines import (
    BaselineEngine,
    BaselinePolicy,
    HistoryConfidence,
    SourceQualityInput,
)
from network_behaviour.baselines.engine import _ClientObservation
from network_behaviour.baselines.models import CLIENT_METRICS, MetricCalibration
from network_behaviour.population import (
    CURRENT_SUPPORT_DEFINITION,
    RETIRED_SUPPORT_DEFINITION_V2,
    SupportDefinition,
)
from network_behaviour.storage.migrations import MigrationRunner
from network_behaviour.time import UtcDay

MIGRATIONS = Path(__file__).parents[3] / "sql" / "migrations"
DAY = UtcDay.parse("2026-07-10")
CLIENT_COLUMNS = ", ".join(ClientDayRow.__dataclass_fields__)
SERVICE_COLUMNS = ", ".join(ClientServiceDayRow.__dataclass_fields__)
SERVICE_ONE = bytes.fromhex("01" * 16)
SERVICE_TWO = bytes.fromhex("02" * 16)


def _client_row(
    day: date,
    client_ip: str,
    value: int,
    *,
    opaque_bytes: int = 0,
) -> ClientDayRow:
    return ClientDayRow(
        day=day,
        client_ip=client_ip,
        up_bytes=value,
        down_bytes=value // 2,
        up_packets=value,
        down_packets=value // 2,
        flow_count=max(value // 10, 1),
        active_minutes=60,
        active_5m_buckets=12,
        unique_servers=10,
        unique_services=5,
        unique_routes=5,
        unique_asns=3,
        unique_port_groups=2,
        top_service_up_bytes=value // 2,
        top_service_total_bytes=value,
        opaque_bytes=opaque_bytes,
        p95_5m_up_bytes=float(value // 4),
        max_5m_up_bytes=value // 3,
        p95_5m_unique_servers=3.0,
        max_5m_unique_servers=4,
        p95_5m_unique_services=2.0,
        max_5m_unique_services=3,
        p95_5m_unique_port_groups=1.0,
        max_5m_unique_port_groups=2,
        p95_bucket_up_rate_p95_bps=float(value),
        max_bucket_up_rate_p95_bps=float(value * 2),
        large_flow_count=1,
        large_flow_up_bytes=value,
        max_large_flow_bytes=value * 2,
        max_large_flow_duration_sec=60.0,
    )


def _observation(day: date, client_ip: str, services: int, value: int) -> _ClientObservation:
    row = replace(_client_row(day, client_ip, value), unique_services=services)
    return _ClientObservation(
        day, client_ip, tuple(float(getattr(row, name)) for name in CLIENT_METRICS)
    )


def _service_row(
    day: date,
    client_ip: str,
    service_id: bytes,
    asn_id: int,
    *,
    basis: str = "domain",
) -> ClientServiceDayRow:
    return ClientServiceDayRow(
        day=day,
        client_ip=client_ip,
        service_id=service_id,
        service_basis=basis,
        asn_id=asn_id,
        application_category_id=1,
        transport_protocol=6,
        port_group=443,
        active_5m_bitmap=bytes([1]) + bytes(35),
        up_bytes=100,
        down_bytes=50,
        flow_count=10,
        unique_servers=1,
        large_flow_count=0,
        large_flow_up_bytes=0,
        max_large_flow_bytes=0,
        max_large_flow_duration_sec=0.0,
    )


def _large_flow_service_row(
    day: date,
    client_ip: str,
    service_id: bytes,
    *,
    bytes_moved: int,
    duration_sec: float,
) -> ClientServiceDayRow:
    return replace(
        _service_row(day, client_ip, service_id, 64500),
        large_flow_count=1,
        large_flow_up_bytes=bytes_moved,
        max_large_flow_bytes=bytes_moved,
        max_large_flow_duration_sec=duration_sec,
    )


@pytest.fixture
def connection() -> duckdb.DuckDBPyConnection:
    value = duckdb.connect(":memory:")
    MigrationRunner(MIGRATIONS).apply(value)
    return value


def _insert_clients(connection: duckdb.DuckDBPyConnection, rows: tuple[ClientDayRow, ...]) -> None:
    placeholders = ", ".join("?" for _ in ClientDayRow.__dataclass_fields__)
    connection.executemany(
        f"INSERT INTO history.client_day ({CLIENT_COLUMNS}) VALUES ({placeholders})",
        [row.values() for row in rows],
    )


def _insert_services(
    connection: duckdb.DuckDBPyConnection, rows: tuple[ClientServiceDayRow, ...]
) -> None:
    placeholders = ", ".join("?" for _ in ClientServiceDayRow.__dataclass_fields__)
    connection.executemany(
        f"INSERT INTO history.client_service_day ({SERVICE_COLUMNS}) VALUES ({placeholders})",
        [row.values() for row in rows],
    )


def _seed_history(connection: duckdb.DuckDBPyConnection) -> None:
    clients: list[ClientDayRow] = []
    for offset in range(31, 0, -1):
        history_day = DAY.value - timedelta(days=offset)
        clients.extend(
            (
                _client_row(history_day, "10.20.1.1", 1_000 + offset),
                _client_row(history_day, "10.20.1.2", 900 + offset),
            )
        )
    # This synthetic same-day poison row proves every historical path excludes D.
    clients.append(_client_row(DAY.value, "10.20.1.1", 1_000_000_000))
    _insert_clients(connection, tuple(clients))
    _insert_services(
        connection,
        (
            _service_row(DAY.value - timedelta(days=10), "10.20.1.1", SERVICE_ONE, 64500),
            _service_row(DAY.value - timedelta(days=3), "10.20.1.1", SERVICE_ONE, 64500),
            _service_row(DAY.value - timedelta(days=5), "10.20.1.2", SERVICE_ONE, 64500),
            _service_row(DAY.value, "10.20.1.1", SERVICE_TWO, 64501),
        ),
    )


def _current(
    *, peer_fill: int = 0
) -> tuple[tuple[ClientDayRow, ...], tuple[ClientServiceDayRow, ...]]:
    """`peer_fill` adds same-band clients with no history, so a test can put the target's peer
    cohort above or below `BaselinePolicy.min_cohort` without disturbing anything else. They sort
    after "10.20.1.3", so `batch.clients[0:3]` keeps indexing the three named clients below.
    """
    clients = (
        _client_row(DAY.value, "10.20.1.1", 5_000, opaque_bytes=1_000),
        _client_row(DAY.value, "10.20.1.2", 1_100),
        _client_row(DAY.value, "10.20.1.3", 700),
        *(_client_row(DAY.value, f"10.20.9.{index}", 500 + index) for index in range(peer_fill)),
    )
    services = (
        _service_row(DAY.value, "10.20.1.1", SERVICE_ONE, 64501),
        _service_row(DAY.value, "10.20.1.1", SERVICE_TWO, 0, basis="server_ip"),
        _service_row(DAY.value, "10.20.1.2", SERVICE_ONE, 64500),
    )
    return clients, services


def test_engine_builds_history_calibration_novelty_and_quality_context(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    _seed_history(connection)
    # 20 filler peers (the validation floor) plus the 3 named clients puts the target's peer
    # cohort at min_cohort exactly, so this test still exercises the peer-percentile path. The
    # guard's own refusal behaviour is covered separately, below.
    clients, services = _current(peer_fill=17)
    batch = BaselineEngine(connection, BaselinePolicy(min_cohort=20)).build(
        DAY,
        clients,
        services,
        SourceQualityInput(dns_context_available=False),
    )

    first = batch.clients[0]
    cold = batch.clients[2]
    assert (first.prior_active_days, first.history_confidence) == (
        31,
        HistoryConfidence.MATURE,
    )
    # bytes0 (7,500 raw bytes, below the 1 MiB edge) and destinations1 (10 unique servers, in
    # [5, 20)). No minutes segment: `active_minutes` was retired as a band dimension in
    # baseline-calibration-v6.
    assert first.activity_band == "bytes0-destinations1"
    assert first.same_weekday_eligible
    up_bytes = next(metric for metric in first.metrics if metric.name == "up_bytes")
    assert up_bytes.recent is not None and up_bytes.recent.median_raw < 2_000
    assert up_bytes.long is not None and up_bytes.long.count == 31
    assert up_bytes.current_residual is not None
    assert up_bytes.self_percentile is not None
    assert up_bytes.peer_percentile is not None
    assert up_bytes.metric_strength is not None
    assert first.source_quality.opaque_byte_fraction == pytest.approx(1_000 / 7_500)
    assert not first.source_quality.dns_context_available
    assert cold.history_confidence is HistoryConfidence.COLD
    assert all(metric.current_residual is None for metric in cold.metrics)

    by_relationship = {
        (row.client_ip, row.service_id_hex, row.asn_id): row for row in batch.relationships
    }
    changed_route = by_relationship[("10.20.1.1", SERVICE_ONE.hex(), 64501)]
    new_service = by_relationship[("10.20.1.1", SERVICE_TWO.hex(), 0)]
    familiar = by_relationship[("10.20.1.2", SERVICE_ONE.hex(), 64500)]
    assert changed_route.prior_service_active_days == 2
    assert not changed_route.new_service and changed_route.new_route
    assert changed_route.historical_service_prevalence == 1.0
    assert new_service.new_service
    assert new_service.prior_route_active_days is None and new_service.new_route is None
    assert new_service.historical_service_prevalence == 0.0
    assert new_service.service_confidence.value == "low"
    assert not familiar.new_service and not familiar.new_route


def test_a_small_peer_cohort_refuses_a_peer_percentile_it_cannot_support(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """A midpoint-rank percentile over n peers tops out at (n - 0.5)/n, so a cohort below
    `min_cohort` cannot place any value in the `moderate_strength` tail regardless of behaviour.
    Below the floor the answer is a refused percentile, not one the cohort cannot support —
    `bands.min_cohort`, `CASE_STUDY` §4.
    """
    _seed_history(connection)
    small_clients, small_services = _current(peer_fill=0)
    large_clients, large_services = _current(peer_fill=40)
    policy = BaselinePolicy(min_cohort=20)

    small_batch = BaselineEngine(connection, policy).build(
        DAY, small_clients, small_services, SourceQualityInput()
    )
    large_batch = BaselineEngine(connection, policy).build(
        DAY, large_clients, large_services, SourceQualityInput()
    )

    small_metric = next(
        metric for metric in small_batch.clients[0].metrics if metric.name == "up_bytes"
    )
    large_metric = next(
        metric for metric in large_batch.clients[0].metrics if metric.name == "up_bytes"
    )
    assert small_metric.self_percentile is not None
    assert small_metric.peer_percentile is None
    assert small_metric.metric_strength is None
    assert large_metric.peer_percentile is not None
    assert large_metric.metric_strength is not None


def test_day_d_poison_is_excluded_and_replay_envelope_is_byte_stable(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    _seed_history(connection)
    clients, services = _current()
    engine = BaselineEngine(connection)

    with_poison = engine.build(DAY, clients, services).to_bytes()
    reordered = engine.build(DAY, tuple(reversed(clients)), tuple(reversed(services))).to_bytes()
    connection.execute("DELETE FROM history.client_service_day WHERE day = ?", [DAY.value])
    connection.execute("DELETE FROM history.client_day WHERE day = ?", [DAY.value])
    without_poison = engine.build(DAY, clients, services).to_bytes()

    assert with_poison == reordered == without_poison


def test_engine_rejects_invalid_current_grains(connection: duckdb.DuckDBPyConnection) -> None:
    clients, services = _current()
    engine = BaselineEngine(connection)

    with pytest.raises(ValueError, match="unique"):
        engine.build(DAY, (*clients, clients[0]), services)
    with pytest.raises(ValueError, match="day D"):
        engine.build(
            DAY,
            clients,
            (replace(services[0], day=DAY.value - timedelta(days=1)),),
        )


def test_prevalence_is_measured_over_the_population_its_numerator_is_drawn_from(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """The v2 -> v3 correction: the denominator counted addresses that no numerator could contain.

    Numerators count clients seen contacting a service, from `client_service_day`. The denominator
    counted every observed address, from `client_day`. An address that contacted no service at all
    was in the denominator of every prevalence and could never be in one numerator, so every
    service looked rarer than it was.
    """
    _seed_history(connection)
    # Two addresses reach a service today; two more are observed and reach nothing, which is the
    # ordinary case in this deployment — the median observed address contacts no service at all.
    clients = (
        _client_row(DAY.value, "10.20.1.1", 1_000),
        _client_row(DAY.value, "10.20.1.2", 1_000),
        _client_row(DAY.value, "10.20.1.8", 1_000),
        _client_row(DAY.value, "10.20.1.9", 1_000),
    )
    services = (
        _service_row(DAY.value, "10.20.1.1", SERVICE_ONE, 64500),
        _service_row(DAY.value, "10.20.1.2", SERVICE_ONE, 64500),
    )

    batch = BaselineEngine(connection).build(DAY, clients, services, SourceQualityInput())
    context = next(item for item in batch.relationships if item.client_ip == "10.20.1.1")

    # Two of the two addresses that contacted anything used this service.
    assert context.current_service_prevalence == 1.0
    # Under the v2 denominator this was 2/4 = 0.5, and the service read as half as prevalent
    # as it is purely because two silent addresses were counted.


def test_large_flow_qualification_reads_only_the_hosts_own_history_before_day_d(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """The reference pool is one host's own prior large flows, and day D is not one of them.

    A day-D row is seeded larger than anything today, so a leak would be visible as a strength
    below 100 rather than as a subtle shift: with the poison in the pool, today's flow would no
    longer be the most extreme value in it.
    """
    policy = BaselinePolicy()
    pool_size = policy.large_flow_reference_min_units
    host, quiet = "10.20.1.1", "10.20.1.2"
    _insert_clients(
        connection,
        tuple(
            _client_row(DAY.value - timedelta(days=offset), host, 1_000 + offset)
            for offset in range(1, 32)
        ),
    )
    history = tuple(
        _large_flow_service_row(
            DAY.value - timedelta(days=1 + index % 30),
            host,
            bytes([index % 256]) + SERVICE_ONE[1:],
            bytes_moved=1_000_000 + index,
            duration_sec=float(index),
        )
        for index in range(pool_size)
    )
    poison = _large_flow_service_row(
        DAY.value, host, SERVICE_TWO, bytes_moved=10**12, duration_sec=10**6
    )
    _insert_services(connection, (*history, poison))

    clients = (
        replace(_client_row(DAY.value, host, 5_000), large_flow_count=1),
        replace(_client_row(DAY.value, quiet, 900), large_flow_count=0),
    )
    services = (
        _large_flow_service_row(
            DAY.value, host, SERVICE_TWO, bytes_moved=9_000_000, duration_sec=1.0
        ),
        _service_row(DAY.value, quiet, SERVICE_ONE, 64500),
    )
    batch = BaselineEngine(connection).build(DAY, clients, services)

    qualified = next(item for item in batch.relationships if item.client_ip == host)
    unqualified = next(item for item in batch.relationships if item.client_ip == quiet)
    assert qualified.large_flow_size_strength == 100.0, "day D leaked into the reference pool"
    assert qualified.large_flow_strength == 100.0
    # Longer than one second on only two of the forty prior flows, so duration alone would not
    # have qualified it. The axes are alternatives, and the combined strength takes the stronger.
    assert qualified.large_flow_duration_strength < qualified.large_flow_size_strength
    # No large flow at all: zero rather than a percentile of something that did not happen.
    assert unqualified.large_flow_strength == 0.0
    assert next(item for item in batch.clients if item.client_ip == quiet).large_flow_strength == 0


def test_addresses_with_no_service_row_are_not_anyones_peers(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """`baseline-calibration-v7`: a peer pool holds only client-days the support definition admits.

    Under v6 the lowest destination band was made of addresses carrying only unaddressed rows —
    6,801 of 6,967 members on 2026-10-14 (`CASE_STUDY` §3) — so a quiet addressed host was ranked
    against traffic whose meaning is not established. The same 40 fillers that clear `min_cohort`
    when they have a service stop counting once they have none, and count again under the ungated
    v2 definition a replay of an earlier day would pass.
    """
    _seed_history(connection)
    clients, services = _current(peer_fill=40)
    unaddressed = tuple(
        replace(row, unique_services=0, unique_routes=0)
        if row.client_ip.startswith("10.20.9.")
        else row
        for row in clients
    )
    policy = BaselinePolicy(min_cohort=20)

    def up_bytes(support: SupportDefinition) -> MetricCalibration:
        batch = BaselineEngine(connection, policy).build(
            DAY, unaddressed, services, SourceQualityInput(), support
        )
        return next(metric for metric in batch.clients[0].metrics if metric.name == "up_bytes")

    assert up_bytes(CURRENT_SUPPORT_DEFINITION).peer_percentile is None
    assert up_bytes(RETIRED_SUPPORT_DEFINITION_V2).peer_percentile is not None


def test_a_calibration_pool_takes_residuals_only_from_admitted_client_days(
    connection: duckdb.DuckDBPyConnection,
) -> None:
    engine = BaselineEngine(connection, BaselinePolicy())
    days = [DAY.value - timedelta(days=offset) for offset in range(20, 0, -1)]
    history = tuple(
        _observation(day, client_ip, services, value)
        for client_ip, services in (("10.20.1.1", 5), ("10.20.9.1", 0))
        for day, value in zip(days, [100] * 19 + [10_000], strict=True)
    )

    admitted = engine._calibration_pools(history, CURRENT_SUPPORT_DEFINITION)
    ungated = engine._calibration_pools(history, RETIRED_SUPPORT_DEFINITION_V2)

    band = next(key for key in ungated if key[1] == "up_bytes")
    assert len(ungated[band]) == 2 * len(admitted[band])
