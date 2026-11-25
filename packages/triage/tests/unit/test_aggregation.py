from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest

import network_behaviour.aggregation as aggregation
from network_behaviour.aggregation import (
    ActivityObservation,
    ClientServiceDayRow,
    DayAggregator,
    LongFlowObservation,
    RateObservation,
)
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.time import UtcDay

DAY = UtcDay.parse("2026-07-10")


def _activity(
    minute: int,
    *,
    server_ip: str = "8.8.8.8",
    asn: str = "AS15169",
    up_bytes: int = 100,
    down_bytes: int = 50,
) -> ActivityObservation:
    return ActivityObservation(
        datetime(2026, 7, 10, 0, minute, tzinfo=UTC),
        "10.20.1.2",
        server_ip,
        443,
        6,
        "Example.COM",
        None,
        None,
        "Web",
        "Browsing",
        asn,
        up_bytes,
        down_bytes,
        10,
        5,
        2,
        (0, 1),
    )


def test_day_aggregation_builds_exact_grains_and_opaque_totals() -> None:
    staged = DayAggregator().aggregate(
        DAY,
        (
            _activity(0),
            _activity(5, asn="AS64500", up_bytes=300, down_bytes=100),
            _activity(10, server_ip="10.0.0.8", up_bytes=40, down_bytes=60),
        ),
        (
            RateObservation(datetime(2026, 7, 10, 0, 0, tzinfo=UTC), "10.20.1.2", 80),
            RateObservation(datetime(2026, 7, 10, 0, 5, tzinfo=UTC), "10.20.1.2", 120),
        ),
        (),
    )

    assert len(staged.client_rows) == 1
    assert len(staged.service_rows) == 2
    client = staged.client_rows[0]
    assert (client.up_bytes, client.down_bytes, client.opaque_bytes) == (440, 210, 100)
    assert (client.active_minutes, client.active_5m_buckets) == (6, 3)
    assert (client.unique_services, client.unique_routes, client.unique_asns) == (1, 2, 2)
    assert (client.top_service_up_bytes, client.top_service_total_bytes) == (400, 550)
    assert client.p95_bucket_up_rate_p95_bps == 118
    assert {ActivityBitmap(row.active_5m_bitmap).count for row in staged.service_rows} == {1}


def test_long_flows_require_actual_unambiguous_interval_overlap_for_service() -> None:
    staged = DayAggregator().aggregate(
        DAY,
        (_activity(0),),
        (),
        (
            LongFlowObservation(
                datetime(2026, 7, 10, 0, 1, tzinfo=UTC),
                datetime(2026, 7, 10, 0, 4, tzinfo=UTC),
                "10.20.1.2",
                "8.8.8.8",
                6,
                443,
                2,
                2_000_000,
                1_500_000,
                180,
            ),
            LongFlowObservation(
                datetime(2026, 7, 10, 0, 20, tzinfo=UTC),
                datetime(2026, 7, 10, 0, 25, tzinfo=UTC),
                "10.20.1.2",
                "8.8.8.8",
                6,
                443,
                1,
                900_000,
                1_200_000,
                300,
            ),
        ),
    )

    client = staged.client_rows[0]
    service = staged.service_rows[0]
    assert (client.large_flow_count, client.large_flow_up_bytes) == (3, 2_900_000)
    assert (service.large_flow_count, service.large_flow_up_bytes) == (2, 2_000_000)
    assert service.max_large_flow_duration_sec == 180


def test_reordered_transient_rows_produce_identical_aggregates() -> None:
    rows = (_activity(0), _activity(5, asn="AS64500"))
    aggregator = DayAggregator()

    assert aggregator.aggregate(DAY, rows, (), ()) == aggregator.aggregate(
        DAY, tuple(reversed(rows)), (), ()
    )


def test_repeated_dimensions_reuse_normalization_and_retained_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_constructions = 0
    service_constructions = 0
    service_normalizations = 0
    original_client = aggregation._ClientState
    original_service = aggregation._ServiceState
    original_build = aggregation._build_service

    def client_factory() -> Any:
        nonlocal client_constructions
        client_constructions += 1
        return original_client()

    def service_factory(key: Any) -> Any:
        nonlocal service_constructions
        service_constructions += 1
        return original_service(key)

    def build_service(*args: Any, **kwargs: Any) -> Any:
        nonlocal service_normalizations
        service_normalizations += 1
        return original_build(*args, **kwargs)

    monkeypatch.setattr(aggregation, "_ClientState", client_factory)
    monkeypatch.setattr(aggregation, "_ServiceState", service_factory)
    monkeypatch.setattr(aggregation, "_build_service", build_service)

    staged = DayAggregator().aggregate(DAY, (_activity(0), _activity(5)), (), ())

    assert len(staged.client_rows) == len(staged.service_rows) == 1
    assert (client_constructions, service_constructions, service_normalizations) == (1, 1, 1)


def test_long_flow_bucket_index_preserves_exact_boundary_and_ambiguity() -> None:
    first = _activity(0)
    second = replace(_activity(5), root_domain="other.example")
    staged = DayAggregator().aggregate(
        DAY,
        (first, second),
        (),
        (
            LongFlowObservation(
                datetime(2026, 7, 10, 0, 4, tzinfo=UTC),
                datetime(2026, 7, 10, 0, 5, tzinfo=UTC),
                first.client_ip,
                first.server_ip,
                6,
                443,
                1,
                1_000_000,
                1_100_000,
                60,
            ),
            LongFlowObservation(
                datetime(2026, 7, 10, 0, 4, tzinfo=UTC),
                datetime(2026, 7, 10, 0, 5, 1, tzinfo=UTC),
                first.client_ip,
                first.server_ip,
                6,
                443,
                1,
                1_000_000,
                1_100_000,
                61,
            ),
        ),
    )

    assert staged.client_rows[0].large_flow_count == 2
    assert sorted(row.large_flow_count for row in staged.service_rows) == [0, 1]


def test_domain_basis_services_stage_their_registered_domain() -> None:
    staged = DayAggregator().aggregate(DAY, (_activity(0),), (), ())

    assert list(staged.service_domains.values()) == ["example.com"]
    assert set(staged.service_domains) == {row.service_id for row in staged.service_rows}


def test_non_domain_basis_services_stage_no_domain() -> None:
    observation = replace(_activity(0), root_domain=None, sni=None, dns=None)

    staged = DayAggregator().aggregate(DAY, (observation,), (), ())

    assert staged.service_rows
    assert staged.service_domains == {}


def test_no_domain_reaches_the_grain_retained_for_365_days() -> None:
    """`history.client_service_day` stays hashed; the domain lives only on the current day.

    `ClientServiceDayRow.values()` feeds bulk persistence, so a domain added to that dataclass
    would be written to retained history silently. This pins the persisted columns.
    """
    staged = DayAggregator().aggregate(DAY, (_activity(0),), (), ())

    assert "example.com" in staged.service_domains.values()
    assert tuple(ClientServiceDayRow.__dataclass_fields__) == (
        "day",
        "client_ip",
        "service_id",
        "service_basis",
        "asn_id",
        "application_category_id",
        "transport_protocol",
        "port_group",
        "active_5m_bitmap",
        "up_bytes",
        "down_bytes",
        "flow_count",
        "unique_servers",
        "large_flow_count",
        "large_flow_up_bytes",
        "max_large_flow_bytes",
        "max_large_flow_duration_sec",
    )
    for row in staged.service_rows:
        assert "example.com" not in {value for value in row.values() if isinstance(value, str)}
