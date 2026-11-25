"""The support definition: statable, countable, and since `behavioural-support-v3` one question —
whether any of an address's traffic resolved to a service."""

from __future__ import annotations

from datetime import date

import pytest

from network_behaviour.aggregation import ClientDayRow
from network_behaviour.population import (
    CURRENT_SUPPORT_DEFINITION,
    RETIRED_SUPPORT_DEFINITION_V1,
    RETIRED_SUPPORT_DEFINITION_V2,
    SupportArm,
    SupportCombinator,
    SupportDefinition,
    compare_definitions,
    take_census,
)

DAY = date(2026, 8, 9)


def _row(client_ip: str, *, buckets: int, flows: int, services: int = 0) -> ClientDayRow:
    return ClientDayRow(
        day=DAY,
        client_ip=client_ip,
        up_bytes=0,
        down_bytes=0,
        up_packets=0,
        down_packets=0,
        flow_count=flows,
        active_minutes=min(1440, buckets * 5),
        active_5m_buckets=buckets,
        unique_servers=services,
        unique_services=services,
        unique_routes=services,
        unique_asns=0,
        unique_port_groups=0,
        top_service_up_bytes=0,
        top_service_total_bytes=0,
        opaque_bytes=0,
        p95_5m_up_bytes=0.0,
        max_5m_up_bytes=0,
        p95_5m_unique_servers=0.0,
        max_5m_unique_servers=0,
        p95_5m_unique_services=0.0,
        max_5m_unique_services=0,
        p95_5m_unique_port_groups=0.0,
        max_5m_unique_port_groups=0,
        p95_bucket_up_rate_p95_bps=0.0,
        max_bucket_up_rate_p95_bps=0.0,
        large_flow_count=0,
        large_flow_up_bytes=0,
        max_large_flow_bytes=0,
        max_large_flow_duration_sec=0.0,
    )


def test_the_definition_in_force_admits_any_address_with_a_service_however_quiet() -> None:
    """`behavioural-support-v3` asks whether any traffic resolved to a service, not how much.

    The quiet shape v1 excluded stays in scope when it has a service — on 2026-08-09 two of v1's
    three exclusions had pulled tens of megabytes through one — and an address carrying only
    unaddressed rows, with no server, port or domain (`CASE_STUDY` §3), is out.
    """

    for buckets, flows in ((288, 5_000), (8, 2), (0, 0)):
        row = _row("10.20.1.1", buckets=buckets, flows=flows, services=1)
        assert CURRENT_SUPPORT_DEFINITION.admits(row)
    assert not CURRENT_SUPPORT_DEFINITION.admits(_row("10.20.1.1", buckets=288, flows=0))
    assert CURRENT_SUPPORT_DEFINITION.version == "behavioural-support-v3"


def test_the_ungated_definition_is_kept_for_replaying_days_it_governed() -> None:
    for buckets, flows, services in ((288, 5_000, 3), (8, 2, 1), (0, 0, 0)):
        row = _row("10.20.1.1", buckets=buckets, flows=flows, services=services)
        assert RETIRED_SUPPORT_DEFINITION_V2.admits(row)
    assert RETIRED_SUPPORT_DEFINITION_V2.is_ungated
    assert RETIRED_SUPPORT_DEFINITION_V2.version == "behavioural-support-v2"


def test_one_decision_serves_rows_and_retained_metric_vectors() -> None:
    """Baselines read history as metric lookups; the pools and detectors must agree on scope."""

    for services in (0, 1, 7):
        row = _row("10.20.1.1", buckets=288, flows=0, services=services)

        def quantity(name: str, row: ClientDayRow = row) -> float:
            return float(getattr(row, name))

        assert CURRENT_SUPPORT_DEFINITION.admits_quantities(
            quantity
        ) == CURRENT_SUPPORT_DEFINITION.admits(row)


def test_the_retired_gate_is_kept_verbatim_for_replaying_days_it_governed() -> None:
    """A day published under `primary-detectors-v2` can only be re-read with the gate it used."""

    for buckets, flows in ((288, 0), (10, 0), (0, 100), (9, 99), (0, 0), (9, 100), (10, 99)):
        row = _row("10.20.1.1", buckets=buckets, flows=flows)
        assert RETIRED_SUPPORT_DEFINITION_V1.admits(row) == (buckets >= 10 or flows >= 100)
    assert RETIRED_SUPPORT_DEFINITION_V1.version == "behavioural-support-v1"


def test_a_definition_renders_as_the_registry_states_it() -> None:
    assert CURRENT_SUPPORT_DEFINITION.describe() == "unique_services >= 1"
    assert RETIRED_SUPPORT_DEFINITION_V2.describe() == "every observed address"
    assert RETIRED_SUPPORT_DEFINITION_V1.describe() == (
        "active_5m_buckets >= 10 or flow_count >= 100"
    )
    conjunction = SupportDefinition(
        ((SupportArm.UNIQUE_SERVICES, 5), (SupportArm.FLOW_COUNT, 100)),
        SupportCombinator.ALL,
    )
    assert conjunction.describe() == "unique_services >= 5 and flow_count >= 100"


def test_a_census_counts_every_observed_address_in_or_out() -> None:
    rows = [
        _row("10.20.1.1", buckets=288, flows=5_000),
        _row("10.20.1.2", buckets=288, flows=0),
        _row("10.20.1.3", buckets=1, flows=0),
    ]
    ungated = take_census(DAY.isoformat(), rows, RETIRED_SUPPORT_DEFINITION_V2)
    assert ungated.observed == 3
    assert ungated.supported == 3
    assert ungated.out_of_scope == 0
    assert ungated.arms == ()
    assert "no gate" in ungated.render()

    current = take_census(
        DAY.isoformat(), [*rows, _row("10.20.1.4", buckets=1, flows=1, services=1)]
    )
    assert (current.observed, current.supported, current.out_of_scope) == (4, 1, 3)

    census = take_census(DAY.isoformat(), rows, RETIRED_SUPPORT_DEFINITION_V1)
    assert census.observed == 3
    assert census.supported == 2
    assert census.out_of_scope == 1
    assert census.supported_fraction == pytest.approx(2 / 3)


def test_an_arm_that_changes_no_decision_is_reported_as_such() -> None:
    """The measurement that showed the flow arm decorative: it never decides alone."""

    rows = [_row(f"10.20.1.{index}", buckets=288, flows=index * 50) for index in range(1, 6)]
    census = take_census(DAY.isoformat(), rows, RETIRED_SUPPORT_DEFINITION_V1)
    by_arm = {arm.arm: arm for arm in census.arms}

    assert by_arm["active_5m_buckets"].decided_alone > 0
    assert by_arm["flow_count"].decided_alone == 0
    assert "changes no decision" in census.render()


def test_candidates_are_compared_without_new_code() -> None:
    """A candidate definition is measured against the current one before either is chosen."""

    rows = [
        _row("10.20.1.1", buckets=288, flows=5_000, services=40),
        _row("10.20.1.2", buckets=288, flows=0, services=0),
    ]
    censuses = compare_definitions(
        DAY.isoformat(),
        rows,
        (
            CURRENT_SUPPORT_DEFINITION,
            RETIRED_SUPPORT_DEFINITION_V1,
            SupportDefinition(((SupportArm.FLOW_COUNT, 100),)),
            SupportDefinition(((SupportArm.UNIQUE_SERVICES, 5),)),
        ),
    )

    assert [item.supported for item in censuses] == [1, 2, 1, 1]
    assert [item.definition for item in censuses] == [
        "unique_services >= 1",
        "active_5m_buckets >= 10 or flow_count >= 100",
        "flow_count >= 100",
        "unique_services >= 5",
    ]


def test_an_empty_definition_admits_rather_than_relying_on_vacuous_truth() -> None:
    """`any(()) is False` and `all(()) is True`. Neither may decide what "no gate" means."""

    quiet = _row("10.20.1.1", buckets=0, flows=0)
    for combinator in (SupportCombinator.ANY, SupportCombinator.ALL):
        assert SupportDefinition((), combinator).admits(quiet)


def test_a_definition_must_be_statable_and_well_formed() -> None:
    with pytest.raises(ValueError, match="each arm at most once"):
        SupportDefinition(((SupportArm.FLOW_COUNT, 1), (SupportArm.FLOW_COUNT, 2)))
    with pytest.raises(ValueError, match="cannot be negative"):
        SupportDefinition(((SupportArm.FLOW_COUNT, -1),))
