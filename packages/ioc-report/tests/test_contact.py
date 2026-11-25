from __future__ import annotations

from datetime import date
from pathlib import Path

from network_behaviour.aggregation import ClientServiceDayRow
from network_behaviour.evaluation.shadow import beacon_candidates
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.time import UtcDay

from ioc_report.contact import bitmap_timing
from ioc_report.history import HostServiceDay
from tests.builders import evidence, load
from tests.conftest import long_flow, minute_row, record


def test_rows_group_into_contacts_by_kind(tmp_path: Path) -> None:
    rows = [
        minute_row("2026-09-15 10:00:00", sni="www.example.com", transport=17),
        minute_row("2026-09-15 10:01:00", sni="www.example.com", transport=17),
        minute_row("2026-09-15 10:02:00", port=1604),
    ]
    feed, case = load(tmp_path, [record(rows, indicator="1.1.1.1:443", indicator_type="ip:port")])

    contacts = evidence(feed, case).contacts

    assert [(c.port, c.transport, c.sni, len(c.minutes)) for c in contacts] == [
        (443, 17, "www.example.com", 2),
        (1604, 6, "", 1),
    ]


def test_a_feed_flow_is_attributed_only_to_contacts_it_overlaps(tmp_path: Path) -> None:
    rows = [
        minute_row("2026-09-15 10:00:00", sni="www.example.com"),
        minute_row("2026-09-15 12:00:00", port=8080),
    ]
    flows = [
        long_flow("f1", start="2026-09-15 09:59:30.000000", finish="2026-09-15 10:30:00.000000"),
        long_flow("f2", start="2026-09-15 11:00:00.000000", finish="2026-09-15 11:30:00.000000"),
    ]
    feed, case = load(tmp_path, [record(rows, flows=flows)])

    found = evidence(feed, case)

    assert found.flow_attribution == {0: (0,), 1: ()}


def test_a_spaced_schedule_is_scheduled_and_a_contiguous_session_is_not(tmp_path: Path) -> None:
    every_half_hour = [
        minute_row(f"2026-09-15 {8 + offset // 2:02d}:{30 * (offset % 2):02d}:00")
        for offset in range(21)
    ]
    contiguous = [minute_row(f"2026-09-15 10:{minute:02d}:00") for minute in range(30)]

    feed, case = load(tmp_path, [record(every_half_hour)])
    (day,) = evidence(feed, case).pair_days
    assert (day.minutes, day.mean_gap_minutes, day.cv, day.scheduled) == (21, 30.0, 0.0, True)

    feed, case = load(tmp_path, [record(contiguous)])
    (day,) = evidence(feed, case).pair_days
    assert not day.regular and day.runs == 1


def test_a_heavy_schedule_is_regular_but_not_low_volume(tmp_path: Path) -> None:
    rows = [
        minute_row(f"2026-09-15 {8 + offset // 2:02d}:{30 * (offset % 2):02d}:00", down=90_000)
        for offset in range(21)
    ]
    feed, case = load(tmp_path, [record(rows)])

    (day,) = evidence(feed, case).pair_days

    assert day.regular and not day.scheduled


def _row(buckets: list[int], up: int = 2_000) -> ClientServiceDayRow:
    return ClientServiceDayRow(
        day=date(2026, 9, 15),
        client_ip="192.0.2.10",
        service_id=bytes(16),
        service_basis="domain",
        asn_id=13335,
        application_category_id=0,
        transport_protocol=6,
        port_group=443,
        active_5m_bitmap=ActivityBitmap.from_buckets(buckets).value,
        up_bytes=up,
        down_bytes=up,
        flow_count=len(buckets),
        unique_servers=1,
        large_flow_count=0,
        large_flow_up_bytes=0,
        max_large_flow_bytes=0,
        max_large_flow_duration_sec=0.0,
    )


def test_bitmap_timing_matches_the_triage_beacon_profile() -> None:
    hourly = list(range(0, 288, 12))
    for buckets, up in ((hourly, 2_000), (hourly, 10_000_000), (list(range(40, 60)), 2_000)):
        row = _row(buckets, up)
        funnel = beacon_candidates(UtcDay(row.day), [row])
        timing = bitmap_timing(
            HostServiceDay(
                row.day,
                row.active_5m_bitmap,
                row.up_bytes,
                row.down_bytes,
                6,
                443,
                13335,
                0,
                0.0,
                service_rows_that_day=1,
            )
        )
        assert timing.beacon == bool(funnel.candidates)
        assert timing.regular == (funnel.after_span == 1)
