"""The live queries run against a real source file, as `load-zeek` writes it."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

from network_behaviour.config import SourceConfig

from ioc_report.feed import Case, load_feed
from ioc_report.live import LiveSession, minute_horizon
from tests.conftest import minute_row, record, write_feed
from tests.source_builders import activity, long_flow, write_source

NOW = datetime(2026, 10, 7, 9, 0, tzinfo=UTC)
HOST = "192.0.2.10"
OTHER = "192.0.2.20"


def _cases(tmp_path: Path, time: str = "2026-10-05 10:00:00") -> tuple[Case, ...]:
    return load_feed(write_feed(tmp_path, [record([minute_row(time, host=HOST)], host=HOST)])).cases


def _source(tmp_path: Path) -> Path:
    return write_source(
        tmp_path / "source.duckdb",
        [
            activity("2026-10-05 10:00:00", sni="www.example.com", root="example.com", up=700),
            activity("2026-10-05 10:01:00", sni="www.example.com", root="example.com", up=300),
            activity("2026-10-05 10:02:00", port=8443, transport=17, flows=0),
            activity("2026-10-05 10:00:00", OTHER, root="example.org"),
            activity("2026-10-05 10:03:00", server="9.9.9.9", root="quad9.net", asn=None),
            activity("2026-10-06 12:00:00", server="9.9.9.9", root="quad9.net"),
        ],
        [long_flow("F1", "2026-10-05 09:00:00", "2026-10-05 11:00:00")],
    )


def test_the_live_phases_read_contacts_sharing_flows_context_and_destinations(
    tmp_path: Path,
) -> None:
    cases = _cases(tmp_path)
    session = LiveSession.connect(SourceConfig(_source(tmp_path)))

    with session:
        live = session.gather(cases, NOW)
        live = session.add_host_context(live, cases)
        live = session.add_destinations(live, cases)

    assert live.status == "queried", live.error
    contacts = live.contacts[(HOST, "1.1.1.1")]
    assert [(c.port, c.transport, c.active_minutes, c.up_bytes) for c in contacts] == [
        (443, 6, 2, 1000),
        (8443, 17, 1, 1000),
    ]
    assert contacts[0].minute_epochs[1] - contacts[0].minute_epochs[0] == 1
    (sharing,) = live.addresses["1.1.1.1"]
    assert (sharing.campus_clients, sharing.registered_domains, sharing.udp_clients) == (2, 2, 0)
    assert sharing.asns == ("13335",)
    (flows,) = live.long_flows[(HOST, "1.1.1.1")]
    assert (flows.day, flows.flows, flows.held_open_flows) == (date(2026, 10, 5), 1, 1)
    assert live.host_context is not None
    context = live.host_context[HOST]
    assert context[0].flagged and {row.root_domain for row in context} >= {"example.com"}
    assert live.destinations is not None
    days = {(row.day, row.root_domain or row.network) for row in live.destinations[HOST]}
    assert (date(2026, 10, 6), "quad9.net") in days
    assert all(audit.status == "passed" for audit in live.audits)


def test_a_source_that_keeps_every_day_lets_an_old_match_be_read(tmp_path: Path) -> None:
    old = _cases(tmp_path, "2026-08-01 10:00:00")
    write_source(tmp_path / "source.duckdb", [activity("2026-08-01 10:00:00")])

    kept = LiveSession.connect(SourceConfig(tmp_path / "source.duckdb"))
    limited = LiveSession.connect(SourceConfig(tmp_path / "source.duckdb", detail_days=15))
    with kept, limited:
        read = kept.gather(old, NOW)
        expired = limited.gather(old, NOW)

    assert minute_horizon(SourceConfig(Path("s"), detail_days=15)) == 13
    assert kept.horizon_days is None and read.days_expired == ()
    assert read.contacts[(HOST, "1.1.1.1")][0].day == date(2026, 8, 1)
    assert expired.days_expired == (date(2026, 8, 1),)


def test_an_old_match_reads_the_original_span_of_destination_days(tmp_path: Path) -> None:
    old = _cases(tmp_path, "2026-08-01 10:00:00")
    write_source(tmp_path / "source.duckdb", [activity("2026-08-01 10:00:00")])

    session = LiveSession.connect(SourceConfig(tmp_path / "source.duckdb"))
    with session:
        live = session.add_destinations(session.gather(old, NOW), old)

    assert live.destination_days[0] == date(2026, 7, 31)
    assert len(live.destination_days) == 14
