"""The loader on logs that real Zeek wrote, not the test helpers' imitation of them.

`fixtures/zeek-real/trace.pcap` is a synthetic capture (`make_pcap.py`). Zeek 9.0.1 read it three
times (JSON, JSON with ISO 8601 timestamps, TSV) with the site config in the root `Makefile`
(`make zeek-fixture`). Every expected value below follows from what the capture sends, worked out
by hand, so a wrong mapping fails here even when it agrees with the helpers.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from ipaddress import IPv4Network
from pathlib import Path
from typing import cast

import pytest
from zeek_logs import Query

from network_behaviour.source.zeek import load_day

FIXTURE = Path(__file__).resolve().parents[5] / "fixtures" / "zeek-real"
DAY = date(2026, 3, 2)
FORMATS = ("json", "json-iso", "tsv")

LAPTOP, WORKSTATION, BACKUP = "10.1.0.10", "10.1.0.20", "10.1.0.30"
RESOLVER = "198.51.100.53"
UPLOAD = 1_200_000


def _at(clock: str) -> datetime:
    hour, minute = (int(part) for part in clock.split(":"))
    return datetime(2026, 3, 2, hour, minute, tzinfo=UTC)


# A TLS 1.2 ClientHello naming www.shop.test is 78 bytes and the ServerHello 47. The HTTP request
# is 72 bytes and the response 66 bytes of headers plus a 920-byte body. The SSH-like banners are
# 21 bytes from the workstation and 17 from the remote side, which opened the session.
# The upload runs from 12:00:40.000 to 12:02:10.210 (90.21 s): 20 s, 60 s and 10.21 s of it fall in
# the three minutes, and the integer split floors the running total (1.2 MB * 20 / 90.21, ...).
EXPECTED_ACTIVITY = [
    # time, client, server, port, proto, application, category, root, sni, dns, up, down, starts
    (_at("12:00"), LAPTOP, "203.0.113.10", 443, 6, "shop", "ssl", "shop.test",
     "www.shop.test", "www.shop.test", 78, 47, 1),
    (_at("12:00"), LAPTOP, "203.0.113.30", 80, 6, "shop", "http", "shop.test",
     "", "files.shop.test", 72, 986, 1),
    (_at("12:00"), WORKSTATION, "192.0.2.25", 51515, 6, "", "_unknown", "", "", "", 21, 17, 1),
    (_at("12:00"), BACKUP, "203.0.113.40", 8443, 6, "", "_unknown", "", "", "", 266_045, 0, 1),
    (_at("12:01"), BACKUP, "203.0.113.40", 8443, 6, "", "_unknown", "", "", "", 798_138, 0, 0),
    (_at("12:02"), BACKUP, "203.0.113.40", 8443, 6, "", "_unknown", "", "", "", 135_817, 0, 0),
]  # fmt: skip


@pytest.fixture(params=[(fmt, nets) for fmt in FORMATS for nets in (False, True)],
                ids=lambda p: f"{p[0]}-{'local-nets' if p[1] else 'zeek-flags'}")  # fmt: skip
def loaded(request: pytest.FixtureRequest, tmp_path: Path, synthetic: None) -> tuple[str, bool]:
    fmt, nets = cast(tuple[str, bool], request.param)
    report = load_day(
        tmp_path / "source.duckdb",
        DAY,
        [FIXTURE / "logs" / fmt],
        local_nets=(IPv4Network("10.0.0.0/8"),) if nets else (),
    )
    # Eight connections: three DNS, TLS, HTTP, inbound, upload and the lone reply. Zeek's flags
    # agree with the local networks because the site config said so.
    assert (report.connections, report.dropped_connections, report.named_connections) == (8, 0, 2)
    return fmt, nets


def test_activity_matches_the_capture(loaded: tuple[str, bool], query: Query) -> None:
    rows = query(
        "SELECT time, client_ip, server_ip, server_port, transport_protocol, application, "
        "application_category, root_domain, sni, dns, up_bytes, down_bytes, flow_count "
        "FROM flow.activity_1m ORDER BY time, client_ip, server_ip"
    )
    assert rows == EXPECTED_ACTIVITY
    assert query("SELECT count(*) FROM flow.activity_1m WHERE asn IS NOT NULL") == [(0,)]


def test_packets_split_and_sum_to_zeek_counts(loaded: tuple[str, bool], query: Query) -> None:
    # 1,000 data segments plus SYN, ACK, FIN and the last ACK go up; 100 ACKs, SYN-ACK and FIN-ACK
    # come back.
    assert query(
        "SELECT sum(up_packets), sum(down_packets), count(*) FROM flow.activity_1m "
        f"WHERE client_ip = '{BACKUP}'"
    ) == [(1004, 102, 3)]


def test_rate_reconciles_per_bucket(loaded: tuple[str, bool], query: Query) -> None:
    rows = query(
        "SELECT time, client_ip, active_minutes, up_bytes, down_bytes FROM flow.host_load_5m "
        "ORDER BY client_ip"
    )
    assert rows == [
        (_at("12:00"), LAPTOP, 1, 78 + 72, 47 + 986),
        (_at("12:00"), WORKSTATION, 1, 21, 17),
        (_at("12:00"), BACKUP, 3, UPLOAD, 0),
    ]


def test_the_upload_is_the_only_long_flow(loaded: tuple[str, bool], query: Query) -> None:
    rows = query(
        "SELECT client_ip, client_port, server_ip, server_port, protocol, up_bytes, "
        "down_bytes, initiator, start, round(duration_sec, 2), flow_id <> '' FROM flow.long_flows"
    )
    assert rows == [
        (BACKUP, 50100, "203.0.113.40", 8443, 6, UPLOAD, 0, "client",
         datetime(2026, 3, 2, 12, 0, 40, tzinfo=UTC), 90.21, True),
    ]  # fmt: skip


def test_dns_pairs_count_answered_unanswered_and_unsolicited(
    loaded: tuple[str, bool], query: Query
) -> None:
    rows = query(
        "SELECT time, client_ip, server_ip, complete_sessions, unanswered_sessions, "
        "unsolicited_sessions, query_packets, response_packets, unanswered_query_packets, "
        "unsolicited_response_packets, mean_service_nanos FROM flow.dns_pairs ORDER BY client_ip"
    )
    # The laptop's two answers took 20 ms each (TSV rounds rtt to the microsecond, JSON keeps
    # the pcap's float error), and one query went unanswered. The workstation got one reply it
    # never asked for, which Zeek 9 logs in dns.log with an rcode and no rtt, and no weird.
    assert [row[:-1] for row in rows] == [
        (_at("12:00"), LAPTOP, RESOLVER, 2, 1, 0, 3, 2, 1, 0),
        (_at("12:00"), WORKSTATION, RESOLVER, 0, 0, 1, 0, 0, 0, 1),
    ]
    assert rows[0][-1] == pytest.approx(20_000_000, abs=100)
    assert rows[1][-1] == 0


def test_zeek_wrote_no_weird_log_for_the_lone_reply() -> None:
    for fmt in FORMATS:
        assert not (FIXTURE / "logs" / fmt / "weird.log").exists()
