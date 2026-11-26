"""One test per Zeek mapping rule (`source/zeek/loader.py`, `docs/SOURCE_CONTRACT.md`)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from ipaddress import IPv4Network, ip_network
from pathlib import Path

import pytest
from zeek_logs import DAY, Query, at, conn, dns, write_json, write_tsv

from network_behaviour.normalization.ip import NormalizedIp
from network_behaviour.normalization.service import registered_domain
from network_behaviour.publication import NORMALIZATION_BUNDLE_VERSION, normalization_bundle_version
from network_behaviour.source.zeek import LOADER_VERSION, LoadReport, ZeekLoadError, load_day
from network_behaviour.source.zeek.loader import LONG_FLOW_MIN_BYTES, parse_local_nets

NETS = (IPv4Network("10.0.0.0/8"),)
HOST = "10.1.2.3"
SERVER = "198.51.100.10"


def _load(
    tmp_path: Path, *, nets: bool = True, day: date = DAY, asn_table: Path | None = None
) -> LoadReport:
    return load_day(
        tmp_path / "source.duckdb",
        day,
        [tmp_path / "logs"],
        local_nets=NETS if nets else (),
        asn_table=asn_table,
    )


def _minute(clock: str) -> datetime:
    return datetime.fromtimestamp(at(clock), UTC)


# --- orientation ----------------------------------------------------------------------------------


def test_the_local_side_is_the_client_and_server_port_is_the_remote_port(
    tmp_path: Path, query: Query
) -> None:
    write_json(
        tmp_path / "logs",
        "conn",
        [
            conn("out", at("10:00:00"), HOST, SERVER, orig_p=50001, resp_p=443,
                 orig_bytes=10, resp_bytes=20),
            # The remote side opened this one, to the host's port 22.
            conn("in", at("11:00:00"), "203.0.113.7", HOST, orig_p=40000, resp_p=22,
                 orig_bytes=30, resp_bytes=40),
            conn("lateral", at("12:00:00"), HOST, "10.9.9.9"),
            conn("transit", at("13:00:00"), SERVER, "203.0.113.7"),
        ],
    )  # fmt: skip

    report = _load(tmp_path)

    rows = query(
        "SELECT client_ip, server_ip, server_port, up_bytes, down_bytes FROM flow.activity_1m "
        "ORDER BY time"
    )
    assert rows == [(HOST, SERVER, 443, 10, 20), (HOST, "203.0.113.7", 40000, 40, 30)]
    assert report.dropped_connections == 2


def test_zeek_flags_decide_locality_when_no_networks_are_given(
    tmp_path: Path, query: Query
) -> None:
    write_json(
        tmp_path / "logs",
        "conn",
        [conn("in", at("10:00:00"), SERVER, "192.168.5.5", resp_p=8443,
              local_orig=False, local_resp=True)],
    )  # fmt: skip

    _load(tmp_path, nets=False)

    assert query("SELECT client_ip, server_ip FROM flow.activity_1m") == [("192.168.5.5", SERVER)]


def test_a_day_where_every_connection_is_dropped_says_why(tmp_path: Path) -> None:
    # Zeek's default site config counts private and documentation ranges as local, so on
    # synthetic data both sides of every connection are flagged local.
    write_json(
        tmp_path / "logs",
        "conn",
        [conn("both", at("10:00:00"), HOST, SERVER, local_orig=True, local_resp=True)],
    )

    by_flags = _load(tmp_path, nets=False).render()
    by_nets = load_day(
        tmp_path / "other.duckdb",
        DAY,
        [tmp_path / "logs"],
        local_nets=(IPv4Network("10.9.0.0/16"),),
    ).render()

    assert "Site::private_address_space_is_local" in by_flags
    assert "inside the local networks given" in by_nets
    assert "warning" not in _load(tmp_path).render()


def test_long_flows_record_who_opened_them(tmp_path: Path, query: Query) -> None:
    big = LONG_FLOW_MIN_BYTES
    write_json(
        tmp_path / "logs",
        "conn",
        [
            conn("up", at("09:00:00"), HOST, SERVER, duration=600.0, orig_bytes=big, resp_bytes=0),
            conn("served", at("10:00:00"), "203.0.113.7", HOST, orig_p=40000, resp_p=443,
                 duration=60.0, orig_bytes=0, resp_bytes=big),
            conn("small", at("11:00:00"), HOST, SERVER, orig_bytes=big - 1, resp_bytes=0),
        ],
    )  # fmt: skip

    _load(tmp_path)

    rows = query(
        "SELECT flow_id, client_ip, client_port, server_port, up_bytes, initiator, duration_sec "
        "FROM flow.long_flows ORDER BY start"
    )
    assert rows == [
        ("up", HOST, 50000, 443, big, "client", 600.0),
        ("served", HOST, 443, 40000, big, "server", 60.0),
    ]


# --- minute grain ---------------------------------------------------------------------------------


def test_a_connection_occupies_every_minute_it_spans_and_its_bytes_split_exactly(
    tmp_path: Path, query: Query
) -> None:
    write_json(
        tmp_path / "logs",
        "conn",
        [
            conn("long", at("10:00:30"), HOST, SERVER, duration=150.0, orig_bytes=3000,
                 resp_bytes=7, orig_pkts=10, resp_pkts=1),
            conn("instant", at("10:05:10"), HOST, SERVER, duration=None, orig_bytes=5),
        ],
    )  # fmt: skip

    _load(tmp_path)

    rows = query(
        "SELECT time, up_bytes, down_bytes, up_packets, flow_count FROM flow.activity_1m "
        "ORDER BY time"
    )
    assert rows == [
        (_minute("10:00:00"), 600, 1, 2, 1),
        (_minute("10:01:00"), 1200, 3, 4, 0),
        (_minute("10:02:00"), 1200, 3, 4, 0),
        (_minute("10:05:00"), 5, 200, 2, 1),
    ]


def test_only_the_days_own_minutes_are_written_and_the_next_day_writes_the_rest(
    tmp_path: Path, query: Query
) -> None:
    # Zeek logs a connection when it ends, so this one is in the next day's folder.
    next_day = DAY + timedelta(days=1)
    write_json(
        tmp_path / "logs" / next_day.isoformat(),
        "conn",
        [conn("midnight", at("23:59:00"), HOST, SERVER, duration=120.0, orig_bytes=400)],
    )
    write_json(
        tmp_path / "logs" / DAY.isoformat(), "conn", [conn("x", at("01:00:00"), HOST, SERVER)]
    )

    _load(tmp_path)
    assert query("SELECT time, up_bytes FROM flow.activity_1m WHERE up_bytes = 200") == [
        (_minute("23:59:00"), 200)
    ]
    _load(tmp_path, day=next_day)

    assert query(
        "SELECT time, up_bytes FROM flow.activity_1m WHERE up_bytes = 200 ORDER BY time"
    ) == [(_minute("23:59:00"), 200), (datetime(2026, 7, 11, tzinfo=UTC), 200)]


def test_reloading_a_day_replaces_it(tmp_path: Path, query: Query) -> None:
    write_json(tmp_path / "logs", "conn", [conn("a", at("10:00:00"), HOST, SERVER)])

    _load(tmp_path)
    _load(tmp_path)

    assert query("SELECT count(*) FROM flow.activity_1m") == [(1,)]


def test_each_day_records_the_mapping_and_locality_that_built_it(
    tmp_path: Path, query: Query
) -> None:
    write_json(tmp_path / "logs", "conn", [conn("a", at("10:00:00"), HOST, SERVER)])

    _load(tmp_path, nets=False)
    report = _load(tmp_path)

    assert query("SELECT day, loader_version, locality FROM zeek.loaded_day") == [
        (DAY, LOADER_VERSION, "10.0.0.0/8")
    ]
    assert f"({LOADER_VERSION}, local by --local-nets)" in report.render()


def test_plain_dns_stays_out_of_activity(tmp_path: Path, query: Query) -> None:
    write_json(
        tmp_path / "logs",
        "conn",
        [conn("q", at("10:00:00"), HOST, "198.51.100.53", proto="udp", resp_p=53, service="dns")],
    )

    _load(tmp_path)

    assert query("SELECT count(*) FROM flow.activity_1m") == [(0,)]


# --- names ----------------------------------------------------------------------------------------


@pytest.mark.usefixtures("synthetic")
def test_sni_and_the_resolved_name_are_attributed_by_connection(
    tmp_path: Path, query: Query
) -> None:
    logs = tmp_path / "logs"
    write_json(
        logs,
        "conn",
        [
            conn("tls", at("10:00:10"), HOST, SERVER, service="ssl"),
            conn("named", at("10:00:20"), HOST, "198.51.100.20", service="http", resp_p=80),
            conn("stale", at("10:30:00"), HOST, "198.51.100.20", service=None, resp_p=8080),
            conn("other", at("10:00:30"), "10.7.7.7", "198.51.100.20", service=None),
        ],
    )
    write_json(logs, "ssl", [{"ts": at("10:00:10"), "uid": "tls", "server_name": "WWW.Shop.Test"}])
    write_json(
        logs,
        "dns",
        [dns("d1", at("10:00:00"), HOST, "198.51.100.53", "cdn.media.test",
             ["alias.media.test", "198.51.100.20"], [60.0, 300.0])],
    )  # fmt: skip

    _load(tmp_path)

    rows = query(
        "SELECT client_ip, server_port, sni, dns, root_domain, application, application_category "
        "FROM flow.activity_1m ORDER BY time, client_ip, server_port"
    )
    assert rows == [
        (HOST, 80, "", "cdn.media.test", "media.test", "media", "http"),
        (HOST, 443, "www.shop.test", "", "shop.test", "shop", "ssl"),
        # Another host's connection to the same address: it never resolved the name.
        ("10.7.7.7", 443, "", "", "", "", "_unknown"),
        # After the answer's TTL ran out, the name no longer covers the address.
        (HOST, 8080, "", "", "", "", "_unknown"),
    ]


def test_server_asn_comes_from_an_ip2asn_table(tmp_path: Path, query: Query) -> None:
    table = tmp_path / "ip2asn.tsv"
    table.write_text(
        "198.51.100.0\t198.51.100.255\t64500\tZZ\tEXAMPLE-NET\n"
        f"{int(ip_network('203.0.113.0/24').network_address)}\t"
        f"{int(ip_network('203.0.113.0/24').broadcast_address)}\t64501\tZZ\tOTHER-NET\n"
        "192.0.2.0\t192.0.2.255\t0\tNone\tNot routed\n",
        encoding="utf-8",
    )
    write_json(
        tmp_path / "logs",
        "conn",
        [
            conn("a", at("10:00:00"), HOST, SERVER),
            conn("b", at("10:01:00"), HOST, "203.0.113.9"),
            conn("c", at("10:02:00"), HOST, "192.0.2.1"),
        ],
    )

    _load(tmp_path, asn_table=table)

    assert query("SELECT asn FROM flow.activity_1m ORDER BY time") == [
        ("64500",),
        ("64501",),
        (None,),
    ]


# --- rate -----------------------------------------------------------------------------------------


def test_the_rate_table_reconciles_with_activity_and_keeps_a_p95_of_minute_rates(
    tmp_path: Path, query: Query
) -> None:
    write_json(
        tmp_path / "logs",
        "conn",
        [
            conn("a", at("10:00:00"), HOST, SERVER, duration=120.0, orig_bytes=1200),
            conn("b", at("10:01:00"), HOST, "198.51.100.11", duration=60.0, orig_bytes=600),
        ],
    )

    _load(tmp_path)

    activity = query(
        "SELECT sum(up_bytes), sum(down_bytes) FROM flow.activity_1m WHERE client_ip = '10.1.2.3'"
    )
    rate = query(
        "SELECT time, active_minutes, up_rate_p95_bps, up_bytes, down_bytes FROM flow.host_load_5m"
    )
    # Minute 10:00 carries a's 80 bit/s; minute 10:01 carries a's 80 and b's 80.
    assert rate == [(_minute("10:00:00"), 2, pytest.approx(80 + 0.95 * 80), 1800, 400)]
    assert activity == [(1800, 400)]


# --- DNS pairs ------------------------------------------------------------------------------------


def test_dns_pairs_count_sessions_packets_service_time_and_unsolicited_replies(
    tmp_path: Path, query: Query
) -> None:
    resolver = "198.51.100.53"
    logs = tmp_path / "logs"
    write_json(
        logs,
        "conn",
        [
            conn("d1", at("10:00:00"), HOST, resolver, proto="udp", resp_p=53, service="dns",
                 orig_pkts=1, resp_pkts=1),
            conn("d2", at("10:10:00"), HOST, resolver, proto="udp", resp_p=53, service="dns",
                 orig_pkts=3, resp_pkts=0),
        ],
    )  # fmt: skip
    write_json(
        logs,
        "dns",
        [
            dns("d1", at("10:00:00"), HOST, resolver, "a.example.test", rtt=0.010),
            dns("d1", at("10:00:01"), HOST, resolver, "b.example.test", rtt=0.030),
            dns("d2", at("10:10:00"), HOST, resolver, "c.example.test", rtt=None),
        ],
    )
    write_json(
        logs,
        "weird",
        [{"ts": at("10:20:00"), "uid": "w1", "id.orig_h": HOST, "id.resp_h": resolver,
          "name": "dns_unmatched_reply"}],
    )  # fmt: skip

    _load(tmp_path)

    rows = query(
        "SELECT time, client_ip, server_ip, complete_sessions, unanswered_sessions, "
        "unsolicited_sessions, query_packets, response_packets, unanswered_query_packets, "
        "unsolicited_response_packets, mean_service_nanos FROM flow.dns_pairs"
    )
    assert rows == [(_minute("10:00:00"), HOST, resolver, 2, 1, 1, 4, 1, 3, 1, 20_000_000)]


def test_a_reply_zeek_could_not_match_is_unsolicited_and_counted_once(
    tmp_path: Path, query: Query
) -> None:
    """Zeek 9 logs a reply without a query as a dns.log row with an `rcode` and no `rtt`, and
    raises no weird (`tests/integration/source/test_zeek_real.py`). Older versions flagged it in
    weird.log as `dns_unmatched_reply`; when both are present it counts once."""
    resolver = "198.51.100.53"
    logs = tmp_path / "logs"
    write_json(
        logs,
        "conn",
        [
            # Zeek flips a lone reply so the client is the originator, with no query packets.
            conn("r1", at("10:00:00"), HOST, resolver, proto="udp", resp_p=53, service="dns",
                 orig_pkts=0, resp_pkts=1),
            conn("q1", at("10:05:00"), HOST, resolver, proto="udp", resp_p=53, service="dns",
                 orig_pkts=1, resp_pkts=0),
        ],
    )  # fmt: skip
    write_json(
        logs,
        "dns",
        [
            dns("r1", at("10:00:00"), HOST, resolver, "a.example.test", reply_only=True),
            dns("q1", at("10:05:00"), HOST, resolver, "b.example.test", rtt=None),
        ],
    )
    write_json(
        logs,
        "weird",
        [
            {"ts": at("10:00:00"), "uid": "r1", "id.orig_h": HOST, "id.resp_h": resolver,
             "name": "dns_unmatched_reply"},
            {"ts": at("10:30:00"), "uid": "w2", "id.orig_h": HOST, "id.resp_h": resolver,
             "name": "dns_unmatched_reply"},
        ],
    )  # fmt: skip

    _load(tmp_path)

    rows = query(
        "SELECT complete_sessions, unanswered_sessions, unsolicited_sessions, query_packets, "
        "response_packets, unanswered_query_packets, unsolicited_response_packets "
        "FROM flow.dns_pairs"
    )
    assert rows == [(0, 1, 2, 1, 0, 1, 2)]


# --- formats --------------------------------------------------------------------------------------


def test_tsv_logs_load_like_json(tmp_path: Path, query: Query) -> None:
    fields = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
    ]
    write_tsv(
        tmp_path / "logs",
        "conn",
        fields,
        [[f"{at('10:00:00'):.6f}", "t1", HOST, "50000", SERVER, "443", "tcp", "-", "1.000000",
          "100", "200", "2", "3"]],
    )  # fmt: skip

    _load(tmp_path)

    assert query(
        "SELECT client_ip, server_ip, up_bytes, down_bytes, application_category "
        "FROM flow.activity_1m"
    ) == [(HOST, SERVER, 100, 200, "_unknown")]


def test_a_day_without_a_conn_log_is_refused(tmp_path: Path) -> None:
    (tmp_path / "logs").mkdir()
    with pytest.raises(ZeekLoadError, match="no conn log"):
        _load(tmp_path)


def test_local_networks_must_be_ipv4() -> None:
    assert parse_local_nets(" 10.0.0.0/8, 172.16.0.0/12 ,") == (
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
    )
    with pytest.raises(ZeekLoadError, match="IPv4"):
        parse_local_nets("2001:db8::/32")


# --- the synthetic-world switch -------------------------------------------------------------------


def test_the_synthetic_switch_admits_documentation_servers_and_test_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = NormalizedIp.parse(SERVER)
    monkeypatch.delenv("NETWORK_BEHAVIOUR_SYNTHETIC", raising=False)
    assert not server.is_public_destination
    assert registered_domain("www.shop.test") is None
    assert normalization_bundle_version() == NORMALIZATION_BUNDLE_VERSION

    monkeypatch.setenv("NETWORK_BEHAVIOUR_SYNTHETIC", "1")
    assert server.is_public_destination
    assert not NormalizedIp.parse("10.1.2.3").is_public_destination
    assert registered_domain("www.shop.test") == "shop.test"
    assert normalization_bundle_version() == NORMALIZATION_BUNDLE_VERSION + "+synthetic"
