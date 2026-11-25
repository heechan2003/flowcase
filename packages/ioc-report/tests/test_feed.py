from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from network_behaviour.normalization.ip import NormalizedIp
from network_behaviour.normalization.service import build_logical_service

from ioc_report.feed import FeedError, load_feed, load_feeds
from tests.conftest import FIXTURES, long_flow, minute_row, record, write_feed


def test_the_fixture_groups_into_one_case_per_indicator_and_host() -> None:
    feed = load_feed(FIXTURES / "ioc_matches_synthetic.json")

    assert (feed.record_count, len(feed.cases), feed.hosts, feed.indicators) == (3, 2, 2, 2)
    assert feed.rejected == ()
    tunnel = next(case for case in feed.cases if case.indicator == "tunnel.example.com")
    assert len(tunnel.minutes) == 2
    assert tunnel.match_ids == ("m_fixture_0001", "m_fixture_0002")


def test_a_long_flow_repeated_on_every_minute_is_counted_once(tmp_path: Path) -> None:
    flow = long_flow(duration=10_800.0)
    feed = load_feed(
        write_feed(
            tmp_path,
            [
                record([minute_row(f"2026-09-15 10:0{minute}:00")], flows=[flow])
                for minute in range(5)
            ],
        )
    )

    (case,) = feed.cases
    assert len(case.long_flows) == 1
    assert case.held_open


def test_held_open_starts_at_one_hour(tmp_path: Path) -> None:
    short = load_feed(
        write_feed(
            tmp_path,
            [record([minute_row("2026-09-15 10:00:00")], flows=[long_flow(duration=3599.0)])],
        )
    )
    assert not short.cases[0].held_open


def test_unusable_records_are_rejected_with_a_reason_not_dropped(tmp_path: Path) -> None:
    missing_host = record([minute_row("2026-09-15 10:00:00")], match_id="m_missing")
    del missing_host["affected_host"]
    other_client = record(
        [minute_row("2026-09-15 10:00:00", host="192.0.2.99")], match_id="m_other"
    )
    no_rows = record([], match_id="m_empty")
    good = record([minute_row("2026-09-15 10:00:00")])

    feed = load_feed(write_feed(tmp_path, [missing_host, other_client, no_rows, "text", good]))

    assert len(feed.cases) == 1
    reasons = {item.match_id: item.reason for item in feed.rejected}
    assert reasons["m_missing"] == "missing or invalid affected_host"
    assert reasons["m_other"] == "an evidence row names a different client than the record"
    assert reasons["m_empty"] == "record carries no matched traffic row"
    assert reasons["record 3"] == "record is not an object"


def test_flow_ports_and_feed_wide_correlation_are_read(tmp_path: Path) -> None:
    records = [
        record(
            [
                minute_row(
                    "2026-09-14 08:12:00", host=host, sni=f"www.site{n}.com", root=f"site{n}.com"
                )
            ],
            indicator="1.1.1.1:443",
            indicator_type="ip:port",
            host=host,
            flows=[long_flow(host=host, port=8443, protocol=17)] if n == 0 else None,
        )
        for n, host in enumerate(("192.0.2.10", "192.0.2.11"))
    ]
    records.append(
        record(
            [minute_row("2026-09-14 09:00:00", sni="lure.example.com")],
            indicator="lure.example.com",
        )
    )

    feed = load_feed(write_feed(tmp_path, records))

    first = next(
        case for case in feed.cases if case.host == "192.0.2.10" and case.indicator == "1.1.1.1:443"
    )
    assert (first.long_flows[0].server_port, first.long_flows[0].transport) == (8443, 17)
    assert first.rows[0].flow_count == 1
    assert first.domains_same_indicator == 2
    assert first.other_indicators == (("lure.example.com", "win.nanocore"),)
    assert feed.domain_indicators == frozenset({"lure.example.com"})
    assert feed.domains_by_address is not None and feed.domains_by_address["1.1.1.1"] == 2


def test_records_that_disagree_on_the_family_have_no_consistent_claim(tmp_path: Path) -> None:
    rows = [minute_row("2026-09-15 10:00:00")]
    feed = load_feed(write_feed(tmp_path, [record(rows), record(rows, malware="win.asyncrat")]))

    (case,) = feed.cases
    assert len(case.claims) == 2 and case.consistent_claim is None


def test_services_hash_exactly_as_the_publisher_does(tmp_path: Path) -> None:
    rows = [
        minute_row("2026-09-15 10:00:00", sni="www.example.com"),
        minute_row("2026-09-15 10:01:00", sni="www.example.com"),
        minute_row("2026-09-15 10:02:00"),
    ]
    (case,) = load_feed(write_feed(tmp_path, [record(rows)])).cases

    expected = build_logical_service(
        server_ip=NormalizedIp.parse("1.1.1.1"),
        root_domain=None,
        sni="www.example.com",
        dns=None,
        application=None,
        asn=None,
    )
    assert expected is not None
    (service,) = case.services
    assert (service.domain, service.service_id_hex, service.minutes) == (
        "example.com",
        expected.service_id.hex(),
        2,
    )


def test_an_ech_outer_name_is_flagged_and_not_counted_as_a_site(tmp_path: Path) -> None:
    records = [
        record(
            [minute_row("2026-09-14 08:12:00", host=host, sni="cloudflare-ech.com")],
            indicator="1.1.1.1:443",
            indicator_type="ip:port",
            host=host,
        )
        for host in ("192.0.2.10", "192.0.2.11", "192.0.2.12")
    ]

    feed = load_feed(write_feed(tmp_path, records))

    assert {case.other_hosts_same_indicator for case in feed.cases} == {2}
    assert all(case.ech_names == ("cloudflare-ech.com",) for case in feed.cases)
    assert {case.domains_same_indicator for case in feed.cases} == {0}
    assert feed.cases[0].days == (date(2026, 9, 14),)


def test_a_json_lines_feed_reads_like_an_array(tmp_path: Path) -> None:
    records = [record([minute_row(f"2026-09-15 10:0{n}:00")]) for n in range(3)]
    path = tmp_path / "feed.jsonl"
    path.write_text("\n".join(json.dumps(item) for item in records) + "\n\n", encoding="utf-8")

    feed = load_feed(path)

    assert (feed.record_count, len(feed.cases), len(feed.cases[0].minutes)) == (3, 1, 3)
    path.write_text(json.dumps(records[0]) + "\n{broken\n", encoding="utf-8")
    with pytest.raises(FeedError, match="line 2"):
        load_feed(path)


@pytest.mark.parametrize("content", ["{}", "not json"])
def test_a_feed_that_is_not_a_json_array_is_refused(tmp_path: Path, content: str) -> None:
    path = tmp_path / "feed.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(FeedError):
        load_feed(path)


def test_the_halves_of_a_split_export_load_as_one_feed(tmp_path: Path) -> None:
    rows = [minute_row("2026-09-15 10:00:00", sni="www.tunnel.example.com")]
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    domains = write_feed(tmp_path / "a", [record(rows), "not a record"])
    addresses = write_feed(
        tmp_path / "b", [record(rows, indicator="1.1.1.1:443", indicator_type="ip:port")]
    )

    feed = load_feeds([domains, addresses])

    assert feed.paths == (domains, addresses) and feed.record_count == 3
    assert {case.indicator for case in feed.cases} == {"tunnel.example.com", "1.1.1.1:443"}
    assert feed.domain_indicators == frozenset({"tunnel.example.com"})
    assert feed.rejected[0].match_id == "feed.json: record 1"


def test_threatfox_times_are_read_and_a_bad_one_rejects_nothing(tmp_path: Path) -> None:
    rows = [minute_row("2026-09-15 10:00:00")]
    first, second, broken = record(rows), record(rows), record(rows)
    first["threatfox"].update(
        first_seen_utc="2026-09-14T08:00:00Z", last_seen_utc="2026-09-15T00:00:00Z"
    )
    second["threatfox"].update(
        first_seen_utc="2026-09-13T08:00:00Z", last_seen_utc="2026-09-20T00:00:00Z"
    )
    broken["threatfox"].update(first_seen_utc="yesterday")

    (case,) = load_feed(write_feed(tmp_path, [first, second, broken])).cases

    assert case.matched_first == datetime(2026, 9, 13, 8, tzinfo=UTC)
    assert case.matched_last == datetime(2026, 9, 20, tzinfo=UTC)
    assert len(case.match_ids) == 3
