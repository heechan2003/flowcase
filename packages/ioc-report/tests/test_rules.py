"""Every rule on its own fixture, the cases that must clear, and the ones that must not."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from network_behaviour.normalization.bitmap import ActivityBitmap

from ioc_report.feed import Case, Feed
from ioc_report.history import Episode, HostServiceDay, address_services
from ioc_report.live import LiveContext, PairContact
from ioc_report.registration import NameAge
from ioc_report.rules import (
    ESTABLISHED_MIN_ADDRESSES,
    EXPLAINED,
    REVIEW,
    SHARED_MIN_DOMAINS,
)
from tests.builders import decision, established, history, load
from tests.conftest import long_flow, minute_row, record

IP: dict[str, Any] = {"indicator": "1.1.1.1:443", "indicator_type": "ip:port"}
DAY = "2026-09-15"


def _shared_rows() -> list[dict[str, Any]]:
    """Rows from other feed hosts that make 1.1.1.1 carry SHARED_MIN_DOMAINS registered domains."""
    return [
        minute_row(
            f"{DAY} 07:00:00", host="192.0.2.200", sni=f"www.site{n}.com", root=f"site{n}.com"
        )
        for n in range(SHARED_MIN_DOMAINS)
    ]


def _with_neighbours(tmp_path: Path, main: dict[str, Any]) -> tuple[Feed, Case]:
    neighbour = record(_shared_rows(), host="192.0.2.200", **IP)
    feed, _ = load(tmp_path, [main, neighbour])
    case = next(c for c in feed.cases if c.host == "192.0.2.10")
    return feed, case


# Must clear ---------------------------------------------------------------------------------


def test_quic_ech_and_tls_to_a_site_clear_a_nanocore_address(tmp_path: Path) -> None:
    rows = [
        minute_row(f"{DAY} 10:00:00", transport=17, sni="www.news.com.au"),
        minute_row(f"{DAY} 10:01:00", sni="cloudflare-ech.com"),
        minute_row(f"{DAY} 10:02:00", sni="cdn.shop.example.com"),
    ]
    flows = [
        long_flow(start=f"{DAY} 09:59:00.000000", finish=f"{DAY} 10:00:30.000000", protocol=17)
    ]
    feed, case = load(tmp_path, [record(rows, flows=flows, **IP)])

    found = decision(feed, case)

    assert found.disposition == EXPLAINED
    assert [judged.rules for judged in found.contacts] == [("E1", "E3"), ("E2",), ("E3",)]
    assert found.flows[0].rules == ("E1", "E3")


def test_a_bore_client_on_its_control_port_is_explained(tmp_path: Path) -> None:
    rows = [
        minute_row(f"{DAY} 10:{m:02d}:00", port=7835, dns="bore.pub", root="bore.pub")
        for m in range(30)
    ]
    flows = [
        long_flow(
            duration=10_800.0,
            port=7835,
            start=f"{DAY} 10:00:00.000000",
            finish=f"{DAY} 13:00:00.000000",
        )
    ]
    feed, case = load(tmp_path, [record(rows, flows=flows, indicator="bore.pub")])

    found = decision(feed, case)

    assert found.disposition == EXPLAINED and found.explaining_rules == ("E5",)


def test_traffic_the_host_never_answered_is_explained(tmp_path: Path) -> None:
    feed, case = load(tmp_path, [record([minute_row(f"{DAY} 10:00:00", port=23, up=0)], **IP)])

    assert decision(feed, case).explaining_rules == ("E6",)


def test_an_established_site_on_a_shared_address_is_explained_for_any_family(
    tmp_path: Path,
) -> None:
    main = record(
        [minute_row(f"{DAY} 10:00:00", sni="www.portal.example.org")],
        malware="win.lumma",
        **IP,
    )
    feed, case = _with_neighbours(tmp_path, main)

    found = decision(feed, case, retained=history([established("www.portal.example.org")]))

    assert found.disposition == EXPLAINED and found.explaining_rules == ("E4",)


# Must stay in review ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("row", "why"),
    [
        (minute_row(f"{DAY} 10:00:00", port=1604), "no SNI"),
        (minute_row(f"{DAY} 10:00:00", dns="www.example.com"), "no SNI"),
        (minute_row(f"{DAY} 10:00:00", sni="c2.duckdns.org"), "dynamic DNS"),
    ],
)
def test_contact_nanocore_could_have_made_stays_in_review(
    tmp_path: Path, row: dict[str, Any], why: str
) -> None:
    feed, case = load(tmp_path, [record([row], **IP)])

    found = decision(feed, case)

    assert found.disposition == REVIEW and why in found.unexplained[0].gap


def test_tls_to_a_rare_name_for_a_family_without_a_profile_stays_in_review(tmp_path: Path) -> None:
    main = record(
        [minute_row(f"{DAY} 10:00:00", sni="update.rare-name.xyz")], malware="win.asyncrat", **IP
    )
    feed, case = _with_neighbours(tmp_path, main)

    found = decision(
        feed,
        case,
        retained=history(
            [established("update.rare-name.xyz", addresses=ESTABLISHED_MIN_ADDRESSES - 1)]
        ),
    )

    assert found.disposition == REVIEW
    assert "no cited C2 profile" in found.unexplained[0].gap


def test_a_scheduled_contact_keeps_a_protocol_explanation_in_review(tmp_path: Path) -> None:
    rows = [
        minute_row(f"{DAY} {8 + n // 2:02d}:{30 * (n % 2):02d}:00", sni="api.rare-name.xyz")
        for n in range(21)
    ]
    feed, case = load(tmp_path, [record(rows, **IP)])

    found = decision(feed, case)

    assert all(judged.rules == ("E3",) for judged in found.contacts)
    assert found.disposition == REVIEW and found.keeping_rules == ("K4",)


def test_a_retained_beacon_shape_on_the_matched_name_keeps_it_in_review(tmp_path: Path) -> None:
    feed, case = load(
        tmp_path, [record([minute_row(f"{DAY} 10:00:00", sni="api.rare-name.xyz")], **IP)]
    )
    beacon = HostServiceDay(
        date(2026, 9, 15),
        ActivityBitmap.from_buckets(list(range(0, 288, 12))).value,
        2_000,
        2_000,
        6,
        443,
        13335,
        0,
        0.0,
        service_rows_that_day=1,
    )
    retained = history(
        [established("api.rare-name.xyz", addresses=0, days=0, match_rows=(beacon,))]
    )

    found = decision(feed, case, retained=retained)

    assert found.keeping_rules == ("K4",) and "§13" in found.kept_by[0].text


def test_a_payload_download_is_never_explained_by_the_family_protocol(tmp_path: Path) -> None:
    rows = [minute_row(f"{DAY} 10:00:00", sni="files.rare-name.xyz", down=3_000_000)]
    flows = [
        long_flow(start=f"{DAY} 10:00:00.000000", finish=f"{DAY} 10:00:40.000000", duration=40.0)
    ]
    feed, case = load(tmp_path, [record(rows, flows=flows, threat_type="payload_delivery", **IP)])

    found = decision(feed, case)

    assert found.disposition == REVIEW
    assert "K5" in found.keeping_rules and "download server" in found.contacts[0].gap


def test_an_imitated_popular_name_from_another_network_is_not_established(tmp_path: Path) -> None:
    main = record(
        [minute_row(f"{DAY} 10:00:00", sni="www.microsoft.com", asn="14061")],
        malware="win.lumma",
        **IP,
    )
    feed, case = _with_neighbours(tmp_path, main)

    found = decision(
        feed, case, retained=history([established("www.microsoft.com", asns=frozenset({8075}))])
    )

    assert found.disposition == REVIEW and "AS14061" in found.unexplained[0].gap


def test_a_platform_tenant_is_not_established_by_the_platform(tmp_path: Path) -> None:
    main = record([minute_row(f"{DAY} 10:00:00", sni="abc.workers.dev")], malware="win.lumma", **IP)
    feed, case = _with_neighbours(tmp_path, main)

    found = decision(feed, case, retained=history([established("abc.workers.dev")]))

    assert found.disposition == REVIEW and "shared platform" in found.unexplained[0].gap


def test_an_address_not_shown_shared_does_not_establish_a_name(tmp_path: Path) -> None:
    site = "www.portal.example.org"
    main = record([minute_row(f"{DAY} 10:00:00", sni=site, asn="64500")], malware="win.lumma", **IP)
    feed, case = load(tmp_path, [main])

    found = decision(feed, case, retained=history([established(site, asns=frozenset({64500}))]))

    assert found.disposition == REVIEW and "§14" in found.unexplained[0].gap


CLOUDFLARE = "13335"


def test_a_network_shared_by_design_counts_as_shared_for_an_established_site(
    tmp_path: Path,
) -> None:
    site = "www.portal.example.org"
    main = record(
        [minute_row(f"{DAY} 10:00:00", sni=site, asn=CLOUDFLARE)], malware="win.lumma", **IP
    )
    feed, case = load(tmp_path, [main])

    found = decision(
        feed, case, retained=history([established(site, asns=frozenset({int(CLOUDFLARE)}))])
    )

    assert found.disposition == EXPLAINED and found.explaining_rules == ("E4",)
    assert "Cloudflare's network" in found.contacts[0].explained_by[0].text


def test_a_network_shared_by_design_does_not_make_a_name_established(tmp_path: Path) -> None:
    site = "www.portal.example.org"
    main = record(
        [minute_row(f"{DAY} 10:00:00", sni=site, asn=CLOUDFLARE)], malware="win.lumma", **IP
    )
    feed, case = load(tmp_path, [main])

    found = decision(
        feed,
        case,
        retained=history(
            [established(site, addresses=1, days=1, asns=frozenset({int(CLOUDFLARE)}))]
        ),
    )

    assert found.disposition == REVIEW and "§15" in found.unexplained[0].gap


def test_a_network_shared_by_design_never_clears_a_visit_to_the_flagged_domain(
    tmp_path: Path,
) -> None:
    site = "www.portal.example.org"
    main = record(
        [minute_row(f"{DAY} 10:00:00", sni=site, asn=CLOUDFLARE)],
        indicator=site,
        malware="js.clearfake",
        threat_type="payload_delivery",
    )
    feed, case = load(tmp_path, [main])

    found = decision(
        feed, case, retained=history([established(site, asns=frozenset({int(CLOUDFLARE)}))])
    )

    assert found.disposition == REVIEW and "K1" in found.keeping_rules


def _transfer(tmp_path: Path, **row: Any) -> str:
    flow = long_flow(duration=40.0, start=f"{DAY} 10:00:00.000000", finish=f"{DAY} 10:00:40.000000")
    main = record(
        [minute_row(f"{DAY} 10:00:00", asn=row.pop("asn", CLOUDFLARE), down=3_000_000, **row)],
        flows=[flow],
        malware="win.nanocore",
        threat_type="payload_delivery",
        **IP,
    )
    feed, case = load(tmp_path, [main])
    found = decision(feed, case)
    assert found.disposition == REVIEW
    (k5,) = [finding for finding in found.kept_by if finding.rule == "K5"]
    return k5.text


def test_a_transfer_on_a_shared_network_says_when_no_name_ties_it_to_the_site(
    tmp_path: Path,
) -> None:
    assert "no TLS name to tie them to the flagged site" in _transfer(tmp_path)


def test_a_transfer_under_a_tls_name_or_on_an_ordinary_network_says_nothing_of_it(
    tmp_path: Path,
) -> None:
    named = _transfer(tmp_path, sni="dl.example.org", root="example.org")
    assert "tie them" not in named
    ordinary = _transfer(tmp_path, asn="64500")
    assert "tie them" not in ordinary


def test_a_bore_visitor_port_is_kept(tmp_path: Path) -> None:
    rows = [minute_row(f"{DAY} 10:00:00", port=41234, dns="bore.pub", root="bore.pub")]
    feed, case = load(tmp_path, [record(rows, indicator="bore.pub")])

    assert decision(feed, case).keeping_rules == ("K1", "K2")


def test_a_lure_visit_is_always_kept(tmp_path: Path) -> None:
    rows = [minute_row(f"{DAY} 10:00:00", sni="www.lure.example.com", up=600, down=4_000)]
    feed, case = load(
        tmp_path,
        [
            record(
                rows,
                indicator="lure.example.com",
                threat_type="payload_delivery",
                malware="js.clearfake",
            )
        ],
    )

    found = decision(feed, case)

    assert found.keeping_rules == ("K1",) and "lure" in found.kept_by[0].text


def test_live_contact_on_another_port_keeps_an_explained_match_in_review(tmp_path: Path) -> None:
    feed, case = load(tmp_path, [record([minute_row(f"{DAY} 10:00:00", transport=17)], **IP)])
    raw_tcp = PairContact(
        day=date(2026, 9, 15),
        server_ip="1.1.1.1",
        transport=6,
        port=1604,
        sni="",
        root_domain="",
        dns="",
        asn="13335",
        active_minutes=1,
        minute_epochs=(int(datetime(2026, 9, 15, 11, tzinfo=UTC).timestamp()) // 60,),
        up_bytes=500,
        down_bytes=500,
        flows=1,
    )
    live = LiveContext(
        status="queried",
        days_queried=(date(2026, 9, 15),),
        contacts={("192.0.2.10", "1.1.1.1"): (raw_tcp,)},
    )

    found = decision(feed, case, live=live)

    assert decision(feed, case).disposition == EXPLAINED
    assert found.disposition == REVIEW and "1604/TCP" in found.unexplained[0].item.label


def test_a_triage_episode_on_the_flagged_address_itself_is_kept(tmp_path: Path) -> None:
    feed, case = load(tmp_path, [record([minute_row(f"{DAY} 10:00:00", transport=17)], **IP)])
    (address,) = address_services(case)
    on_address = Episode(date(2026, 9, 15), "relationship", "E2", address.service_id_hex, None)
    elsewhere = Episode(date(2026, 9, 15), "relationship", "E2", "ab" * 16, "example.com")

    assert decision(feed, case, retained=history(episodes=[on_address])).keeping_rules == ("K3",)
    assert decision(feed, case, retained=history(episodes=[elsewhere])).disposition == EXPLAINED


def test_records_that_disagree_on_the_family_disable_protocol_rules(tmp_path: Path) -> None:
    rows = [minute_row(f"{DAY} 10:00:00", transport=17)]
    feed, case = load(tmp_path, [record(rows, **IP), record(rows, malware="win.asyncrat", **IP)])

    found = decision(feed, case)

    assert found.disposition == REVIEW and found.notes


def test_an_unattributable_tcp_flow_stays_unexplained(tmp_path: Path) -> None:
    rows = [minute_row(f"{DAY} 10:00:00", transport=17)]
    flows = [
        long_flow(start=f"{DAY} 14:00:00.000000", finish=f"{DAY} 15:30:00.000000", duration=5400.0)
    ]
    feed, case = load(tmp_path, [record(rows, flows=flows, **IP)])

    found = decision(feed, case)

    assert found.disposition == REVIEW and "cannot be attributed" in found.unexplained[0].gap


def _registered(when: datetime | None, status: str = "ok") -> dict[str, NameAge]:
    return {"rare-name.xyz": NameAge("rare-name.xyz", when, status)}


@pytest.mark.parametrize(
    ("registered", "status", "kept"),
    [
        (datetime(2014, 3, 2, tzinfo=UTC), "ok", False),  # years old: another site
        (datetime(2026, 9, 10, tzinfo=UTC), "ok", True),  # 5 days old: may be the operator's
        (None, "no-service", False),  # unknown age changes nothing
        (datetime(2026, 10, 1, tzinfo=UTC), "ok", False),  # registered again after the match
    ],
)
def test_a_newly_registered_tls_name_is_no_protocol_mismatch(
    tmp_path: Path, registered: datetime | None, status: str, kept: bool
) -> None:
    feed, case = load(
        tmp_path, [record([minute_row(f"{DAY} 10:00:00", sni="api.rare-name.xyz")], **IP)]
    )

    found = decision(feed, case, registrations=_registered(registered, status))

    assert found.disposition == (REVIEW if kept else EXPLAINED)
    if kept:
        assert "registered 2026-09-10, 5 day(s) before the first match" in found.unexplained[0].gap
    assert decision(feed, case).disposition == EXPLAINED  # not looked up: E3 as before
