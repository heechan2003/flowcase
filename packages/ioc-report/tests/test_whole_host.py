"""The host as a whole from retained history, and the retained use of names the context lines
show."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import duckdb

from ioc_report.casefile import render_case_file
from ioc_report.contact import build_evidence
from ioc_report.feed import Case, load_feed
from ioc_report.history import name_key, read_history, read_name_use, superseded
from ioc_report.live import LiveContext
from ioc_report.rules import decide
from tests.conftest import insert, minute_row, publish, record, write_feed

MATCH = date(2026, 9, 16)
HOST = "192.0.2.10"


def _case(tmp_path: Path) -> Case:
    rows = [minute_row("2026-09-16 10:00:00", sni="www.example.com")]
    (case,) = load_feed(write_feed(tmp_path, [record(rows)])).cases
    return case


def _service(name: str) -> bytes:
    key = name_key(name)
    assert key is not None
    return bytes.fromhex(key.service_id_hex)


def _use(connection: duckdb.DuckDBPyConnection, day: date, client: str, name: str) -> None:
    insert(
        connection,
        "history.client_service_day",
        {
            "day": day,
            "client_ip": client,
            "service_id": _service(name),
            "service_basis": "domain",
            "asn_id": 13335,
            "active_5m_bitmap": bytes(36),
        },
    )


def test_the_whole_host_is_read_on_every_retained_day(tmp_path: Path, store_path: Path) -> None:
    case = _case(tmp_path)
    days = [MATCH - timedelta(days=2), MATCH - timedelta(days=1), MATCH, MATCH + timedelta(days=1)]
    with duckdb.connect(str(store_path)) as connection:
        for day, flows in zip(days, (5, 7, 0, 3), strict=True):
            insert(
                connection,
                "history.client_day",
                {"day": day, "client_ip": HOST, "flow_count": flows},
            )
            publish(connection, day)
        _use(connection, days[0], HOST, "habit-site.com")
        _use(connection, days[3], HOST, "new-site.com")
        for day, family, tier, name in (
            (days[1], "relationship", "E3", "habit-site.com"),
            (days[3], "persistence", "E2", "new-site.com"),
        ):
            insert(
                connection,
                "feed.episode",
                {
                    "day": day,
                    "client_ip": HOST,
                    "family": family,
                    "evidence_tier": tier,
                    "service_id": _service(name).hex(),
                    "service_domain": name,
                    "sequence": 1,
                    "tie_group": 1,
                    "family_strength": 99.0,
                },
            )

    whole = read_history(store_path, [case]).cases[(case.indicator, case.host)].whole_host

    assert whole is not None
    assert (whole.first_day, whole.last_day) == (days[0], days[3])
    assert (whole.retained_days, whole.addressed_days) == (4, 3)
    assert set(whole.episode_counts) == {("relationship", "E3", 1), ("persistence", "E2", 1)}
    assert whole.episode_days == 2
    assert [(e.family, e.service_domain) for e in whole.other_episodes] == [
        ("persistence", "new-site.com")
    ]
    assert whole.other_episode_count == 1
    assert (whole.services_since_match, whole.names_since_match) == (1, ("new-site.com",))


def test_name_use_reads_the_host_and_the_campus_before_the_match(store_path: Path) -> None:
    with duckdb.connect(str(store_path)) as connection:
        _use(connection, MATCH - timedelta(days=40), HOST, "spa-site.com")
        for offset, client in enumerate(("192.0.2.20", "192.0.2.21", "192.0.2.22")):
            _use(connection, MATCH - timedelta(days=offset + 1), client, "spa-site.com")
        _use(connection, MATCH + timedelta(days=1), "192.0.2.23", "spa-site.com")
        publish(connection, MATCH)

    found = read_name_use(
        store_path,
        [(HOST, MATCH, "spa-site.com"), (HOST, MATCH, "never-site.com"), (HOST, MATCH, "234.16")],
    )

    use = found[(HOST, MATCH, "spa-site.com")]
    assert use.host_first_day == MATCH - timedelta(days=40)
    assert (use.prior_addresses, use.prior_days) == (4, 4)
    never = found[(HOST, MATCH, "never-site.com")]
    assert (never.host_first_day, never.prior_addresses) == (None, 0)
    assert (HOST, MATCH, "234.16") not in found


def test_name_use_reads_nothing_without_a_hashable_name(tmp_path: Path) -> None:
    assert read_name_use(tmp_path / "absent.duckdb", [(HOST, MATCH, "234.16")]) == {}


def test_episodes_on_one_day_are_listed_in_one_order(tmp_path: Path, store_path: Path) -> None:
    case = _case(tmp_path)
    names = sorted(
        ("alpha-site.com", "beta-site.com", "gamma-site.com"),
        key=lambda name: _service(name).hex(),
        reverse=True,
    )
    with duckdb.connect(str(store_path)) as connection:
        insert(connection, "history.client_day", {"day": MATCH, "client_ip": HOST, "flow_count": 1})
        publish(connection, MATCH)
        for sequence, name in enumerate(names, 1):
            insert(
                connection,
                "feed.episode",
                {
                    "day": MATCH,
                    "client_ip": HOST,
                    "family": "persistence",
                    "evidence_tier": "E2",
                    "service_id": _service(name).hex(),
                    "service_domain": name,
                    "sequence": sequence,
                    "tie_group": 1,
                    "family_strength": 99.0,
                },
            )

    whole = read_history(store_path, [case]).cases[(case.indicator, case.host)].whole_host

    assert whole is not None
    assert [e.service_domain for e in whole.other_episodes] == names[::-1]


def _episode(connection: duckdb.DuckDBPyConnection, day: date, family: str) -> None:
    insert(
        connection,
        "feed.episode",
        {
            "day": day,
            "client_ip": HOST,
            "family": family,
            "evidence_tier": "E3",
            "sequence": 1,
            "tie_group": 1,
            "family_strength": 90.0,
        },
    )


def test_episodes_scored_before_their_family_was_corrected_are_marked(
    tmp_path: Path, store_path: Path
) -> None:
    feed = load_feed(
        write_feed(tmp_path, [record([minute_row("2026-09-16 10:00:00", sni="www.example.com")])])
    )
    (case,) = feed.cases
    days = [MATCH - timedelta(days=2), MATCH - timedelta(days=1), MATCH]
    with duckdb.connect(str(store_path)) as connection:
        for day, detector, family in zip(
            days,
            ("primary-detectors-v7", "primary-detectors-v8", "primary-detectors-v9"),
            ("dns", "transfer", "fanout"),
            strict=True,
        ):
            insert(connection, "history.client_day", {"day": day, "client_ip": HOST})
            publish(connection, day, detector=detector)
            _episode(connection, day, family)

    history = read_history(store_path, [case])
    retained = history.cases[(case.indicator, case.host)]

    assert retained.whole_host is not None
    assert retained.whole_host.superseded == (("dns", 1), ("transfer", 1))
    assert [(e.family, e.superseded) for e in retained.episodes] == [("fanout", False)]
    live = LiveContext(status="skipped")
    evidence = build_evidence(case, feed, live, retained)
    text = render_case_file(evidence, decide(evidence, feed.domain_indicators), live, history)
    (line,) = [line for line in text.splitlines() if "were published before" in line]
    assert "1 DNS episode(s) were published before primary-detectors-v8" in line
    assert "1 transfer or fanout episode(s) were published before primary-detectors-v9" in line


def test_a_generation_that_names_no_detector_is_never_marked() -> None:
    assert superseded("dns", "primary-detectors-v7")
    assert not superseded("dns", "primary-detectors-v8")
    assert not superseded("relationship", "primary-detectors-v2")
    assert not superseded("fanout", "x")


def test_products_with_a_known_purpose_are_counted_by_day(tmp_path: Path, store_path: Path) -> None:
    case = _case(tmp_path)
    with duckdb.connect(str(store_path)) as connection:
        for offset in (1, 2, 40):
            _use(connection, MATCH - timedelta(days=offset), HOST, "windowsupdate.com")
        _use(connection, MATCH - timedelta(days=1), HOST, "office.com")
        _use(connection, MATCH - timedelta(days=1), HOST, "sharepoint.com")
        _use(connection, MATCH - timedelta(days=1), "192.0.2.77", "cloudsink.net")
        publish(connection, MATCH)

    whole = read_history(store_path, [case]).cases[(case.indicator, case.host)].whole_host

    assert whole is not None
    found = {use.key: (use.days, use.recent_days) for use in whole.signals}
    # Two domains of one product on one day count once; another address's use is not this host's.
    assert found == {"windows-update": (3, 2), "microsoft-365": (1, 1)}
    assert whole.signals[0].key == "windows-update"
