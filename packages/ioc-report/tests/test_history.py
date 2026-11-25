from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path

import duckdb
import pytest
from network_behaviour.population import CURRENT_SUPPORT_DEFINITION

from ioc_report.feed import Case, load_feed
from ioc_report.history import SCORED_MIN_SERVICES, HistoryError, read_history
from tests.conftest import insert, minute_row, publish, record, write_feed

MATCH_DAY = date(2026, 9, 16)
EARLIER = date(2026, 9, 14)
GAP = date(2026, 9, 15)


def _case(tmp_path: Path) -> Case:
    rows = [minute_row("2026-09-16 10:00:00", sni="www.example.com")]
    (case,) = load_feed(write_feed(tmp_path, [record(rows)])).cases
    return case


def _service_row(day: date, client: str, service_id: bytes, asn: int = 13335) -> dict[str, object]:
    return {
        "day": day,
        "client_ip": client,
        "service_id": service_id,
        "service_basis": "domain",
        "asn_id": asn,
        "active_5m_bitmap": bytes(36),
    }


def test_feed_names_join_retained_history_and_the_stream(tmp_path: Path, store_path: Path) -> None:
    case = _case(tmp_path)
    service_id = bytes.fromhex(case.services[0].service_id_hex)
    with duckdb.connect(str(store_path)) as connection:
        for day in (EARLIER, MATCH_DAY):
            insert(connection, "history.client_day", {"day": day, "client_ip": case.host})
            insert(
                connection, "history.client_service_day", _service_row(day, case.host, service_id)
            )
        insert(
            connection,
            "history.client_service_day",
            _service_row(MATCH_DAY, "192.0.2.99", service_id),
        )
        publish(connection, MATCH_DAY)
        insert(
            connection,
            "feed.episode",
            {
                "day": MATCH_DAY,
                "client_ip": case.host,
                "family": "relationship",
                "service_id": service_id.hex(),
                "evidence_tier": "E2",
                "sequence": 1,
                "tie_group": 1,
                "family_strength": 50.0,
            },
        )

    history = read_history(store_path, [case])

    assert history.coverage.gaps == (GAP,)
    record_ = history.cases[(case.indicator, case.host)]
    assert record_.match_days_retained == (MATCH_DAY,)
    assert record_.match_days_unpublished == ()
    service = record_.service(case.services[0].service_id_hex)
    assert service is not None and service.domain == "example.com"
    assert {s.key.basis for s in record_.services} == {"domain", "server_ip"}
    assert (service.campus_addresses, service.campus_days) == (2, 2)
    assert (service.host_first_day, service.host_days_before, service.host_days_on_match) == (
        EARLIER,
        1,
        1,
    )
    assert service.host_days_after == 0
    (episode,) = record_.same_service_episodes
    assert (episode.family, episode.tier) == ("relationship", "E2")


def test_use_before_the_first_match_and_match_day_rows_are_read(
    tmp_path: Path, store_path: Path
) -> None:
    case = _case(tmp_path)
    service_id = bytes.fromhex(case.services[0].service_id_hex)
    with duckdb.connect(str(store_path)) as connection:
        for day, client, asn in (
            (EARLIER, "192.0.2.21", 13335),
            (EARLIER, "192.0.2.22", 16509),
            (GAP, "192.0.2.21", 0),
            (MATCH_DAY, "192.0.2.23", 13335),
        ):
            insert(connection, "history.client_day", {"day": day, "client_ip": client})
            insert(
                connection, "history.client_service_day", _service_row(day, client, service_id, asn)
            )
        insert(
            connection,
            "history.client_day",
            {"day": MATCH_DAY, "client_ip": case.host, "unique_services": 40},
        )
        insert(
            connection, "history.client_service_day", _service_row(MATCH_DAY, case.host, service_id)
        )

    record_ = read_history(store_path, [case]).cases[(case.indicator, case.host)]

    service = record_.service(case.services[0].service_id_hex)
    assert service is not None and service.prior is not None
    prior = service.prior
    assert (prior.addresses, prior.days, prior.first_day) == (2, 2, EARLIER)
    assert prior.asn_ids == frozenset({13335, 16509})
    assert prior.retained_days == 2
    (row,) = service.match_rows
    assert (row.day, row.service_rows_that_day) == (MATCH_DAY, 2)
    (host_day,) = record_.host_days
    assert (host_day.day, host_day.unique_services) == (MATCH_DAY, 40)


def test_campus_quantiles_leave_out_addresses_with_no_service_row(
    tmp_path: Path, store_path: Path
) -> None:
    case = _case(tmp_path)
    with duckdb.connect(str(store_path)) as connection:
        insert(
            connection,
            "history.client_day",
            {"day": MATCH_DAY, "client_ip": case.host, "unique_services": 40},
        )
        for number, services in enumerate((10, 20, 30)):
            insert(
                connection,
                "history.client_day",
                {
                    "day": MATCH_DAY,
                    "client_ip": f"192.0.2.{30 + number}",
                    "unique_services": services,
                },
            )
        # Addresses carrying only unaddressed rows (CASE_STUDY §3): six of ten, as on campus.
        for number in range(6):
            insert(
                connection,
                "history.client_day",
                {"day": MATCH_DAY, "client_ip": f"192.0.2.{40 + number}", "unique_services": 0},
            )

    (host_day,) = read_history(store_path, [case]).cases[(case.indicator, case.host)].host_days

    assert host_day.campus_p50_services == 25.0  # of 10, 20, 30 and 40; 0 over all ten rows


def test_the_scored_population_is_the_triage_repos() -> None:
    # behavioural-support-v3. A triage checkout without it (one before primary-detectors-v9) fails
    # here rather than set the host beside a different population.
    assert CURRENT_SUPPORT_DEFINITION.describe() == f"unique_services >= {SCORED_MIN_SERVICES}"


def test_v1_days_are_read_from_the_candidate_tables(tmp_path: Path, store_path: Path) -> None:
    case = _case(tmp_path)
    service_id = bytes.fromhex(case.services[0].service_id_hex)
    with duckdb.connect(str(store_path)) as connection:
        publish(connection, MATCH_DAY)
        insert(
            connection,
            "feed.candidate_episode",
            {
                "day": MATCH_DAY,
                "client_ip": case.host,
                "family": "transfer",
                "service_id": service_id,
                "priority_tier": "P1",
                "daily_rank": 1,
                "priority_score": 90,
                "family_strength": 50.0,
            },
        )

    record_ = read_history(store_path, [case]).cases[(case.indicator, case.host)]

    assert [(episode.family, episode.tier) for episode in record_.same_service_episodes] == [
        ("transfer", "P1")
    ]
    assert record_.match_days_not_retained == (MATCH_DAY,)


def test_history_hashed_under_another_service_id_version_fails_closed(
    tmp_path: Path, store_path: Path
) -> None:
    with duckdb.connect(str(store_path)) as connection:
        publish(connection, MATCH_DAY, version="service-id-v2/category-id-v1")

    with pytest.raises(HistoryError, match="service-id version"):
        read_history(store_path, [_case(tmp_path)])


def test_reading_history_writes_nothing(tmp_path: Path, store_path: Path) -> None:
    before = hashlib.sha256(store_path.read_bytes()).hexdigest()

    read_history(store_path, [_case(tmp_path)])

    assert hashlib.sha256(store_path.read_bytes()).hexdigest() == before


def test_a_store_held_open_for_writing_is_refused_clearly(tmp_path: Path, store_path: Path) -> None:
    with duckdb.connect(str(store_path)), pytest.raises(HistoryError, match="read-only"):
        read_history(store_path, [_case(tmp_path)])


def test_a_missing_store_is_refused(tmp_path: Path) -> None:
    with pytest.raises(HistoryError, match="not found"):
        read_history(tmp_path / "absent.duckdb", [_case(tmp_path)])


def test_serving_marks_addresses_that_serve_many_outside_networks(store_path: Path) -> None:
    from ioc_report.history import (
        HIGH_PORT_GROUPS,
        SERVING_MIN_NETWORKS,
        SERVING_MIN_REMOTES,
        read_serving,
    )

    site = hashlib.sha256(b"site").digest()[:16]
    day = date(2026, 11, 9)
    with duckdb.connect(str(store_path)) as connection:
        # Serving: enough outside addresses over enough networks on high remote ports.
        for asn in range(SERVING_MIN_NETWORKS):
            row = _service_row(day, "192.0.2.10", site, asn=asn + 1)
            row |= {
                "transport_protocol": 6,
                "port_group": HIGH_PORT_GROUPS[asn % 2],
                "unique_servers": SERVING_MIN_REMOTES,
            }
            insert(connection, "history.client_service_day", row)
        # Many outside addresses but one network: not marked.
        row = _service_row(day, "192.0.2.20", site) | {
            "transport_protocol": 6,
            "port_group": HIGH_PORT_GROUPS[1],
            "unique_servers": SERVING_MIN_REMOTES * 5,
        }
        insert(connection, "history.client_service_day", row)
        # The same many networks on web ports: the address reached a site, it did not serve one.
        for asn in range(SERVING_MIN_NETWORKS):
            row = _service_row(day, "192.0.2.30", site, asn=asn + 1) | {
                "transport_protocol": 6,
                "port_group": 443,
                "unique_servers": SERVING_MIN_REMOTES,
            }
            insert(connection, "history.client_service_day", row)

    found = read_serving(store_path)

    assert set(found) == {"192.0.2.10"}
    marked = found["192.0.2.10"]
    assert (marked.first_day, marked.last_day) == (day, day)
    assert marked.peak_remotes == SERVING_MIN_REMOTES * SERVING_MIN_NETWORKS
