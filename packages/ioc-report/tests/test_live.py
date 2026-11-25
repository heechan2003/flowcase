from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from network_behaviour.source.sql import SqlKind, SqlLoader
from network_behaviour.time import UtcDay

from ioc_report.feed import Case, load_feed
from ioc_report.live import (
    MINUTE_HORIZON_DAYS,
    SQL_ROOT,
    LiveSession,
    plan_days,
)
from tests.conftest import minute_row, record, write_feed

NOW = datetime(2026, 10, 7, 9, 0, tzinfo=UTC)
LATEST = date(2026, 10, 6)


@dataclass
class _Result:
    column_names: Sequence[str]
    result_rows: Sequence[Sequence[Any]]
    query_id: str | None = "q"
    summary: Mapping[str, Any] = field(default_factory=lambda: {"read_rows": 10, "read_bytes": 20})

    @property
    def row_count(self) -> int:
        return len(self.result_rows)


class _FakeClient:
    """Records every query; answers the minute query for one pair and the long-flow query."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []
        self.fail = fail

    def query(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
        external_data: object = None,
    ) -> _Result:
        self.calls.append((query, dict(parameters or {})))
        if self.fail:
            raise ConnectionError("refused")
        start = parameters["start"] if parameters else None
        if "long_flows" in query:
            return _Result(
                (
                    "client_ip",
                    "server_ip",
                    "server_port",
                    "protocol",
                    "start_day",
                    "flows",
                    "longest_sec",
                    "held_open_flows",
                    "flow_up_bytes",
                    "flow_down_bytes",
                    "first_start_us",
                    "last_finish_us",
                ),
                [
                    (
                        "192.0.2.10",
                        "1.1.1.1",
                        443,
                        6,
                        LATEST,
                        2,
                        7200.0,
                        1,
                        10,
                        20,
                        1_789_000_000_000_000,
                        1_789_000_100_000_000,
                    )
                ],
            )
        if "{windows:" in query:
            return _Result(
                (
                    "client_ip",
                    "bucket",
                    "root_domain",
                    "flagged",
                    "active_minutes",
                    "addresses",
                    "sent_bytes",
                    "received_bytes",
                ),
                [("192.0.2.10", 5_970_936, "example.com", 0, 3, 2, 100, 200)],
            )
        if "registered_domains" in query:
            return _Result(
                (
                    "server_ip",
                    "campus_clients",
                    "registered_domains",
                    "ech_clients",
                    "udp_clients",
                    "asns",
                ),
                [("1.1.1.1", 40, 120, 5, 9, ["13335"])],
            )
        if start is not None and start.date() == LATEST:
            return _Result(
                (
                    "client_ip",
                    "server_ip",
                    "transport_protocol",
                    "server_port",
                    "sni",
                    "root_domain",
                    "dns",
                    "asn",
                    "active_minutes",
                    "minute_epochs",
                    "sent_bytes",
                    "received_bytes",
                    "flows",
                ),
                [
                    (
                        "192.0.2.10",
                        "1.1.1.1",
                        17,
                        443,
                        "www.example.com",
                        "example.com",
                        "",
                        "13335",
                        2,
                        [29_854_680, 29_854_681],
                        100,
                        200,
                        2,
                    )
                ],
            )
        return _Result((), [])

    def query_row_block_stream(self, *args: object, **kwargs: object) -> Any:
        raise NotImplementedError

    def close(self) -> None:
        pass


def _cases(tmp_path: Path, times: Sequence[str], hosts: Sequence[str]) -> tuple[Case, ...]:
    records = [record([minute_row(time, host=host)], host=host) for time in times for host in hosts]
    return load_feed(write_feed(tmp_path, records)).cases


def test_every_query_passes_the_triage_sql_guard() -> None:
    for name, version in (
        ("ioc_pair_minutes", 2),
        ("ioc_address_profile", 1),
        ("ioc_pair_long_flows", 2),
        ("ioc_host_context", 2),
        ("ioc_host_after", 1),
    ):
        query = SqlLoader(SQL_ROOT).load(name, version, timeout_seconds=60, kind=SqlKind.DATA)
        assert query.bounded and query.aggregate_only


def test_days_past_the_minute_horizon_are_expired_not_queried(tmp_path: Path) -> None:
    cases = _cases(tmp_path, ["2026-09-01 10:00:00", "2026-10-05 10:00:00"], ["192.0.2.10"])

    queried, expired = plan_days(cases, UtcDay(LATEST))

    assert queried == (date(2026, 10, 5), LATEST)
    assert expired == (date(2026, 9, 1),)
    assert MINUTE_HORIZON_DAYS < 15


def test_queries_are_batched_across_cases_never_per_host(tmp_path: Path) -> None:
    one = _FakeClient()
    many = _FakeClient()
    LiveSession(one).gather(_cases(tmp_path, ["2026-10-05 10:00:00"], ["192.0.2.10"]), NOW)
    LiveSession(many).gather(
        _cases(tmp_path, ["2026-10-05 10:00:00"], [f"192.0.2.{n}" for n in range(10, 20)]), NOW
    )

    # Two days (the match day and the latest day) x two minute-grain queries, one flow query.
    assert len(one.calls) == len(many.calls) == 5
    pairs = many.calls[0][1]["pairs"]
    assert len(pairs) == 10 and all(pair.endswith(" 1.1.1.1") for pair in pairs)


def test_results_are_parsed_and_the_footprint_recorded(tmp_path: Path) -> None:
    live = LiveSession(_FakeClient()).gather(
        _cases(tmp_path, ["2026-09-01 10:00:00"], ["192.0.2.10"]), NOW
    )

    assert live.status == "queried"
    assert live.days_queried == (LATEST,) and live.days_expired == (date(2026, 9, 1),)
    (seen,) = live.contacts[("192.0.2.10", "1.1.1.1")]
    assert (seen.day, seen.transport, seen.sni, seen.minute_epochs) == (
        LATEST,
        17,
        "www.example.com",
        (29_854_680, 29_854_681),
    )
    (address,) = live.addresses["1.1.1.1"]
    assert (address.registered_domains, address.asns) == (120, ("13335",))
    (flows,) = live.long_flows[("192.0.2.10", "1.1.1.1")]
    assert (flows.day, flows.port, flows.held_open_flows) == (LATEST, 443, 1)
    assert len(live.audits) == 3 and all(audit.status == "passed" for audit in live.audits)


def test_host_context_is_read_for_review_cases_inside_the_horizon_only(tmp_path: Path) -> None:
    client = _FakeClient()
    session = LiveSession(client)
    recent = _cases(tmp_path, ["2026-10-05 10:00:00"], ["192.0.2.10"])
    live = session.gather(recent, NOW)

    assert session.add_host_context(live, []) is live
    with_context = session.add_host_context(live, recent)

    windows = client.calls[-1][1]["windows"]
    assert len(windows) == 3 and all(key.startswith("192.0.2.10 ") for key in windows)
    assert with_context.host_context is not None
    assert with_context.host_context["192.0.2.10"][0].root_domain == "example.com"


def test_an_unreachable_source_is_labelled_not_raised(tmp_path: Path) -> None:
    live = LiveSession(_FakeClient(fail=True)).gather(
        _cases(tmp_path, ["2026-10-05 10:00:00"], ["192.0.2.10"]), NOW
    )

    assert live.status == "unavailable"
    assert live.error is not None and "SELECT" not in live.error


class _ReversedClient(_FakeClient):
    """Answers the minute query with two kinds of contact, the later one first."""

    def query(
        self,
        query: str,
        parameters: Mapping[str, Any] | None = None,
        settings: Mapping[str, Any] | None = None,
        external_data: object = None,
    ) -> _Result:
        result = super().query(query, parameters, settings, external_data)
        if "minute_epochs" not in result.column_names:
            return result
        (row,) = result.result_rows
        later = (*row[:3], 8443, *row[4:9], [29_854_700], *row[10:])
        return _Result(result.column_names, [later, row])


def test_contacts_are_in_minute_order_whatever_order_the_source_returns(tmp_path: Path) -> None:
    live = LiveSession(_ReversedClient()).gather(
        _cases(tmp_path, ["2026-09-01 10:00:00"], ["192.0.2.10"]), NOW
    )

    first, second = live.contacts[("192.0.2.10", "1.1.1.1")]
    assert (first.port, second.port) == (443, 8443)
    assert first.minute_epochs[0] < second.minute_epochs[0]
