"""The feed and the live re-query reporting the same traffic: shown and counted once, judged as
before.

Shaped on a real review case: one 2.6-minute download from a payload-delivery listing, which the
feed matched and the live source returned again, minute for minute and byte for byte.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from ioc_report.casefile import ledger_line, next_steps, render_case_file
from ioc_report.contact import Evidence
from ioc_report.history import Coverage, HistoryContext
from ioc_report.live import LiveContext, PairContact, PairFlows
from ioc_report.rules import REVIEW, decide
from tests.builders import SKIPPED, evidence, load
from tests.conftest import long_flow, minute_row, record

DAY = date(2026, 10, 15)
HOST = "192.0.2.10"
SERVER = "1.1.1.1"
LURE = "lure.example.com"
MINUTES = ("03:06", "03:07", "03:08", "03:09")
DOWN = 11_726_183
UP = 249_077
CONTEXT = HistoryContext(Path("retained.duckdb"), Coverage(frozenset(), frozenset()), {})


def _records() -> list[dict[str, Any]]:
    rows = [minute_row(f"2026-10-15 {m}:00", sni=LURE, root="example.com") for m in MINUTES]
    flow = long_flow(start="2026-10-15 03:06:55.302036", finish="2026-10-15 03:09:30.000000")
    flow.update(duration_sec=154.7, down_bytes=DOWN, up_bytes=UP)
    return [record(rows, indicator=LURE, threat_type="payload_delivery", flows=[flow])]


def _epoch(minute: str) -> int:
    hour, mins = (int(part) for part in minute.split(":"))
    return int(datetime(2026, 10, 15, hour, mins, tzinfo=UTC).timestamp()) // 60


def _live(minutes: tuple[str, ...] = MINUTES) -> LiveContext:
    contact = PairContact(
        day=DAY, server_ip=SERVER, transport=6, port=443, sni=LURE, root_domain="example.com",
        dns="", asn="13335", active_minutes=len(minutes),
        minute_epochs=tuple(_epoch(m) for m in minutes), up_bytes=4000, down_bytes=20000, flows=4,
    )  # fmt: skip
    flows = PairFlows(
        day=DAY, server_ip=SERVER, port=443, transport=6, flows=1, longest_sec=154.7,
        held_open_flows=0, up_bytes=UP, down_bytes=DOWN,
        first_start=datetime(2026, 10, 15, 3, 6, 55, tzinfo=UTC),
        last_finish=datetime(2026, 10, 15, 3, 9, 30, tzinfo=UTC),
    )  # fmt: skip
    return LiveContext(
        status="queried",
        days_queried=(DAY,),
        contacts={(HOST, SERVER): (contact,)},
        long_flows={(HOST, SERVER): (flows,)},
    )


def _evidence(tmp_path: Path, live: LiveContext) -> Evidence:
    feed, case = load(tmp_path, _records())
    return evidence(feed, case, live=live)


def test_the_same_traffic_from_feed_and_live_is_recognised(tmp_path: Path) -> None:
    found = _evidence(tmp_path, _live())

    assert [c.source for c in found.contacts] == ["feed", "live"]
    assert found.contact_duplicates == {0: 1}
    assert [f.source for f in found.flows] == ["feed", "live"]
    assert found.flow_duplicates == {0: 1}


def test_a_feed_minute_the_live_source_lacks_keeps_the_feed_contact(tmp_path: Path) -> None:
    found = _evidence(tmp_path, _live(MINUTES[1:]))

    assert found.contact_duplicates == {}


def test_k5_counts_one_download_and_k1_is_stated_once(tmp_path: Path) -> None:
    found = _evidence(tmp_path, _live())
    feed, case = load(tmp_path, _records())
    result = decide(found, feed.domain_indicators)

    assert result.disposition == REVIEW
    (k5,) = [f for f in result.kept_by if f.rule == "K5"]
    assert k5.text.startswith(f"1 transfer(s) of 1 MB or more with the flagged address ({DOWN:,}")
    assert [f.rule for f in result.kept_by].count("K1") == 1
    without_live = decide(evidence(feed, case, live=SKIPPED), feed.domain_indicators)
    assert without_live.disposition == result.disposition
    assert without_live.keeping_rules == result.keeping_rules


def test_the_case_file_shows_the_traffic_once(tmp_path: Path) -> None:
    live = _live()
    found = _evidence(tmp_path, live)
    feed, _case = load(tmp_path, _records())
    result = decide(found, feed.domain_indicators)

    text = render_case_file(found, result, live, CONTEXT)

    contacts = [line for line in text.splitlines() if "] contact 1.1.1.1 443/TCP" in line]
    assert len(contacts) == 1 and contacts[0].startswith("[Live source, also in the IOC feed]")
    flows = [line for line in text.splitlines() if "] long flow(s) 1.1.1.1 443/TCP" in line]
    assert len(flows) == 1 and flows[0].startswith("[Live source, also in the IOC feed]")
    assert "not re-queried" not in text
    assert len([line for line in text.splitlines() if "not explained: contact" in line]) == 1
    steps = next_steps(found, result)
    # One step covers every unexplained item, and it names the contact once.
    assert len([s for s in steps if "contact 1.1.1.1 443/TCP" in s]) == 1


def test_a_feed_contact_on_a_day_not_re_queried_says_so(tmp_path: Path) -> None:
    found = _evidence(tmp_path, SKIPPED)
    feed, _case = load(tmp_path, _records())
    result = decide(found, feed.domain_indicators)

    text = render_case_file(found, result, SKIPPED, CONTEXT)

    assert "[IOC feed, not re-queried] contact 1.1.1.1 443/TCP" in text


def test_a_feed_contact_the_re_query_did_not_hold_is_labelled_as_such(tmp_path: Path) -> None:
    live = _live(MINUTES[1:])
    found = _evidence(tmp_path, live)
    feed, _case = load(tmp_path, _records())

    text = render_case_file(found, decide(found, feed.domain_indicators), live, CONTEXT)

    assert "[IOC feed, not matched by the live re-query] contact 1.1.1.1 443/TCP" in text


def test_an_explained_ledger_counts_the_traffic_once(tmp_path: Path) -> None:
    rows = [minute_row("2026-10-15 03:06:00", up=0)]
    feed, case = load(tmp_path, [record(rows, indicator=f"{SERVER}:443", indicator_type="ip:port")])
    contact = PairContact(
        day=DAY, server_ip=SERVER, transport=6, port=443, sni="", root_domain="", dns="",
        asn="13335", active_minutes=1, minute_epochs=(_epoch("03:06"),), up_bytes=0,
        down_bytes=5000, flows=1,
    )  # fmt: skip
    live = LiveContext(status="queried", days_queried=(DAY,), contacts={(HOST, SERVER): (contact,)})
    found = evidence(feed, case, live=live)
    result = decide(found, frozenset())

    assert found.contact_duplicates == {0: 1}
    assert result.disposition != REVIEW
    assert ledger_line(found, result).startswith("E6 x1")
