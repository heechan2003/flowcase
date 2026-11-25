"""ThreatFox's dates are not in the feed: its threatfox.first_seen/last_seen are the matched flow's
start and finish (IOC_Processor `agent/evidence.py`). The report says so unless the hand-filled
metadata file gives the real ones."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ioc_report.feed import FeedError, load_feed, load_listing_dates, with_listing_dates
from ioc_report.summary import listing_line
from tests.conftest import minute_row, record, write_feed


def _case(tmp_path: Path):  # type: ignore[no-untyped-def]
    first = record([minute_row("2026-10-15 03:06:00")], indicator="Lure.Example.com")
    first["threatfox"].update(
        first_seen_utc="2026-10-15T03:06:55Z", last_seen_utc="2026-10-15T03:09:00Z"
    )
    (case,) = load_feed(write_feed(tmp_path, [first])).cases
    return case


def test_the_feed_dates_are_named_as_the_match_window(tmp_path: Path) -> None:
    case = _case(tmp_path)

    line = listing_line(case)

    assert case.matched_first == datetime(2026, 10, 15, 3, 6, 55, tzinfo=UTC)
    assert line.startswith("ThreatFox's listing dates are not in the feed")
    assert "matched flow's start and finish (2026-10-15 03:06 to 2026-10-15 03:09 UTC)" in line
    assert "ThreatFox first saw" not in line


def test_hand_filled_dates_are_shown_as_threatfox_dates(tmp_path: Path) -> None:
    case = _case(tmp_path)
    path = tmp_path / "ioc_metadata.json"
    path.write_text(
        json.dumps(
            {
                "lure.example.com": {
                    "threatfox_first_seen": "2026-10-01 08:00:00",
                    "threatfox_last_seen": "2026-10-20T00:00:00Z",
                    "reporter": "someone",
                }
            }
        ),
        encoding="utf-8",
    )

    (dated,) = with_listing_dates([case], load_listing_dates(path))

    assert dated.threatfox_first_seen == datetime(2026, 10, 1, 8, tzinfo=UTC)
    assert listing_line(dated).startswith(
        "ThreatFox first saw the indicator 2026-10-01 08:00 UTC, 14 day(s) before"
    )
    assert listing_line(dated).endswith("(from data/ioc_metadata.json).")


def test_a_missing_file_means_no_dates_and_a_broken_one_stops_the_run(tmp_path: Path) -> None:
    assert load_listing_dates(tmp_path / "absent.json") == {}
    broken = tmp_path / "broken.json"
    broken.write_text("[1, 2", encoding="utf-8")
    with pytest.raises(FeedError):
        load_listing_dates(broken)
