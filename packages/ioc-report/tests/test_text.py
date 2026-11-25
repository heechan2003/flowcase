from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ioc_report.text import REPORT_TIMEZONE, local_time, report_zone, when

MOMENT = datetime(2026, 9, 15, 9, 45, tzinfo=UTC)


def test_times_are_utc_alone_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(REPORT_TIMEZONE, raising=False)
    assert when(MOMENT) == "2026-09-15 09:45 UTC"
    assert local_time(MOMENT) is None


@pytest.mark.parametrize("value", ["", "UTC", "Etc/UTC", "Not/AZone", "../etc"])
def test_utc_or_an_unknown_zone_shows_utc_alone(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv(REPORT_TIMEZONE, value)
    assert report_zone() is None and when(MOMENT) == "2026-09-15 09:45 UTC"


def test_a_report_zone_is_shown_beside_utc_with_its_city_as_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(REPORT_TIMEZONE, "America/New_York")
    assert when(MOMENT) == "2026-09-15 09:45 UTC (2026-09-15 05:45 New York)"
    assert local_time(MOMENT) == ("2026-09-15 05:45", "New York")
