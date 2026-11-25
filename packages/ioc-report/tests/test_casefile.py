"""Caveats on an explained verdict, and the lookup sheet a review case gets."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from ioc_report.casefile import caveats, next_steps
from ioc_report.history import CaseHistory
from ioc_report.live import LiveContext
from ioc_report.registration import NameAge
from ioc_report.rules import EXPLAINED, REVIEW, decide
from tests.builders import FIRST_MATCH, evidence, load
from tests.conftest import minute_row, record

IP: dict[str, Any] = {"indicator": "1.1.1.1:443", "indicator_type": "ip:port"}
QUERIED = LiveContext(status="queried", days_queried=(FIRST_MATCH,))


def _tls_case(tmp_path: Path) -> tuple[Any, Any]:
    return load(
        tmp_path, [record([minute_row("2026-09-15 10:00:00", sni="api.rare-name.xyz")], **IP)]
    )


def test_a_fully_checked_explanation_has_no_caveat(tmp_path: Path) -> None:
    feed, case = _tls_case(tmp_path)
    ages = {"rare-name.xyz": NameAge("rare-name.xyz", datetime(2014, 3, 2, tzinfo=UTC), "ok")}
    found = evidence(feed, case, live=QUERIED, registrations=ages)
    decided = decide(found, feed.domain_indicators)

    assert decided.disposition == EXPLAINED
    assert caveats(found, decided) == ()


def test_each_check_that_could_not_run_is_a_caveat(tmp_path: Path) -> None:
    feed, case = _tls_case(tmp_path)
    gaps = CaseHistory((), (FIRST_MATCH,), (FIRST_MATCH,), (), ())
    found = evidence(feed, case, retained=gaps)
    decided = decide(found, feed.domain_indicators)

    found_caveats = caveats(found, decided)

    assert [c.code for c in found_caveats] == ["live", "stream", "retained", "e3-name"]
    assert "--no-live" in found_caveats[0].text
    assert "not looked up (NAME_LOOKUP=rdap)" in found_caveats[3].text


def test_a_day_the_source_no_longer_held_is_a_live_caveat(tmp_path: Path) -> None:
    feed, case = _tls_case(tmp_path)
    later = LiveContext(status="queried", days_queried=(date(2026, 9, 30),))
    ages = {"rare-name.xyz": NameAge("rare-name.xyz", None, "no-service")}
    found = evidence(feed, case, live=later, registrations=ages)

    codes = {c.code: c.text for c in caveats(found, decide(found, feed.domain_indicators))}

    assert "2026-09-15 had expired" in codes["live"]
    assert "its registry lists no RDAP service" in codes["e3-name"]


def test_the_lookup_sheet_names_the_systems_and_the_campus_clock(tmp_path: Path) -> None:
    rows = [minute_row("2026-09-15 10:00:00", sni="promo.lure.example")]
    feed, case = load(
        tmp_path,
        [
            record(
                rows,
                indicator="promo.lure.example",
                threat_type="payload_delivery",
                malware="js.clearfake",
            )
        ],
    )
    found = evidence(feed, case)
    decided = decide(found, feed.domain_indicators)

    steps = next_steps(found, decided)

    assert decided.disposition == REVIEW
    assert steps[0].startswith("Identify the device: the address lease")
    # The window opens 15 minutes before; times are UTC alone unless REPORT_TIMEZONE is set.
    assert "from 2026-09-15 09:45 UTC to 2026-09-15 11:00 UTC" in steps[0]
    assert any(step.startswith("Web gateway or proxy logs") for step in steps)
    assert any(step.startswith("Resolver logs") for step in steps)
    assert any(step.startswith("Mail gateway") for step in steps)
