"""The digest: a case in grouped, sourced lines, with contacts grouped by why no rule explained
them, and code's own overview when no model writes one."""

from __future__ import annotations

from pathlib import Path

from ioc_report.digest import case_digest, group_label
from ioc_report.history import Coverage, HistoryContext
from ioc_report.rules import decide
from ioc_report.summary import CaseResult, case_text
from tests.builders import SKIPPED, evidence, load
from tests.conftest import minute_row, record
from tests.test_facts import VERDICT_WORDS


def _lure(tmp_path: Path, ad_names: int) -> tuple[CaseResult, str]:
    """A payload-delivery lure: two visits to its own names, then many ad-network names on the
    same address, none of them established on campus."""
    rows = [
        minute_row("2026-09-15 10:00:00", sni="lure.example.com"),
        minute_row("2026-09-15 10:01:00", sni="cdn.lure.example.com"),
        *(
            minute_row(f"2026-09-15 10:{2 + index:02d}:00", sni=f"x.ads{index}.example.net")
            for index in range(ad_names)
        ),
    ]
    feed, case = load(
        tmp_path,
        [
            record(
                rows,
                indicator="lure.example.com",
                threat_type="payload_delivery",
                malware="js.iclickfix",
            )
        ],
    )
    found = evidence(feed, case)
    decision = decide(found, feed.domain_indicators)
    retained = HistoryContext(tmp_path / "none.duckdb", Coverage(frozenset(), frozenset()), {})
    digest = case_digest(found, decision, SKIPPED, retained)
    return CaseResult(found, decision, digest=digest), digest.text()


def test_a_hundred_contacts_read_as_their_reasons(tmp_path: Path) -> None:
    result, text = _lure(tmp_path, ad_names=40)

    unexplained = [line for line in text.splitlines() if "Not explained:" in line]
    assert len(result.decision.unexplained) == 42
    assert len(unexplained) == 2
    assert any("40 contact(s)" in line and "and 34 more" in line for line in unexplained)
    assert any(
        "2 contact(s)" in line and "under the flagged domain" in line for line in unexplained
    )
    k1 = [line for line in text.splitlines() if "K1:" in line]
    assert len(k1) == 1 and "2 kind(s) of contact" in k1[0]


def test_every_section_is_there_and_names_its_source(tmp_path: Path) -> None:
    _result, text = _lure(tmp_path, ad_names=1)

    for heading in ("Threat:", "Host:", "What happened:", "Decision:", "Model verdict:"):
        assert heading in text
    lines = [line for line in text.splitlines() if line.startswith("- ")]
    assert lines and all(line.startswith("- [") for line in lines)
    assert "ClickFix-style lure" in text and "confidence" not in text
    assert "no blind verdict was asked for" in text


def test_code_writes_a_plain_overview_without_rule_codes_or_verdicts(tmp_path: Path) -> None:
    result, _text = _lure(tmp_path, ad_names=3)

    reading = case_text(result, "reading")
    assert reading.startswith("Code kept it for review: the host named the flagged domain")
    assert "K1" not in reading
    for part in ("threat", "host", "what_happened", "reading"):
        text = case_text(result, part).lower()
        assert text and not [word for word in VERDICT_WORDS if word in text]


def test_a_group_label_says_what_decided_it() -> None:
    label = group_label(("NanoCore RAT", "botnet_cc", "explained", ("E1", "E2")))
    assert label == "NanoCore RAT (botnet_cc): explained by UDP contact, ECH browser traffic"


def test_an_address_with_no_retained_day_still_has_a_host_line(tmp_path: Path) -> None:
    result, _text = _lure(tmp_path, ad_names=0)
    assert result.digest is not None
    assert [line.text for line in result.digest.host] == ["nothing about this address is retained."]
