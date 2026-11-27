"""Feeds from other lists: read through a table entry, attributed to the list that names the
indicator, and with ThreatFox's text and evaluated inputs exactly as they were."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from ioc_report import cli
from ioc_report.case_report import brief, code_text, load_report, page_data
from ioc_report.casefile import next_steps, render_case_file
from ioc_report.cli import main
from ioc_report.digest import case_digest
from ioc_report.feed import Feed, load_feed, load_feeds
from ioc_report.history import Coverage, HistoryContext
from ioc_report.knowledge import (
    FAMILIES,
    LISTINGS,
    REPORT_FAMILIES,
    THREATFOX,
    family_profile,
    listing_for,
)
from ioc_report.live import LiveContext, LiveSession, is_address_fragment, reads_after_view
from ioc_report.model import OllamaClient
from ioc_report.narrative import (
    CASE_PROMPT,
    FEED_PROMPT,
    GROUP_PROMPT,
    PROMPT_VERSION,
    REPORT_PROMPT,
    case_prompt,
    feed_prompt,
    group_prompt,
    report_prompt,
)
from ioc_report.report import write_report
from ioc_report.rules import EXPLAINED, REVIEW, SHARED_MIN_DOMAINS, decide
from ioc_report.shadow import SHADOW_PROMPT
from ioc_report.summary import CaseResult
from tests.builders import SKIPPED, established, evidence, history
from tests.conftest import minute_row, record, write_feed
from tests.test_narrative import DIGEST, GOOD, NOTHING, _reply, _writer
from tests.test_report import _fake_writer

AMAZON = listing_for("amazon-php2shell")
ADDRESS = "1.1.1.1"
GENERATED = datetime(2026, 11, 6, tzinfo=UTC)
NO_HISTORY = HistoryContext(Path("x"), Coverage(frozenset(), frozenset()), {})
# The prompts as evaluated and cached on 2026-11-06. Their ThreatFox text must not move.
# REPORT_PROMPT gives no verdict, so a deliberate change to it moves its pin with no new evaluation.
# Re-pinned once on purpose: each prompt said which university's network it served, and now says
# "a university campus network". No other character moved. SHADOW_PROMPT is re-run on evals/ before
# its scorecard is quoted again.
PINNED = {
    "case": "c4cfacbf5bc64cf2686301d10b3b585693203820c2c6982e21fc76bac7222fce",
    "group": "24ecfc37564ea86d4fe876da19fd42d157370894537919f8e82a1a7acd2fb45b",
    "feed": "99c0f39b0b28746d1cd57715dc7c2b2d46f491f7bc92690aee245a3444fb7b03",
    "report": "9e290edbd3b5c38481f6a9da9a0885eaa80965814070e05c0b815802a57d028a",
    "shadow": "9e30f7592419c05e09305771e1a670dc64a890c9b0d252a0944fd9402481c9b7",
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _amazon(port: int = 50001, **row: Any) -> dict[str, Any]:
    """A match as the PHP2Shell export writes it: no threatfox block, its own indicator key."""
    item = record(
        [
            minute_row(
                f"2026-10-21 11:{port % 60:02d}:00",
                server=ADDRESS,
                port=port,
                sni="web.campus.example",
                root="campus.example",
                **row,
            )
        ],
        indicator=f"{ADDRESS}:{port}",
        indicator_type="ip:port",
    )
    item.pop("threatfox")
    item["aws_indicator"] = item.pop("indicator")
    return item


def _feed(tmp_path: Path, *items: dict[str, Any]) -> Feed:
    return load_feed(write_feed(tmp_path, list(items)), AMAZON)


# --- the table ------------------------------------------------------------------------------------


def test_every_list_cites_a_source_and_threatfox_is_the_default() -> None:
    for key, entry in LISTINGS.items():
        assert entry.key == key
        assert entry.sources and all(url.startswith("https://") for url in entry.sources)
    assert listing_for(" ThreatFox ") is THREATFOX
    assert load_feeds.__defaults__ == (THREATFOX,)
    with pytest.raises(ValueError, match="known ones are amazon-php2shell, threatfox"):
        listing_for("nope")


def test_a_family_from_another_list_decides_nothing() -> None:
    assert "php2shell" in REPORT_FAMILIES and "php2shell" not in FAMILIES
    assert family_profile(AMAZON.family) is None


# --- reading records ------------------------------------------------------------------------------


def test_two_ports_on_one_listed_address_are_one_case(tmp_path: Path) -> None:
    feed = _feed(tmp_path, _amazon(50001), _amazon(50002))

    (case,) = feed.cases

    assert (case.indicator, case.indicator_type) == (ADDRESS, "ip")
    assert len(case.rows) == 2 and not feed.rejected
    assert case.listing.source == "Amazon Threat Intelligence"
    assert (case.listing.malware, case.listing.threat_type) == ("php2shell", "exploit_source")
    assert case.listing.inbound and case.listing.confidence is None
    assert feed.listing is AMAZON


def test_a_list_that_keeps_its_ports_keeps_them(tmp_path: Path) -> None:
    item = record(
        [minute_row("2026-10-21 11:00:00", server=ADDRESS)],
        indicator=f"{ADDRESS}:443",
        indicator_type="ip:port",
    )
    (case,) = load_feed(write_feed(tmp_path, [item])).cases

    assert (case.indicator, case.indicator_type) == (f"{ADDRESS}:443", "ip:port")
    assert case.listing.source == "ThreatFox" and not case.listing.inbound


def test_records_read_as_the_wrong_list_are_rejected_not_guessed(tmp_path: Path) -> None:
    path = write_feed(tmp_path, [_amazon()])

    feed = load_feed(path)
    assert not feed.cases and "missing or invalid threatfox" in feed.rejected[0].reason

    threatfox = load_feed(
        write_feed(tmp_path, [record([minute_row("2026-10-21 11:00:00")])]), AMAZON
    )
    assert not threatfox.cases and "aws_indicator" in threatfox.rejected[0].reason


def test_the_command_names_the_flag_when_a_feed_needs_one(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(store_path))
    path = str(write_feed(tmp_path, [_amazon()]))

    assert main([path, "--no-live", "--no-model"]) == 2
    assert "name it with --listing (known: amazon-php2shell)" in capsys.readouterr().err

    with pytest.raises(SystemExit) as stopped:
        main([path, "--no-live", "--no-model", "--listing", "nope"])
    assert stopped.value.code == 2
    assert "unknown listing" in capsys.readouterr().err


# --- the rules ------------------------------------------------------------------------------------


def test_an_established_site_cannot_explain_an_address_that_connects_in(tmp_path: Path) -> None:
    name = "www.portal.example.org"
    rows = [minute_row("2026-10-21 10:00:00", server=ADDRESS, sni=name, root="example.org")]
    neighbours = [
        minute_row(
            "2026-10-21 07:00:00",
            host="192.0.2.200",
            server=ADDRESS,
            sni=f"www.site{n}.com",
            root=f"site{n}.com",
        )
        for n in range(SHARED_MIN_DOMAINS)
    ]
    shape: dict[str, Any] = {"indicator": f"{ADDRESS}:443", "indicator_type": "ip:port"}
    records = [record(neighbours, host="192.0.2.200", **shape), record(rows, **shape)]
    retained = history([established(name, server=ADDRESS)])

    threatfox = load_feed(write_feed(tmp_path, records))
    case = next(c for c in threatfox.cases if c.host == "192.0.2.10")
    found = decide(evidence(threatfox, case, retained=retained), threatfox.domain_indicators)
    assert found.disposition == EXPLAINED and "E4" in found.explaining_rules

    for item in records:
        item.pop("threatfox")
        item["aws_indicator"] = item.pop("indicator")
    other = load_feed(write_feed(tmp_path, records), AMAZON)
    case = next(c for c in other.cases if c.host == "192.0.2.10")
    found = decide(evidence(other, case, retained=retained), other.domain_indicators)
    assert found.disposition == REVIEW and "E4" not in found.explaining_rules
    assert "this host's own site" in found.contacts[0].gap


def test_traffic_the_host_never_answered_is_still_explained(tmp_path: Path) -> None:
    feed = _feed(tmp_path, _amazon(up=0))
    (case,) = feed.cases

    found = decide(evidence(feed, case), feed.domain_indicators)

    assert found.disposition == EXPLAINED and found.explaining_rules == ("E6",)


def test_only_a_payload_listing_is_said_to_name_a_download_server(tmp_path: Path) -> None:
    feed = _feed(tmp_path, _amazon())
    (case,) = feed.cases

    found = decide(evidence(feed, case), feed.domain_indicators)

    assert "download server" not in found.contacts[0].gap
    assert "names no malware channel" in found.contacts[0].gap


# --- the words ------------------------------------------------------------------------------------


def _result(feed: Feed) -> CaseResult:
    (case,) = feed.cases
    found = evidence(feed, case)
    decided = decide(found, feed.domain_indicators)
    return CaseResult(
        found,
        decided,
        render_case_file(found, decided, SKIPPED, NO_HISTORY),
        next_steps=next_steps(found, decided),
        digest=case_digest(found, decided, SKIPPED, NO_HISTORY),
    )


def test_nothing_credits_threatfox_with_another_lists_indicator(tmp_path: Path) -> None:
    feed = _feed(tmp_path, _amazon(50001), _amazon(50002))
    result = _result(feed)
    assert result.digest is not None
    markdown, data = write_report(
        tmp_path / "run", "synthetic", feed, [result], SKIPPED, NO_HISTORY, "test", GENERATED
    )
    report = load_report(data)
    (saved,) = report["cases"]

    written = {
        "digest": result.digest.text(),
        "case file": result.case_file or "",
        "brief": brief(saved).text(),
        "code's text": " ".join(code_text(brief(saved)).values()),
        "page": json.dumps(page_data(report, saved, code_text(brief(saved)))),
        "markdown": markdown.read_text(encoding="utf-8"),
    }
    for name, text in written.items():
        assert "threatfox" not in text.lower(), name
    assert "Amazon Threat Intelligence, about the indicator only" in written["digest"]
    assert "php2shell: Two critical flaws in PHP" in written["digest"]
    assert page_data(report, saved, {})["facts"].startswith(
        f"Amazon Threat Intelligence lists {ADDRESS} as php2shell (exploit source)."
    )
    assert any("PHP_SESSION_UPLOAD_PROGRESS" in step for step in saved["next_steps"])
    assert any("what the remote side asked for" in step for step in saved["next_steps"])


def test_an_inbound_list_says_which_way_to_read_the_contact(tmp_path: Path) -> None:
    high = _result(_feed(tmp_path, _amazon(50001))).digest
    assert high is not None
    assert "fits the remote side opening it; if so" in high.text()

    low = _result(_feed(tmp_path, _amazon(443))).digest
    assert low is not None
    assert "connect in to their targets" in low.text()
    assert "fits the remote side opening it" not in low.text()

    feed = load_feed(
        write_feed(tmp_path, [record([minute_row("2026-10-21 11:00:00", port=50001)])])
    )
    other = _result(feed).digest
    assert other is not None and "connect in" not in other.text()


def test_threatfox_prompts_have_not_moved_by_a_character() -> None:
    assert _sha(CASE_PROMPT) == PINNED["case"]
    assert _sha(GROUP_PROMPT) == PINNED["group"]
    assert _sha(FEED_PROMPT) == PINNED["feed"]
    assert _sha(REPORT_PROMPT) == PINNED["report"]
    assert _sha(SHADOW_PROMPT) == PINNED["shadow"]
    assert PROMPT_VERSION == "af17d3c277a2"


def test_prompts_for_another_list_name_that_list() -> None:
    source = AMAZON.source
    for prompt in (
        case_prompt(source),
        group_prompt(source),
        feed_prompt(source),
        report_prompt(source, inbound=True),
    ):
        assert "ThreatFox" not in prompt and source in prompt
    inbound = report_prompt(source, inbound=True)
    assert "which host it was in contact with" in inbound
    assert "18. This list names addresses" in inbound
    assert "Never state as fact" in inbound
    assert "which host it was in contact with" not in report_prompt(source)


def test_a_reply_crediting_threatfox_on_another_lists_case_goes_back() -> None:
    clean = {**GOOD, "threat": "Amazon lists 9.9.9.9:443 as win.nanocore, a remote-access trojan."}
    writer, transport = _writer(_reply(GOOD), _reply(clean))

    found = writer.case(DIGEST, NOTHING, EXPLAINED, "x", source=AMAZON.source)

    assert found.by_model and found.attempts == 2
    assert "names ThreatFox" in transport.requests[1]["messages"][-1]["content"]


def test_a_threatfox_reply_may_name_threatfox() -> None:
    writer, _transport = _writer(_reply(GOOD))
    assert writer.case(DIGEST, NOTHING, EXPLAINED, "x").attempts == 1


# --- the days after a contact ---------------------------------------------------------------------


def test_another_list_needs_only_a_later_match_day_inside_the_horizon(tmp_path: Path) -> None:
    def day(text: str) -> dict[str, Any]:
        item = _amazon(50001)
        item["evidence"]["activity"][0]["time"] = f"{text} 11:00:00"
        return item

    (case,) = _feed(tmp_path, day("2026-10-21"), day("2026-10-23")).cases

    assert reads_after_view(case, date(2026, 10, 22))
    assert not reads_after_view(case, date(2026, 10, 24))


def test_threatfox_still_needs_its_first_match_day_inside_the_horizon(tmp_path: Path) -> None:
    rows = [minute_row("2026-10-21 11:00:00"), minute_row("2026-10-23 11:00:00")]
    (case,) = load_feed(write_feed(tmp_path, [record(rows)])).cases

    assert not reads_after_view(case, date(2026, 10, 22))
    assert reads_after_view(case, date(2026, 10, 21))


def test_an_address_written_as_a_name_is_not_a_name() -> None:
    assert is_address_fragment("2.10") and is_address_fragment("10:80")
    assert not is_address_fragment("example.com") and not is_address_fragment("")


def _destination_run(tmp_path: Path, source_feed: Feed) -> LiveContext:
    """The source answers with one real name and one address fragment, on any list."""

    class Outcome:
        def dictionaries(self) -> list[dict[str, Any]]:
            base = {
                "client_ip": "192.0.2.10",
                "network": "",
                "first_minute": datetime(2026, 10, 27, tzinfo=UTC),
                "active_minutes": 3,
                "sent_bytes": 1000,
                "received_bytes": 2_500_000,
            }
            return [{**base, "root_domain": "real.example"}, {**base, "root_domain": "2.10"}]

    class Runner:
        def run(self, query: Any, **kwargs: Any) -> Outcome:
            return Outcome()

    session = LiveSession(None)
    session._runner = Runner()  # type: ignore[assignment]
    session._load = lambda name, version: None  # type: ignore[assignment,method-assign,return-value]
    live = LiveContext(status="queried", latest_day=date(2026, 11, 3))
    return session.add_destinations(live, list(source_feed.cases))


def test_a_fragment_of_the_address_never_reaches_a_case_from_another_list(tmp_path: Path) -> None:
    feed = _feed(tmp_path, _amazon())

    live = _destination_run(tmp_path, feed)

    assert live.destinations is not None
    names = {row.root_domain for row in live.destinations["192.0.2.10"]}
    assert "real.example" in names and "2.10" not in names


def test_threatfox_rows_are_left_as_the_evaluated_case_files_saw_them(tmp_path: Path) -> None:
    rows = [minute_row("2026-10-23 11:00:00")]
    feed = load_feed(write_feed(tmp_path, [record(rows)]))

    live = _destination_run(tmp_path, feed)

    assert live.destinations is not None
    assert "2.10" in {row.root_domain for row in live.destinations["192.0.2.10"]}


def test_large_later_downloads_are_listed_and_not_linked_to_the_address(tmp_path: Path) -> None:
    feed = _feed(tmp_path, _amazon())
    (case,) = feed.cases
    live = _destination_run(tmp_path, feed)
    found = evidence(feed, case, live=live)

    text = case_digest(found, decide(found, feed.domain_indicators), live, NO_HISTORY).text()

    # The fake source answers on each of the 14 days read.
    assert "1 destination(s) new to this host sent it 1 MB or more, 35.0 MB in all" in text
    assert "real.example sent it 35.0 MB" in text
    assert "cannot link this to the listed address" in text


# --- the run --------------------------------------------------------------------------------------


def test_a_run_on_another_list_asks_for_no_second_opinion_and_says_so(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(store_path))
    calls: list[str] = []
    transport = _fake_writer(calls)
    monkeypatch.setattr(cli, "OllamaClient", lambda config: OllamaClient(config, transport))
    path = str(write_feed(tmp_path, [_amazon(50001), _amazon(50002)]))
    out = tmp_path / "run"

    code = main(
        [
            path,
            "--no-live",
            "--shadow",
            "3",
            "--listing",
            AMAZON.key,
            "--out",
            str(out),
            "--name",
            "x",
        ]
    )

    assert code == 0
    assert "no second opinion on this list" in capsys.readouterr().err
    # The model check, then one overview, one group and the summary: no verdict request.
    assert [url.rsplit("/", 1)[-1] for url in calls] == ["tags", "chat", "chat", "chat"]
    data = json.loads((out / "x.json").read_text(encoding="utf-8"))
    assert data["listing"] == AMAZON.key and data["cases"][0]["shadow"] is None
    assert data["cases"][0]["listing"]["source"] == AMAZON.source
