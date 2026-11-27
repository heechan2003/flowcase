"""The case reports: a PDF per case for a reader who knows nothing of how the team works. Read from
a run's saved JSON, written by the external model from a brief with the method taken out, checked,
and off unless asked for. Every model here is fake and nothing leaves the machine."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from importlib.resources import files
from itertools import cycle, islice
from pathlib import Path
from typing import Any

import pytest
import typst
from network_behaviour.normalization.bitmap import ActivityBitmap

from ioc_report import cli
from ioc_report.case_report import (
    LIMITS,
    CaseReportError,
    _plain,
    brief,
    code_text,
    file_stem,
    load_report,
    page_data,
    render_pdf,
    select_cases,
    write_case_reports,
)
from ioc_report.casefile import (
    after_contact,
    next_steps,
    observed_from_case_file,
    observed_shapes,
    render_case_file,
)
from ioc_report.cli import case_main, main
from ioc_report.contact import Evidence
from ioc_report.digest import case_digest
from ioc_report.feed import Feed
from ioc_report.history import (
    CaseHistory,
    Coverage,
    Episode,
    HistoryContext,
    HostServiceDay,
    address_services,
)
from ioc_report.live import LiveContext
from ioc_report.model import OllamaClient
from ioc_report.narrative import (
    INBOUND_WORDS,
    REPORT_FIELDS,
    REPORT_WORDS,
    inbound_problems,
    method_words,
    missing_facts,
    report_problems,
    unweighed_count,
)
from ioc_report.openrouter import OpenRouterClient
from ioc_report.report import write_report
from ioc_report.rules import EXPLAINED, REVIEW, decide
from ioc_report.summary import CaseResult
from tests.builders import FIRST_MATCH, SKIPPED, established, evidence, history, load
from tests.conftest import long_flow, minute_row, record
from tests.test_facts import shaped
from tests.test_openrouter import CONFIG, _listing, _Post, _reply
from tests.test_report import FEED, _fake_writer

GENERATED = datetime(2026, 11, 5, 17, 0, tzinfo=UTC)
HOST = "192.0.2.10"
IP: dict[str, Any] = {"indicator": "1.1.1.1:443", "indicator_type": "ip:port"}
DAY = "2026-09-15"
GOOD = {
    "summary": "A campus host, HOST, reached a domain ThreatFox lists. We kept it for review.",
    "threat": "ThreatFox lists the domain, and that listing is all we hold.",
    "host": "HOST used a handful of services across the days we hold.",
    "contact": "The contact was one short session with the listed domain.",
    "why": "The case stays open because the host's traffic named the listed domain.",
    "after": "A new destination followed the contact.",
    "conclusion": "We can say the contact happened. The next steps are to identify the device; "
    "and to check its endpoint record.",
}


PROSE = (
    "We kept this case for review because nothing we hold explains the contact with the listed "
    "address on port 443. The host received 11.3 KB and sent 1.5 KB in one minute, and no other "
    "campus host had used that name in the days before it."
)
NO_HISTORY = HistoryContext(Path("x"), Coverage(frozenset(), frozenset()), {})


@dataclass(frozen=True)
class Run:
    """What a case's run holds, before it is saved."""

    feed: Feed
    evidence: Evidence
    live: LiveContext = SKIPPED
    history: HistoryContext = NO_HISTORY


def _saved(tmp_path: Path, run: Run) -> dict[str, Any]:
    """The report a run of this one case writes, read back as the tool reads it."""
    found = run.evidence
    decided = decide(found, run.feed.domain_indicators)
    result = CaseResult(
        found,
        decided,
        render_case_file(found, decided, run.live, run.history),
        next_steps=(
            next_steps(found, decided, after_contact(found, run.live, run.history))
            if decided.disposition == REVIEW
            else ()
        ),
        digest=case_digest(found, decided, run.live, run.history),
    )
    _markdown, data = write_report(
        tmp_path / "run",
        "synthetic",
        run.feed,
        [result],
        run.live,
        run.history,
        "test",
        GENERATED,
    )
    return load_report(data)


# --- every shape a decision can take --------------------------------------------------------------


def _lure(tmp_path: Path) -> Run:
    case = shaped(tmp_path)
    return Run(case.feed, case.evidence, case.live, case.history)


def _tunnel_visitor(tmp_path: Path) -> Run:
    rows = [minute_row(f"{DAY} 10:00:00", port=41234, dns="bore.pub", root="bore.pub")]
    feed, case = load(tmp_path, [record(rows, indicator="bore.pub")])
    return Run(feed, evidence(feed, case))


def _flagged_by_monitoring(tmp_path: Path) -> Run:
    feed, case = load(tmp_path, [record([minute_row(f"{DAY} 10:00:00", transport=17)], **IP)])
    (address,) = address_services(case)
    episode = Episode(date(2026, 9, 15), "relationship", "E2", address.service_id_hex, None)
    return Run(feed, evidence(feed, case, retained=history(episodes=[episode])))


def _scheduled(tmp_path: Path) -> Run:
    rows = [
        minute_row(f"{DAY} {8 + n // 2:02d}:{30 * (n % 2):02d}:00", sni="api.rare-name.xyz")
        for n in range(21)
    ]
    feed, case = load(tmp_path, [record(rows, **IP)])
    return Run(feed, evidence(feed, case))


def _beacon_bitmap(tmp_path: Path) -> Run:
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
    return Run(feed, evidence(feed, case, retained=retained))


def _payload_download(tmp_path: Path) -> Run:
    rows = [minute_row(f"{DAY} 10:00:00", sni="files.rare-name.xyz", down=3_000_000)]
    flows = [
        long_flow(start=f"{DAY} 10:00:00.000000", finish=f"{DAY} 10:00:40.000000", duration=40.0)
    ]
    feed, case = load(tmp_path, [record(rows, flows=flows, threat_type="payload_delivery", **IP)])
    return Run(feed, evidence(feed, case))


def _no_profile(tmp_path: Path) -> Run:
    rows = [minute_row(f"{DAY} 10:00:00", sni="api.rare-name.xyz")]
    feed, case = load(tmp_path, [record(rows, malware="win.asyncrat", **IP)])
    return Run(feed, evidence(feed, case))


def _records_disagree(tmp_path: Path) -> Run:
    rows = [minute_row(f"{DAY} 10:00:00", transport=17)]
    feed, case = load(tmp_path, [record(rows, **IP), record(rows, malware="win.asyncrat", **IP)])
    return Run(feed, evidence(feed, case))


def _explained_with_every_gap(tmp_path: Path) -> Run:
    feed, case = load(
        tmp_path, [record([minute_row(f"{DAY} 10:00:00", sni="api.rare-name.xyz")], **IP)]
    )
    gaps = CaseHistory((), (FIRST_MATCH,), (FIRST_MATCH,), (), ())
    return Run(feed, evidence(feed, case, retained=gaps))


def _explained_on_an_expired_day(tmp_path: Path) -> Run:
    feed, case = load(
        tmp_path, [record([minute_row(f"{DAY} 10:00:00", sni="api.rare-name.xyz")], **IP)]
    )
    later = LiveContext(status="queried", days_queried=(date(2026, 9, 30),))
    return Run(feed, evidence(feed, case, live=later), later)


def _inbound_only(tmp_path: Path) -> Run:
    feed, case = load(tmp_path, [record([minute_row(f"{DAY} 10:00:00", port=23, up=0)], **IP)])
    return Run(feed, evidence(feed, case))


SHAPES: dict[str, tuple[Callable[[Path], Run], str]] = {
    "named the flagged domain": (_lure, REVIEW),
    "tunnel visitor": (_tunnel_visitor, REVIEW),
    "flagged by monitoring": (_flagged_by_monitoring, REVIEW),
    "scheduled": (_scheduled, REVIEW),
    "beacon bitmap": (_beacon_bitmap, REVIEW),
    "payload download": (_payload_download, REVIEW),
    "family with no profile": (_no_profile, REVIEW),
    "records disagree": (_records_disagree, REVIEW),
    "explained with every gap": (_explained_with_every_gap, EXPLAINED),
    "explained on an expired day": (_explained_on_an_expired_day, EXPLAINED),
    "inbound only": (_inbound_only, EXPLAINED),
}


@pytest.mark.parametrize("name", SHAPES)
def test_the_brief_says_nothing_of_how_we_work(tmp_path: Path, name: str) -> None:
    make, disposition = SHAPES[name]
    report = _saved(tmp_path, make(tmp_path))
    (case,) = report["cases"]
    assert case["disposition"] == disposition

    text = brief(case).text()

    # The marker rule 2 of the writer's prompt relies on is the one method phrase it may read.
    assert method_words(text.replace("Background not evidence", "")) == []
    assert "[" not in text and "§" not in text and "Model verdict" not in text
    assert "Outcome:" in text
    # What stands in when no reply passes says nothing of it either, marker included.
    assert method_words(" ".join(code_text(brief(case)).values())) == []


def test_the_brief_keeps_the_facts_the_lead_needs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REPORT_TIMEZONE", "Asia/Tokyo")
    report = _saved(tmp_path, _lure(tmp_path))
    (case,) = report["cases"]

    found = brief(case)

    assert "11.0 MB received" in " ".join(found.happened)
    assert "payload_delivery" not in found.text() and "payload delivery" in found.text()
    # The brief keeps UTC alone, whatever zone the run showed beside it.
    assert "Tokyo" not in found.text() and "03:06 UTC" in found.text()
    assert "kind(s) of contact" not in found.text() and (
        "1 address, port and name combination(s)" in found.text()
    )
    assert any("named the flagged domain" in line for line in found.outcome)
    assert found.outcome[0].startswith("Outcome: review.")
    assert found.next_steps[0].startswith("Identify the device")
    assert not any("still holds that device" in step for step in found.next_steps)
    assert not any("0.25" in line for line in found.happened)


def _with_digest(case: dict[str, Any], lines: dict[str, str]) -> dict[str, Any]:
    digest = "\n".join(f"{section}:\n- [Test] {line}" for section, line in lines.items())
    return {**case, "digest": digest}


def test_an_address_on_a_network_shared_by_design_is_not_called_unshared(tmp_path: Path) -> None:
    (case,) = _saved(tmp_path, _lure(tmp_path))["cases"]
    line = "198.51.100.7 carried at most 1 registered domain(s): not shown to be shared."

    def happened(network: str) -> str:
        lines = {
            "Threat": f"the flagged address 198.51.100.7 is in {network} (Canada).",
            "What happened": line,
        }
        return " ".join(brief(_with_digest(case, lines)).happened)

    shared = happened("AS13335 Cloudflare, Inc.")
    assert "not shown to be shared" not in shared
    assert "198.51.100.7 is on Cloudflare's network" in shared
    assert "only a TLS name on the contact" in shared
    assert happened("AS64500 Example Hosting") == line

    line = (
        "198.51.100.7 carried at most 1 registered domain(s), and is on Cloudflare's network, "
        "whose sites share its addresses by design: shared hosting."
    )
    assert "only a TLS name on the contact" in happened("AS13335 Cloudflare, Inc.")


def test_a_family_whose_channel_we_hold_does_not_read_as_undescribed(tmp_path: Path) -> None:
    (case,) = _saved(tmp_path, _lure(tmp_path))["cases"]
    claim = {**case["listing"], "malware": "win.asyncrat"}
    lines = {
        "Decision": "Not explained: 1 contact(s) (the family has no cited C2 profile). The first "
        "in full: win.asyncrat has no cited C2 profile, so protocol cannot explain it."
    }

    described = " ".join(brief({**_with_digest(case, lines), "listing": claim}).outcome)
    assert "no description" not in described
    assert described.count("AsyncRAT's channel is wrapped in TLS") == 2

    claim = {**case["listing"], "malware": "win.notdescribed"}
    lines["Decision"] = lines["Decision"].replace("win.asyncrat", "win.notdescribed")
    other = " ".join(brief({**_with_digest(case, lines), "listing": claim}).outcome)
    assert "we hold no description of how win.notdescribed communicates" in other


def test_the_brief_says_what_else_the_same_address_matched(tmp_path: Path) -> None:
    (case,) = _saved(tmp_path, _lure(tmp_path))["cases"]
    case = {**case, "matched_first": "2026-10-22T14:50:00+00:00"}
    other = {
        **case,
        "number": case["number"] + 1,
        "indicator": "203.0.113.9:443",
        "matched_first": "2026-10-20T12:24:00+00:00",
        "listing": {**case["listing"], "malware": "unknown"},
        "disposition": EXPLAINED,
    }
    elsewhere = {**other, "number": case["number"] + 2, "host": "192.0.2.200"}

    found = brief(case, [case, other, elsewhere])

    (line, *_rest) = found.happened
    assert line.startswith("The same campus address also matched another indicator: 203.0.113.9")
    assert "for which ThreatFox names no family" in line
    assert "first on 2026-10-20, 2 day(s) before this match" in line
    assert "we found an ordinary reason for that match" in line
    assert "may be a different device" in line
    assert sum("also matched" in text for text in found.happened) == 1
    assert brief(case, [case, elsewhere]).happened == brief(case).happened

    many = [{**other, "number": number} for number in range(10, 15)]
    assert any("2 more listed indicator(s)" in text for text in brief(case, many).happened)

    undated = {**other, "matched_first": None}
    assert "first on" not in brief(case, [undated]).happened[0]


def test_monitoring_is_named_in_plain_words(tmp_path: Path) -> None:
    report = _saved(tmp_path, _flagged_by_monitoring(tmp_path))
    (case,) = report["cases"]

    found = brief(case)

    assert any(
        "our campus behaviour monitoring separately flagged the host's contact" in line
        for line in found.outcome
    )
    assert not any("triage" in step.lower() for step in found.next_steps)


def test_the_digest_counts_read_plainly_in_the_brief() -> None:
    """A rule's count is kinds of contact or findings, never "items", and loses its rule code."""
    assert _plain("E1 explains 1 kind(s) of contact: UDP contact.") == (
        "An ordinary reason covers 1 address, port and name combination(s): UDP contact."
    )
    assert _plain("K4 on 3 finding(s); the first: a scheduled contact.") == (
        "3 finding(s); the first: a scheduled contact."
    )


def test_every_gap_is_named_in_plain_words(tmp_path: Path) -> None:
    report = _saved(tmp_path, _explained_with_every_gap(tmp_path))
    (case,) = report["cases"]

    gaps = [line for line in brief(case).outcome if line.startswith("Not checked:")]

    assert len(gaps) == 4
    assert "rest on the original match alone" in gaps[0]
    assert "behaviour monitoring did not cover 2026-09-15" in gaps[1]
    assert "no campus history for 2026-09-15" in gaps[2]
    assert "the age of rare-name.xyz is unknown" in gaps[3]


def test_a_family_with_no_profile_is_described_from_the_report_table(tmp_path: Path) -> None:
    report = _saved(tmp_path, _no_profile(tmp_path))
    (case,) = report["cases"]

    found = brief(case)

    assert any(line.startswith("Background not evidence: AsyncRAT:") for line in found.threat)
    assert not any("no cited profile" in line for line in found.threat)
    assert any("scheduled task" in step for step in found.next_steps)
    assert [source["label"] for source in page_data(report, case, GOOD)["sources"]] == [
        "Malpedia",
        "Censys",
        "Qualys",
    ]


def test_a_generic_label_and_an_undescribed_family_are_said_plainly(tmp_path: Path) -> None:
    (generic, tmp_a), (other, tmp_b) = (
        ("unknown_loader", tmp_path / "a"),
        ("win.notdescribed", tmp_path / "b"),
    )
    lines = {}
    for malware, directory in ((generic, tmp_a), (other, tmp_b)):
        directory.mkdir()
        rows = [minute_row(f"{DAY} 10:00:00", sni="api.rare-name.xyz")]
        feed, case = load(directory, [record(rows, malware=malware, **IP)])
        report = _saved(directory, Run(feed, evidence(feed, case)))
        lines[malware] = " ".join(brief(report["cases"][0]).threat)

    assert "ThreatFox names no family" in lines[generic]
    assert "We hold no description of win.notdescribed" in lines[other]


# --- choosing cases -------------------------------------------------------------------------------


def _two_cases(tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The fixture feed through a real run: case 1 is review, case 2 is explained."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(store_path))
    assert main([str(FEED), "--no-live", "--no-model", "--out", str(tmp_path / "run")]) == 0
    return tmp_path / "run" / "ioc_matches_synthetic.json"


def test_review_cases_by_default_and_any_case_by_its_number(
    tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = load_report(_two_cases(tmp_path, store_path, monkeypatch))

    assert [case["number"] for case in select_cases(report, None)] == [1]
    assert [case["number"] for case in select_cases(report, [2])] == [2]
    assert [case["number"] for case in select_cases(report, [2, 1, 2])] == [2, 1]
    with pytest.raises(CaseReportError, match="no case 9 in this report: it holds cases 1 to 2"):
        select_cases(report, [9])


def test_an_older_report_and_a_wrong_file_stop_with_a_message(tmp_path: Path) -> None:
    older = {"cases": [{"number": 1, "disposition": REVIEW, "digest": None}]}
    with pytest.raises(CaseReportError, match="predates them"):
        select_cases(older, None)
    oldest = {"cases": [{"disposition": REVIEW}]}
    with pytest.raises(CaseReportError, match="predates case numbers"):
        select_cases(oldest, None)

    wrong = tmp_path / "feed.json"
    wrong.write_text(json.dumps([{"indicator": "x"}]), encoding="utf-8")
    with pytest.raises(CaseReportError, match="not a report"):
        load_report(wrong)
    with pytest.raises(CaseReportError, match="cannot read"):
        load_report(tmp_path / "missing.json")


# --- the writer -----------------------------------------------------------------------------------


def _client(post: _Post) -> OpenRouterClient:
    client = OpenRouterClient(CONFIG, post, sleep=lambda _: None, budget=0.50)
    client.require_model()
    return client


def _posted(*replies: bytes | Exception) -> _Post:
    return _Post([_listing(["structured_outputs"]), *replies])


def _sent(post: _Post) -> list[str]:
    """Everything in every request after the model listing."""
    return [json.dumps(body) for _url, body, _headers in post.calls[1:]]


def test_the_model_writes_every_paragraph_and_the_host_never_reaches_it(tmp_path: Path) -> None:
    report = _saved(tmp_path, _lure(tmp_path))
    post = _posted(_reply(GOOD))

    (written,) = write_case_reports(
        report, select_cases(report, None), tmp_path / "out", _client(post)
    )

    assert written.narrative.by_model and written.narrative.attempts == 1
    assert written.pdf.name == f"{file_stem(report, report['cases'][0])}.pdf"
    assert written.pdf.read_bytes().startswith(b"%PDF-")
    (request,) = _sent(post)
    assert HOST not in request and "HOST" in request
    assert '"zdr": true' in request
    audit = json.loads(written.audit.read_text(encoding="utf-8"))
    assert audit["paragraphs"]["host"].startswith(f"{HOST} used a handful")
    assert HOST not in audit["what_the_writer_read"]
    assert audit["written_by"] == CONFIG.model + " via OpenRouter (zero-retention routing)"


def test_the_address_the_source_writes_is_replaced_too(tmp_path: Path) -> None:
    report = _saved(tmp_path, _lure(tmp_path))
    case = {**report["cases"][0], "source_host": "::ffff:192.0.2.10"}
    case["digest"] = case["digest"].replace(
        "Host:\n", "Host:\n- [Live source] at ::ffff:192.0.2.10\n"
    )
    post = _posted(_reply(GOOD))

    write_case_reports(report, [case], tmp_path / "out", _client(post))

    (request,) = _sent(post)
    assert "192.0.2.10" not in request


@pytest.mark.parametrize(
    ("bad", "problem"),
    [
        ({"why": "Our retained history shows nothing."}, "says how we work (retained)"),
        ({"why": "Rule K1 kept the case."}, "K1"),
        ({"contact": "Code kept it because the rules say so."}, "says how we work"),
        ({"why": "The match can be safely dismissed."}, "contradicts the code's decision"),
        ({"host": "The host is compromised."}, "describes the host's state"),
        ({"contact": "It moved 987 MB."}, "numbers that are not in the input"),
        ({"contact": "It reached evil.example.org."}, "names that are not in the input"),
        ({"summary": "word " * 200}, "summary runs to 200 words"),
        ({"host": "Its products are typical of ordinary office use."}, "judges the host's use"),
        ({"threat": "Our background note describes the family."}, "says how we work (background)"),
        ({"conclusion": "The next step is to identify the device.}"}, "has a stray brace"),
    ],
)
def test_a_reply_that_fails_goes_back_with_its_problem(
    tmp_path: Path, bad: dict[str, str], problem: str
) -> None:
    report = _saved(tmp_path, _lure(tmp_path))
    post = _posted(_reply({**GOOD, **bad}), _reply(GOOD))

    (written,) = write_case_reports(
        report, select_cases(report, None), tmp_path / "out", _client(post)
    )

    assert written.narrative.by_model and written.narrative.attempts == 2
    assert problem in _sent(post)[1]


def test_when_no_reply_passes_code_stands_and_nothing_is_kept(tmp_path: Path) -> None:
    report = _saved(tmp_path, _lure(tmp_path))
    bad = _reply({**GOOD, "why": "Our retained history shows nothing."})
    post = _posted(bad, bad, bad, _reply(GOOD))
    client = _client(post)
    cases = select_cases(report, None)

    (written,) = write_case_reports(report, cases, tmp_path / "out", client)

    assert not written.narrative.by_model and written.narrative.problems
    assert written.pdf.read_bytes().startswith(b"%PDF-")
    audit = json.loads(written.audit.read_text(encoding="utf-8"))
    assert audit["written_by"] == "code" and audit["problems"]
    assert "11.0 MB received" in audit["paragraphs"]["contact"]

    # A failure is asked again, where an overview's would come back from the cache.
    (again,) = write_case_reports(report, cases, tmp_path / "out", client)
    assert again.narrative.by_model and not again.narrative.cached


def test_a_reply_that_passed_is_never_paid_for_twice(tmp_path: Path) -> None:
    report = _saved(tmp_path, _lure(tmp_path))
    post = _posted(_reply(GOOD))
    client = _client(post)
    cases = select_cases(report, None)

    write_case_reports(report, cases, tmp_path / "out", client)
    (again,) = write_case_reports(report, cases, tmp_path / "out", client)

    assert again.narrative.cached and len(_sent(post)) == 1


def test_a_request_over_the_budget_is_not_sent_and_says_so(tmp_path: Path) -> None:
    report = _saved(tmp_path, _lure(tmp_path))
    post = _posted()
    client = OpenRouterClient(CONFIG, post, sleep=lambda _: None, budget=0.0001)
    client.require_model()

    (written,) = write_case_reports(report, select_cases(report, None), tmp_path / "out", client)

    assert not _sent(post) and not written.narrative.by_model
    assert "budget" in written.narrative.problems[0]


def test_a_case_report_asks_for_low_effort_on_a_client_set_higher(tmp_path: Path) -> None:
    report = _saved(tmp_path, _lure(tmp_path))
    client = OpenRouterClient(
        replace(CONFIG, effort="medium"), _posted(), sleep=lambda _: None, budget=0.50
    )

    write_case_reports(report, [], tmp_path / "out", client)

    assert client.config.effort == "low"


def test_a_report_on_an_inbound_list_cannot_state_who_opened_the_contact() -> None:
    assert inbound_problems({"why": "The contact fits the listed address connecting in."}) == []
    assert inbound_problems({"why": "We cannot say who opened the contact."}) == []
    assert inbound_problems({"why": "The host reached the update service."}) == []
    for stated in (
        "The listed address connected in to the host.",
        "The address reached the host twice.",
        "The address reached HOST.",
    ):
        assert inbound_problems({"why": stated})


def test_a_count_of_new_destinations_needs_something_to_weigh_it() -> None:
    assert unweighed_count({"after": "It reached 8845 new named destinations."})
    assert unweighed_count({"after": "It reached 1 new destination."})
    weighed = "It reached 8845 new named destinations and used 400 services; the median was 41."
    assert unweighed_count({"after": weighed}) == []
    assert unweighed_count({"after": "No uploads to new destinations."}) == []


def test_new_destinations_are_weighed_by_that_days_services_not_the_median_alone() -> None:
    brief = "8845 new named destination(s) (this address used 2178 distinct services on that day)"
    alone = "It reached 8845 new named destinations, against a campus median of 36 services."
    assert unweighed_count({"after": alone}, brief)
    both = "It reached 8845 new named destinations; that day it used 2178 services, median 36."
    assert unweighed_count({"after": both}, brief) == []


def test_a_report_cannot_say_there_was_no_contact_after_a_date() -> None:
    for wrong in (
        "We found no further contact with the address after 4 Nov 2026.",
        "No contact with the listed address appeared after 21 Oct 2026.",
        "No later contact with the address appears through 23 Oct 2026.",
    ):
        assert any("no contact after a date" in found for found in report_problems({"why": wrong}))
    assert report_problems({"why": "We found no contact with the address on 4 Nov 2026."}) == []
    for undated in (
        "We saw no later contact with 198.51.100.7.",
        "No further contact with the address.",
    ):
        assert any(
            "without naming the days" in found for found in report_problems({"why": undated})
        )
    dated = "We saw no contact with 198.51.100.7 on 23 Oct 2026, the one later day we read."
    assert report_problems({"why": dated}) == []


def test_an_inbound_report_has_more_room_for_what_followed() -> None:
    written = {"after": " ".join(["word"] * 100)}
    assert report_problems(written)
    assert report_problems(written, INBOUND_WORDS) == []


def test_the_facts_a_reader_needs_cannot_be_dropped() -> None:
    brief_text = (
        "- also matched another indicator: 203.0.113.9:443, listed by ThreatFox as AsyncRAT.\n"
        "- 12 destination(s) new to this host sent it 1 MB or more, 13.5 GB in all."
    )
    assert len(missing_facts({"why": "Nothing else."}, brief_text)) == 2
    kept = {"why": "It also matched 203.0.113.9.", "after": "They sent it 13.5 GB."}
    assert missing_facts(kept, brief_text) == []
    assert missing_facts({"why": "Nothing else."}, "- a line with neither.") == []


def test_a_count_of_new_destinations_reaches_the_writer_beside_the_median(tmp_path: Path) -> None:
    (case,) = _saved(tmp_path, _lure(tmp_path))["cases"]
    lines = {
        "Host": "on 2026-10-15 it used 137 distinct services (campus addresses with a service row "
        "had a median of 41 and a 90th percentile of 165) and moved 1.8 GB.",
        "What happened": "29 new named destination(s) and 0 network(s) with no name in all.",
    }

    (line,) = brief(_with_digest(case, lines)).happened

    assert line.startswith(
        "29 new named destination(s) (this address used 137 distinct services on 2026-10-15, "
        "against a campus median of 41)"
    )


def test_what_the_checks_allow_in_ordinary_words() -> None:
    assert method_words("We cannot rule out or rule it out. Remote code execution.") == []
    assert method_words("Started from the user profile; the file's name, size and hash.") == []
    assert method_words("The rules kept it.") == ["rules"]
    assert method_words("By code, E3 explains it.") == ["E3", "by code"]
    assert method_words("Zeek's logs show the contact.") == ["zeek"]
    assert report_problems(GOOD) == []
    assert report_problems({"why": "We found no ordinary reason for the contact."}) == []
    assert report_problems({"why": "The name was not in routine campus use."}) == []
    assert set(REPORT_WORDS) == set(REPORT_FIELDS)


def test_the_shapes_come_back_from_a_saved_case_file(tmp_path: Path) -> None:
    run = _lure(tmp_path)
    decided = decide(run.evidence, run.feed.domain_indicators)
    text = render_case_file(run.evidence, decided, run.live, run.history)

    assert observed_from_case_file(text) == observed_shapes(run.evidence)
    held = "held-open connection (1.0 h or more): yes; regular schedule: no; "
    found = observed_from_case_file(held + "transfer of about 1 MB or more: yes.")
    assert (found.held_open, found.regular, found.large_transfer) == (True, False, True)
    nothing = observed_from_case_file("")
    assert not (nothing.held_open or nothing.regular or nothing.large_transfer)


# --- the page -------------------------------------------------------------------------------------


def _pages(page: dict[str, Any]) -> int:
    template = files("ioc_report").joinpath("case_report.typ").read_bytes()
    found = typst.compile(
        template,
        format="png",
        ppi=10,
        sys_inputs={"report": json.dumps(page)},
        ignore_system_fonts=True,
    )
    return len(found) if isinstance(found, list) else 1


def _report_page(fields: dict[str, str], disposition: str = REVIEW) -> dict[str, Any]:
    report = {"name": "synthetic", "generated_at": GENERATED.isoformat()}
    case = {
        "number": 1,
        "host": HOST,
        "indicator": "lure.example.com",
        "indicator_type": "domain",
        "disposition": disposition,
        "threatfox": {"malware": "win.asyncrat", "threat_type": "botnet_cc"},
        "contacts": [{"first": "2026-10-22T14:50:00+00:00"}],
    }
    return page_data(report, case, fields)


def test_text_from_a_feed_or_a_model_is_never_evaluated_as_markup() -> None:
    hostile = '#panic("evaluated") $x$ *b* _i_ [z] <l> @ref `r` // c \\ #import "x.typ" = h'

    pdf = render_pdf(_report_page(dict.fromkeys(REPORT_FIELDS, hostile)))

    assert pdf.startswith(b"%PDF-")


def test_a_report_at_its_word_limits_fits_one_page() -> None:
    words = PROSE.split()
    longest = {name: " ".join(islice(cycle(words), limit)) for name, limit in REPORT_WORDS.items()}

    assert _pages(_report_page(longest)) == 1


def test_a_page_count_of_more_than_one_is_seen() -> None:
    assert _pages(_report_page(dict.fromkeys(REPORT_FIELDS, "word " * 3000))) > 1


def test_code_writes_the_facts_line_the_headings_and_the_limits() -> None:
    page = _report_page(GOOD)

    assert page["title"] == f"Case Report: {HOST} and lure.example.com"
    assert page["facts"] == (
        "ThreatFox lists lure.example.com as AsyncRAT (botnet command and control). First contact "
        "22 Oct 2026, 14:50 UTC. Status: open for review. Data to 5 Nov 2026."
    )
    assert page["why_heading"] == "Why this case stays open"
    assert page["limits"] == LIMITS
    assert method_words(" ".join((page["title"], page["facts"], page["limits"]))) == []
    explained = _report_page(GOOD, EXPLAINED)
    assert explained["why_heading"] == "Why the contact has an ordinary reason"
    assert "Status: explained." in explained["facts"]


# --- the commands ---------------------------------------------------------------------------------


def _fake_case_client(monkeypatch: pytest.MonkeyPatch, *replies: bytes | Exception) -> _Post:
    credits = json.dumps({"data": {"total_credits": 5.0, "total_usage": 0.5}}).encode()
    post = _Post([_listing(["structured_outputs"]), credits, *replies])
    monkeypatch.setattr(
        cli,
        "_case_report_client",
        lambda env, budget: OpenRouterClient(CONFIG, post, sleep=lambda _: None, budget=budget),
    )
    return post


def _named(
    number: int,
    disposition: str,
    indicator: str,
    kind: str,
    host: str,
    malware: str = "js.iclickfix",
) -> dict[str, Any]:
    return {
        "number": number,
        "disposition": disposition,
        "indicator": indicator,
        "indicator_type": kind,
        "host": host,
        "listing": {"malware": malware},
    }


def test_a_review_case_is_named_threat_first_then_host_and_detail() -> None:
    domain = _named(1, REVIEW, "bad.example.org", "domain", HOST)
    address = _named(2, REVIEW, "198.51.100.7", "ip", HOST, "win.asyncrat")
    with_port = _named(3, REVIEW, "203.0.113.9:443", "ip:port", HOST, "win.nanocore")
    report = {"name": "run", "cases": [domain, address, with_port]}

    assert file_stem(report, domain) == f"ClickFix-style lure ({HOST}, bad.example.org)"
    assert file_stem(report, address) == f"AsyncRAT ({HOST}, 198.51.100.7)"
    assert file_stem(report, with_port) == f"NanoCore RAT ({HOST}, 203.0.113.9)"


def test_a_threat_label_is_short_and_says_when_no_family_is_named() -> None:
    def label(malware: str) -> str:
        case = _named(1, REVIEW, "bad.example.org", "domain", HOST, malware)
        return file_stem({"name": "run", "cases": [case]}, case).split(" (")[0]

    assert label("elf.shadowv2") == "ShadowV2"
    assert label("unknown") == "Unnamed family"
    assert label("unknown_loader") == "Unnamed loader"
    assert label("unknown_rat") == "Unnamed RAT"
    assert label("win.notdescribed") == "win.notdescribed"


def test_any_other_case_keeps_its_run_and_number() -> None:
    explained = _named(4, EXPLAINED, "bad.example.org", "domain", HOST)

    assert file_stem({"name": "run", "cases": [explained]}, explained) == "run_case_4"


def test_a_port_stays_only_where_two_review_cases_would_share_a_name() -> None:
    web = _named(1, REVIEW, "203.0.113.9:443", "ip:port", HOST, "win.asyncrat")
    other = _named(2, REVIEW, "203.0.113.9:8443", "ip:port", HOST, "win.asyncrat")
    elsewhere = _named(3, REVIEW, "203.0.113.9:443", "ip:port", "192.0.2.11", "win.asyncrat")
    report = {"name": "run", "cases": [web, other, elsewhere]}

    assert file_stem(report, web) == f"AsyncRAT ({HOST}, 203.0.113.9-443)"
    assert file_stem(report, other) == f"AsyncRAT ({HOST}, 203.0.113.9-8443)"
    assert file_stem(report, elsewhere) == "AsyncRAT (192.0.2.11, 203.0.113.9)"


def test_a_feed_value_cannot_leave_the_folder_or_hide_the_file() -> None:
    hostile = _named(1, REVIEW, "../../etc/passwd", "domain", "2001:db8::1", "../../evil/.name")
    empty = _named(2, REVIEW, "...", "domain", HOST, "///")
    long = _named(3, REVIEW, "a" * 400 + ".example.org", "domain", "b" * 39, "c" * 400)
    report = {"name": "r" * 400, "cases": [hostile, empty, long]}

    assert file_stem(report, hostile) == "evil-.name (2001-db8-1, etc-passwd)"
    assert file_stem(report, empty) == f"Unnamed family ({HOST}, unknown)"
    assert "/" not in file_stem(report, hostile)
    assert len(f"{file_stem(report, long)} {report['name'][:40]}.json".encode()) <= 255


def test_a_run_never_overwrites_another_runs_report_in_a_shared_folder(tmp_path: Path) -> None:
    report = _saved(tmp_path, _lure(tmp_path))
    out = tmp_path / "out"
    stem = file_stem(report, report["cases"][0])

    (first,) = write_case_reports(report, select_cases(report, None), out, None)
    (again,) = write_case_reports(report, select_cases(report, None), out, None)
    later = {**report, "name": "later_feed"}
    (other,) = write_case_reports(later, select_cases(later, None), out, None)
    (other_again,) = write_case_reports(later, select_cases(later, None), out, None)

    assert first.pdf.name == again.pdf.name == f"{stem}.pdf"
    assert other.pdf.name == other_again.pdf.name == f"{stem} later_feed.pdf"
    assert {path.name for path in out.glob("*.pdf")} == {f"{stem}.pdf", f"{stem} later_feed.pdf"}
    assert json.loads(first.audit.read_text(encoding="utf-8"))["report"] == report["name"]


def test_the_tool_writes_every_review_case_and_prints_no_case_text(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    saved = _two_cases(tmp_path, store_path, monkeypatch)
    capsys.readouterr()
    _fake_case_client(monkeypatch, _reply(GOOD))

    assert case_main([str(saved), "--budget", "0.10"]) == 0

    printed = capsys.readouterr()
    assert (saved.parent / f"NanoCore RAT ({HOST}, tunnel.example.com).pdf").is_file()
    assert (saved.parent / f"NanoCore RAT ({HOST}, tunnel.example.com).json").is_file()
    assert not (saved.parent / "ioc_matches_synthetic_case_2.pdf").exists()
    assert "case 1, review" in printed.out and "OpenRouter reported $0.0000" in printed.out
    assert HOST not in printed.out + printed.err
    assert "tunnel.example.com" not in printed.out + printed.err


def test_the_tool_writes_the_case_it_is_pointed_at(
    tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved = _two_cases(tmp_path, store_path, monkeypatch)
    _fake_case_client(monkeypatch, _reply(GOOD))
    out = tmp_path / "elsewhere"

    assert case_main([str(saved), "--case", "2", "--budget", "0.10", "--out", str(out)]) == 0

    assert [path.name for path in sorted(out.glob("*.pdf"))] == ["ioc_matches_synthetic_case_2.pdf"]
    audit = json.loads((out / "ioc_matches_synthetic_case_2.json").read_text(encoding="utf-8"))
    assert audit["disposition"] == EXPLAINED and audit["indicator"] == "9.9.9.9:443"


def test_the_tool_needs_a_budget_unless_it_uses_no_model(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    saved = _two_cases(tmp_path, store_path, monkeypatch)
    capsys.readouterr()

    assert case_main([str(saved)]) == 2
    assert "--budget" in capsys.readouterr().err
    assert not (saved.parent / f"NanoCore RAT ({HOST}, tunnel.example.com).pdf").exists()

    assert case_main([str(saved), "--no-model"]) == 0
    printed = capsys.readouterr().out
    assert (saved.parent / f"NanoCore RAT ({HOST}, tunnel.example.com).pdf").is_file()
    assert "by code's plain text" in printed and "not for submission" in printed


def test_the_chosen_model_is_the_default() -> None:
    client = cli._case_report_client({"OPENROUTER_API_KEY": "test-key"}, 0.10)
    assert client.model == "anthropic/claude-haiku-5.5"
    named = {"OPENROUTER_API_KEY": "test-key", "OPENROUTER_MODEL": "other/model"}
    assert cli._case_report_client(named, 0.10).model == "other/model"


def test_a_pdf_on_code_text_is_a_failure_the_tool_says_out_loud(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    saved = _two_cases(tmp_path, store_path, monkeypatch)
    capsys.readouterr()
    bad = _reply({**GOOD, "why": "Our retained history shows nothing."})
    _fake_case_client(monkeypatch, bad, bad, bad)

    assert case_main([str(saved), "--budget", "0.10"]) == 1

    assert "before submitting" in capsys.readouterr().err


def test_a_wrong_case_number_stops_before_any_spend(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    saved = _two_cases(tmp_path, store_path, monkeypatch)
    capsys.readouterr()
    post = _fake_case_client(monkeypatch)

    assert case_main([str(saved), "--case", "9", "--budget", "0.10"]) == 2

    assert "no case 9" in capsys.readouterr().err and not post.calls


def _run(tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: str) -> int:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(store_path))
    return main([str(FEED), "--no-live", "--out", str(tmp_path / "run"), *extra])


def test_a_run_writes_no_pdf_and_asks_for_no_budget_unless_told_to(
    tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(env: object, budget: object) -> None:
        raise AssertionError("no case report was asked for")

    monkeypatch.setattr(cli, "_case_report_client", refuse)

    assert _run(tmp_path, store_path, monkeypatch, "--no-model") == 0
    assert _run(tmp_path, store_path, monkeypatch, "--no-model", "--no-case-reports") == 0

    assert not list((tmp_path / "run").glob("*.pdf"))


def test_a_run_with_case_reports_needs_a_budget(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    transport = _fake_writer([])
    monkeypatch.setattr(cli, "OllamaClient", lambda config: OllamaClient(config, transport))

    assert _run(tmp_path, store_path, monkeypatch, "--case-reports") == 2

    assert "--budget" in capsys.readouterr().err and not (tmp_path / "run").exists()


def test_a_run_with_case_reports_writes_one_for_each_review_case(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []
    transport = _fake_writer(calls)
    monkeypatch.setattr(cli, "OllamaClient", lambda config: OllamaClient(config, transport))
    post = _fake_case_client(monkeypatch, _reply(GOOD))

    assert _run(tmp_path, store_path, monkeypatch, "--case-reports", "--budget", "0.10") == 0

    run = tmp_path / "run"
    assert [path.name for path in run.glob("*.pdf")] == [
        f"NanoCore RAT ({HOST}, tunnel.example.com).pdf"
    ]
    assert (run / "ioc_matches_synthetic.md").is_file()
    audit = json.loads(
        (run / f"NanoCore RAT ({HOST}, tunnel.example.com).json").read_text(encoding="utf-8")
    )
    assert audit["written_by"].startswith(CONFIG.model)
    assert [url.rsplit("/", 1)[1] for url, _body, _headers in post.calls] == [
        "models",
        "credits",
        "completions",
    ]
    assert "OpenRouter reported" in capsys.readouterr().out
    # The local writer still wrote the feed's report: tags, two cases, two groups, the summary.
    assert sum(url.endswith("/api/chat") for url in calls) == 5


def test_no_model_means_no_model_in_a_run_too(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def refuse(env: object, budget: object) -> None:
        raise AssertionError("--no-model sends nothing")

    monkeypatch.setattr(cli, "_case_report_client", refuse)

    assert _run(tmp_path, store_path, monkeypatch, "--no-model", "--case-reports") == 0

    run = tmp_path / "run"
    assert [path.name for path in run.glob("*.pdf")] == [
        f"NanoCore RAT ({HOST}, tunnel.example.com).pdf"
    ]
    assert "not for submission" in capsys.readouterr().out
