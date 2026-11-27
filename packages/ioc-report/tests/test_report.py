from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ioc_report import cli, registration
from ioc_report.casefile import after_contact, next_steps, render_case_file
from ioc_report.cli import main
from ioc_report.digest import case_digest
from ioc_report.model import OllamaClient, OllamaConfig
from ioc_report.openrouter import OpenRouterClient
from ioc_report.report import write_report
from ioc_report.summary import CaseResult
from tests.conftest import FIXTURES, minute_row, record, write_feed
from tests.test_facts import VERDICT_WORDS, shaped
from tests.test_openrouter import CONFIG, _listing, _Post

FEED = FIXTURES / "ioc_matches_synthetic.json"


def _run(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    out: str,
    *extra: str,
) -> dict[str, Any]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(store_path))
    assert main([str(FEED), "--no-live", "--out", str(tmp_path / out), *extra]) == 0
    data: dict[str, Any] = json.loads(
        (tmp_path / out / "ioc_matches_synthetic.json").read_text(encoding="utf-8")
    )
    return data


def test_a_facts_only_run_gives_every_case_an_overview_in_code(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = _run(tmp_path, store_path, monkeypatch, "out", "--no-model")

    printed = capsys.readouterr().out
    assert "2 case(s), 1 review, 1 explained" in printed
    assert printed.startswith(f"wrote {tmp_path / 'out' / 'ioc_matches_synthetic.html'} ")
    page = (tmp_path / "out" / "ioc_matches_synthetic.html").read_text(encoding="utf-8")
    assert page.count('<article class="case card"') == 2 and "<svg" not in page
    for section in ("Executive summary", "Background", "Analysis", "Conclusion and next steps"):
        assert f">{section}</h2>" in page
    markdown = (tmp_path / "out" / "ioc_matches_synthetic.md").read_text(encoding="utf-8")
    for section in ("Summary", "Threats", "Cases", "Next steps by system", "Each case", "Appendix"):
        assert f"\n## {section}\n" in markdown
    assert markdown.count('<a id="case-') == 2 and markdown.count("**Why:**") == 2
    assert "| From (UTC) | To | Source | What |" in markdown
    assert "**How to read it.**" not in markdown and "[Decision, by code]" not in markdown
    assert "### The checks behind every verdict" in markdown
    cases = {case["indicator"]: case for case in data["cases"]}
    review, explained = cases["tunnel.example.com"], cases["9.9.9.9:443"]
    assert (review["number"], explained["number"]) == (1, 2)
    assert (review["disposition"], review["rules"]) == ("review", ["K1"])
    assert "[Decision, by code] review: kept by K1." in review["case_file"]
    assert "[Knowledge, background not evidence] NanoCore RAT" in review["case_file"]
    assert review["next_steps"] and not explained["next_steps"]
    assert review["facts"]["notable"][0]["source"] == "IOC feed"
    assert any(
        "campus standing (CASE_STUDY §15) cannot be judged" in fact["text"]
        for fact in review["facts"]["notable"]
    )
    assert (explained["disposition"], explained["rules"]) == ("explained", ["E1", "E2"])
    for case in (review, explained):
        assert case["case_file"] and case["digest"] and case["overview"]["written_by"] == "code"
        assert all(case["overview"]["text"].values())
    assert "Code explained every contact" in explained["overview"]["text"]["reading"]
    assert [group["cases"] for group in data["groups"]] == [[1], [2]]
    assert datetime.fromisoformat(data["generated_at"]).tzinfo == UTC


def _fake_writer(calls: list[str]) -> Any:
    def transport(url: str, body: bytes | None, timeout: float) -> bytes:
        calls.append(url)
        if url.endswith("/api/tags"):
            return json.dumps({"models": [{"name": OllamaConfig().model}]}).encode()
        fields = json.loads(body or b"{}")["format"]["required"]
        reply = {
            name: "Code decided the case; flow records carry no process or user." for name in fields
        }
        return json.dumps({"message": {"content": json.dumps(reply)}}).encode()

    return transport


def test_the_model_writes_every_case_and_changes_no_decision(
    tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    transport = _fake_writer(calls)
    monkeypatch.setattr(cli, "OllamaClient", lambda config: OllamaClient(config, transport))
    facts = _run(tmp_path, store_path, monkeypatch, "facts", "--no-model")
    with_model = _run(tmp_path, store_path, monkeypatch, "model")

    # Two cases, two groups and the summary: five replies after the model check.
    assert [url.rsplit("/", 1)[-1] for url in calls] == ["tags"] + ["chat"] * 5
    assert [(c["indicator"], c["disposition"]) for c in facts["cases"]] == [
        (c["indicator"], c["disposition"]) for c in with_model["cases"]
    ]
    assert all(c["overview"]["fields"] for c in with_model["cases"])
    assert with_model["summary"]["fields"]["summary"].startswith("Code decided")

    _run(tmp_path, store_path, monkeypatch, "model")
    # The second run checks the model is there, then answers every request from the cache.
    assert sum(url.endswith("/api/chat") for url in calls) == 5


def test_a_missing_store_setting_stops_with_a_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", raising=False)

    assert main([str(FEED), "--no-live", "--no-model"]) == 2
    assert "NETWORK_BEHAVIOUR_DUCKDB_PATH is required" in capsys.readouterr().err


def test_several_feed_files_need_a_name_and_make_one_report(
    tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(store_path))
    rows = [minute_row("2026-09-15 10:00:00", sni="www.tunnel.example.com")]
    for half, indicator in (
        ("a", ("tunnel.example.com", "domain")),
        ("b", ("1.1.1.1:443", "ip:port")),
    ):
        (tmp_path / half).mkdir()
        write_feed(
            tmp_path / half, [record(rows, indicator=indicator[0], indicator_type=indicator[1])]
        )
    feeds = [str(tmp_path / "a" / "feed.json"), str(tmp_path / "b" / "feed.json")]

    assert main([*feeds, "--no-live", "--no-model"]) == 2
    assert main([*feeds, "--no-live", "--no-model", "--name", "export", "--out", "out"]) == 0

    data = json.loads((tmp_path / "out" / "export.json").read_text(encoding="utf-8"))
    assert data["name"] == "export" and len(data["feed"]) == 2
    assert {case["indicator"] for case in data["cases"]} == {"tunnel.example.com", "1.1.1.1:443"}
    explained = [case for case in data["cases"] if case["disposition"] == "explained"]
    assert all(case["caveats"] and case["registrations"] is None for case in explained)
    markdown = (tmp_path / "out" / "export.md").read_text(encoding="utf-8")
    assert "with caveats" in markdown and "**Could not check:**" in markdown


def test_no_name_is_looked_up_unless_asked(
    tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("an RDAP lookup was built without NAME_LOOKUP=rdap")

    monkeypatch.delenv("NAME_LOOKUP", raising=False)
    monkeypatch.setattr(registration, "RdapLookup", refuse)
    data = _run(tmp_path, store_path, monkeypatch, "out", "--no-model")
    assert all(case["registrations"] is None for case in data["cases"])


def test_a_paid_run_stops_when_the_live_source_is_unavailable(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(store_path))
    credits = json.dumps({"data": {"total_credits": 5.0, "total_usage": 0.0}}).encode()
    post = _Post([_listing(["structured_outputs"]), credits])
    client = OpenRouterClient(CONFIG, post, sleep=lambda _: None, budget=0.10)
    monkeypatch.setattr(cli, "_model_client", lambda env, budget: client)
    # The source file is missing, so the live session cannot open it.
    monkeypatch.setenv("NETWORK_BEHAVIOUR_SOURCE_PATH", str(tmp_path / "absent-source.duckdb"))

    assert main([str(FEED), "--budget", "0.10"]) == 2
    assert "load the match days into the source, or pass --no-live" in capsys.readouterr().err
    assert len(post.calls) == 2  # the model listing and the credit check; no case was sent


@pytest.mark.parametrize(
    ("detail_days", "advice", "not_said"),
    [
        ("", "Run the report with the live source", "Run each feed within"),
        ("15", "Run each feed within 13 days", "Run the report with the live source"),
    ],
)
def test_a_run_without_the_live_source_advises_by_the_source_s_retention(
    tmp_path: Path,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    detail_days: str,
    advice: str,
    not_said: str,
) -> None:
    """--no-live reads no source, but the retention it declares still shapes the advice."""
    monkeypatch.setenv("NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS", detail_days)
    _run(tmp_path, store_path, monkeypatch, "out", "--no-model")

    page = (tmp_path / "out" / "ioc_matches_synthetic.html").read_text(encoding="utf-8")
    assert advice in page
    assert not_said not in page


DISCLAIMER = "no case says a host is compromised, infected or benign"


def _markdown(tmp_path: Path) -> str:
    """The report for one shaped review case, written as a run writes it."""
    case = shaped(tmp_path)
    evidence, decision = case.evidence, case.decision
    result = CaseResult(
        evidence,
        decision,
        render_case_file(evidence, decision, case.live, case.history),
        next_steps=next_steps(evidence, decision, after_contact(evidence, case.live, case.history)),
        digest=case_digest(evidence, decision, case.live, case.history),
    )
    paths = write_report(
        tmp_path / "run",
        "synthetic",
        case.feed,
        [result],
        case.live,
        case.history,
        "test",
        datetime(2026, 10, 22, 1, 0, tzinfo=UTC),
    )
    markdown = next(path for path in paths if path.suffix == ".md")
    return markdown.read_text(encoding="utf-8")


def test_the_markdown_carries_its_marking_and_points_to_the_json(tmp_path: Path) -> None:
    markdown = _markdown(tmp_path)

    assert "Sensitive: internal addresses and domains" in markdown
    assert "the case files are in `synthetic.json`" in markdown


def test_no_verdict_words_beyond_the_disclaimer(tmp_path: Path) -> None:
    markdown = _markdown(tmp_path)
    text = markdown.replace(DISCLAIMER, "").lower()

    assert DISCLAIMER in markdown
    assert not [word for word in VERDICT_WORDS if word in text]


def test_a_case_shows_its_reasons_contacts_and_sourced_facts(tmp_path: Path) -> None:
    markdown = _markdown(tmp_path)
    case = markdown[markdown.index('<a id="case-1">') :]

    assert case.index("**Why:**") < case.index("| From (UTC) |") < case.index("**What happened**")
    assert "[Live source] Just before the contact" in case
    assert "natureland.example, 1.0 min later" in case
    assert "**Next steps:**" in case and "**Would change it:**" in case
    assert "Knowledge, background not evidence" not in case
