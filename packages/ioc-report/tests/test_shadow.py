from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from ioc_report import cli
from ioc_report.casefile import render_case_file
from ioc_report.cli import main
from ioc_report.history import Coverage, HistoryContext
from ioc_report.model import OllamaClient, OllamaConfig
from ioc_report.shadow import SHADOW_SCHEMA, shadow_verdict
from tests.builders import SKIPPED, decision, evidence, load
from tests.conftest import FIXTURES, minute_row, record


def _client(
    verdicts: Sequence[str | Exception] | Callable[[str], str],
) -> tuple[OllamaClient, list[dict[str, Any]]]:
    sent: list[dict[str, Any]] = []
    replies = iter(verdicts) if not callable(verdicts) else None

    def transport(url: str, body: bytes | None, timeout: float) -> bytes:
        if url.endswith("/api/tags"):
            return json.dumps({"models": [{"name": OllamaConfig().model}]}).encode()
        payload = json.loads(body or b"{}")
        sent.append(payload)
        if payload["format"] != SHADOW_SCHEMA:
            return json.dumps(
                {"message": {"content": json.dumps({"summary": "A visit."})}}
            ).encode()
        content_in = payload["messages"][1]["content"]
        verdict = next(replies) if replies is not None else verdicts(content_in)  # type: ignore[operator]
        if isinstance(verdict, Exception):
            raise verdict
        content = {"reasoning": "Because.", "verdict": verdict}
        return json.dumps({"message": {"content": json.dumps(content)}}).encode()

    return OllamaClient(OllamaConfig(), transport), sent


def test_a_blind_case_file_carries_no_decision(tmp_path: Path) -> None:
    rows = [minute_row("2026-09-15 10:00:00", sni="www.lure.example.com")]
    feed, case = load(tmp_path, [record(rows, indicator="lure.example.com")])
    found = evidence(feed, case)
    history = HistoryContext(tmp_path, Coverage(frozenset(), frozenset()), {})

    blind = render_case_file(found, decision(feed, case), SKIPPED, history, blind=True)
    full = render_case_file(found, decision(feed, case), SKIPPED, history)

    assert "[Decision" in full and "[Decision" not in blind
    for word in ("explained by", "not explained", "K1", "kept by"):
        assert word not in blind


def test_samples_vary_by_seed_and_a_tie_is_not_a_majority() -> None:
    client, sent = _client(["review", "explained", "review"])

    verdict = shadow_verdict("case file", client, 3)

    assert [p["options"]["seed"] for p in sent] == [11, 23, 37]
    assert all(p["options"]["temperature"] > 0 for p in sent)
    assert (verdict.majority, verdict.unanimous, verdict.agrees("review")) == (
        "review",
        False,
        True,
    )
    client, _ = _client(["review", ConnectionError("down")])
    assert shadow_verdict("case file", client, 2).majority is None


def test_shadow_verdicts_never_change_a_decision(
    tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The opposite of what code decides for each fixture case.
    client, sent = _client(lambda text: "explained" if "tunnel.example.com" in text else "review")
    monkeypatch.setattr(cli, "OllamaClient", lambda config: client)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(store_path))

    feed = FIXTURES / "ioc_matches_synthetic.json"
    assert main([str(feed), "--no-live", "--shadow", "3", "--out", "out"]) == 0

    data = json.loads((tmp_path / "out" / "ioc_matches_synthetic.json").read_text("utf-8"))
    cases = {c["indicator"]: c for c in data["cases"]}
    assert cases["tunnel.example.com"]["disposition"] == "review"
    assert cases["tunnel.example.com"]["shadow"]["agrees"] is False
    assert cases["9.9.9.9:443"]["disposition"] == "explained"
    assert cases["9.9.9.9:443"]["shadow"]["agrees"] is False
    assert all(
        "[Decision" not in p["messages"][1]["content"] for p in sent if p["format"] == SHADOW_SCHEMA
    )
    markdown = (tmp_path / "out" / "ioc_matches_synthetic.md").read_text("utf-8")
    assert (
        "### Blind model verdicts (never applied)" in markdown
        and "disagrees, stable | 2" in markdown
    )


def test_shadow_needs_the_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(tmp_path / "x.duckdb"))
    assert main([str(FIXTURES / "ioc_matches_synthetic.json"), "--shadow", "2", "--no-model"]) == 2
