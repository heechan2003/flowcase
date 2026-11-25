"""The evaluation harness, tested for free: no network, no model."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from evals.cases import build_cases
from evals.run import run_model
from evals.score import grounding_problems, score
from ioc_report.model import Reply

CASES = build_cases()


def test_every_policy_label_is_what_the_rules_decide() -> None:
    for case in CASES:
        if case.group == "knowledge":
            assert case.code == "review", case.id  # where a model would have to add value
        else:
            assert case.code == case.expected, case.id
    assert sum(1 for c in CASES if c.group == "knowledge" and c.expected != c.code) == 2


def test_blind_files_carry_no_decision_and_no_host() -> None:
    for case in CASES:
        text = case.case_file
        for leak in ("[Decision", "explained by", "kept by", "not explained", "192.0.2.10"):
            assert leak not in text, (case.id, leak)
        assert not re.search(r"\b[EK][1-6]\b", text), case.id


def test_a_platform_is_never_shown_as_established() -> None:
    tenant = next(c for c in CASES if c.id == "S2").case_file
    assert "not applicable: a shared platform" in tenant
    assert "CASE_STUDY §15): yes" not in tenant


class _Client:
    """Answers `review` for everything; each call costs 0.30 and could cost 0.50 at worst."""

    model = "fake"
    num_ctx = 100_000
    label = "fake"
    last_cost = 0.0

    def __init__(self) -> None:
        self.calls = 0

    def require_model(self) -> None: ...

    def chat(self, messages: list[dict[str, str]]) -> Reply:
        raise NotImplementedError

    def worst_case_cost(self, prompt_chars: int) -> float:
        return 0.5

    def complete(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        *,
        temperature: float = 0.0,
        seed: int | None = None,
    ) -> tuple[dict[str, Any], str, int, float]:
        self.calls += 1
        self.last_cost = 0.3
        return {"reasoning": "r", "verdict": "review"}, "{}", 100, 0.1


def test_the_budget_stops_a_run_and_the_cache_never_pays_twice(tmp_path: Path) -> None:
    cache = tmp_path / "fake.jsonl"
    client = _Client()

    first = run_model(CASES[:2], client, 3, budget=1.0, cache=cache)

    # 0.3 + 0.5 fits, 0.6 + 0.5 does not: two calls, then a clean stop.
    assert (client.calls, first["calls"]) == (2, 2) and "budget" in first["stopped"]
    second = run_model(CASES[:2], client, 3, budget=10.0, cache=cache)
    assert second["calls"] == 4 and client.calls == 6  # only the 4 not yet answered


def _records(answer: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "case_id": case.id,
            "sample": sample,
            "verdict": answer.get(case.id, case.expected),
            "reasoning": "r",
        }
        for case in CASES
        for sample in range(3)
    ]


def test_a_model_matching_the_policy_passes_and_one_clearing_threats_fails() -> None:
    perfect = score("perfect", CASES, _records({}), 3)
    assert all(ok for _value, ok in perfect.criteria.values())
    assert perfect.outcome.startswith("verdict-capable")

    reckless = score("reckless", CASES, _records({"P1b": "explained", "S6": "explained"}), 3)
    assert not reckless.criteria["safety"][1] and reckless.outcome == "not verdict-capable"

    one_miss = score("one", CASES, _records({"S6": "explained"}), 3)
    assert one_miss.criteria["safety"][1]  # the user's bar: at most one miss


def test_failed_replies_never_make_a_majority() -> None:
    records = [r for r in _records({}) if not (r["case_id"] == "P1a" and r["sample"] > 0)]
    result = score("flaky", CASES, records, 3)
    p1a = next(item for item in result.cases if item.case.id == "P1a")
    assert p1a.majority is None and not p1a.unanimous


def test_grounding_allows_naming_the_family_channel_but_not_invented_numbers() -> None:
    case = next(case for case in build_cases() if case.id == "S6")
    channel = "NanoCore's command-and-control channel carries no TLS, so this is review."
    assert grounding_problems(channel, case.case_file, case.observed) == []
    invented = "The host sent 987654 bytes and is infected."
    problems = grounding_problems(invented, case.case_file, case.observed)
    assert any("987654" in problem for problem in problems)
    assert any("infected" in problem for problem in problems)


def test_the_set_has_the_planned_shape() -> None:
    groups = {
        g: sum(1 for c in CASES if c.group == g) for g in ("must_clear", "must_review", "knowledge")
    }
    assert groups == {"must_clear": 9, "must_review": 14, "knowledge": 4}
    assert len({c.pair for c in CASES if c.pair}) == 8


def test_only_the_shared_network_twin_turns_on_the_network() -> None:
    by_id = {case.id: case for case in CASES}
    assert "by design: shared hosting" in by_id["P8a"].case_file
    assert "not shown to be shared" in by_id["P8b"].case_file
    assert "by design" not in by_id["P8b"].case_file
    assert by_id["P8a"].code == "explained" and by_id["P8b"].code == "review"


# The synthetic blind case files the current prompt version was evaluated on. A change to what the
# model reads is a new test of the model: re-run evals/ ("How we proceed"), then update this.
# Evaluation 1f318da0f278-10ab2a7040d7 (2026-11-06) passed every bar on these files as first
# written. Two renames followed, and nothing else changed: the long-flow table in one line of each
# file ("long_flows only holds transfers of about 1 MB or more"), and the measured-facts citations
# ("SOURCE_FACTS §N" became "CASE_STUDY §N", the same sections). The synthetic set is re-run on
# this text before its scorecard is quoted.
EVALUATED_CASE_FILES = "dc0e9ce2ac173ef05565e906c9798b51baf6692c60b5dc794558c5feba15d373"


def test_the_blind_case_files_are_the_ones_evaluated() -> None:
    text = "\n\x00\n".join(case.case_file for case in CASES)
    assert hashlib.sha256(text.encode()).hexdigest() == EVALUATED_CASE_FILES, (
        "the blind case files changed: re-run evals/ before trusting the scorecard"
    )
