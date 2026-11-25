"""The writer: checked, retried, withheld and cached, with no network and no model."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ioc_report.casefile import Observed
from ioc_report.model import OllamaClient, OllamaConfig
from ioc_report.narrative import CASE_FIELDS, Narrative, Writer, check_prose, restore
from ioc_report.rules import EXPLAINED, REVIEW

NOTHING = Observed(held_open=False, regular=False, large_transfer=False)
DIGEST = (
    "Threat:\n- [ThreatFox, about the indicator only] 9.9.9.9:443 (ip:port) is listed as "
    "win.nanocore, threat type botnet_cc.\nHost:\n- [Retained history] the address HOST appears "
    "on 12 retained day(s).\nWhat happened:\n- [IOC feed] 1 minute(s) on 2026-09-14, 3.2 KB "
    "received, over UDP to quic.example.net.\nDecision:\n- [Decision, by code] explained."
)
GOOD = {
    "threat": "ThreatFox lists 9.9.9.9:443 as win.nanocore, a remote-access trojan.",
    "host": "HOST appears on 12 retained days.",
    "what_happened": "One minute over UDP to quic.example.net, 3.2 KB received.",
    "reading": "Code explained the contact: UDP cannot be the family's TCP-only channel.",
}


def _reply(fields: dict[str, str], tokens: int = 900) -> dict[str, Any]:
    return {"message": {"content": json.dumps(fields)}, "prompt_eval_count": tokens}


class _Transport:
    def __init__(self, replies: list[dict[str, Any] | Exception]) -> None:
        self._replies: Iterator[dict[str, Any] | Exception] = iter(replies)
        self.requests: list[dict[str, Any]] = []

    def __call__(self, url: str, body: bytes | None, timeout: float) -> bytes:
        self.requests.append(json.loads(body) if body else {})
        reply = next(self._replies)
        if isinstance(reply, Exception):
            raise reply
        return json.dumps(reply).encode()


def _writer(
    *replies: dict[str, Any] | Exception, cache: Path | None = None
) -> tuple[Writer, _Transport]:
    transport = _Transport(list(replies))
    return Writer(OllamaClient(OllamaConfig(), transport), cache), transport


def test_a_checked_overview_stands_with_every_part() -> None:
    writer, transport = _writer(_reply(GOOD))

    found = writer.case(DIGEST, NOTHING, EXPLAINED, "overview 1/1")

    assert found.by_model and found.attempts == 1
    assert tuple(found.fields) == CASE_FIELDS
    assert transport.requests[0]["format"]["required"] == list(CASE_FIELDS)
    assert transport.requests[0]["options"]["temperature"] == 0


def test_a_failed_check_is_retried_with_the_problems_listed() -> None:
    writer, transport = _writer(_reply({**GOOD, "host": "HOST moved 42 MB."}), _reply(GOOD))

    found = writer.case(DIGEST, NOTHING, EXPLAINED, "overview 1/1")

    assert found.by_model and found.attempts == 2
    assert "42" in transport.requests[1]["messages"][-1]["content"]


def test_text_failing_every_attempt_is_withheld_and_code_stands() -> None:
    bad = _reply({**GOOD, "reading": "The host is compromised."})
    writer, _ = _writer(bad, bad, bad)

    found = writer.case(DIGEST, NOTHING, EXPLAINED, "overview 1/1")

    assert not found.by_model and found.written_by == "code" and found.problems


def test_a_model_that_cannot_answer_or_overflows_its_window_writes_nothing() -> None:
    writer, _ = _writer(OSError("down"), {"message": {"content": "not json"}}, OSError("down"))
    assert not writer.case(DIGEST, NOTHING, EXPLAINED, "x").by_model
    writer, _ = _writer(_reply(GOOD, tokens=int(OllamaConfig().num_ctx * 0.95)))
    assert not writer.case(DIGEST, NOTHING, EXPLAINED, "x").by_model


def test_a_cached_reply_is_never_asked_twice(tmp_path: Path) -> None:
    first, transport = _writer(_reply(GOOD), cache=tmp_path)
    first.case(DIGEST, NOTHING, EXPLAINED, "x")

    again, unused = _writer(cache=tmp_path)
    found = again.case(DIGEST, NOTHING, EXPLAINED, "x")

    assert found.cached and found.fields == GOOD
    assert len(transport.requests) == 1 and not unused.requests


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("It reached evil.example.org.", "names that are not in the input"),
        ("It reached 203.0.113.9.", "addresses that are not in the input"),
        ("Kept by K1.", "rule codes"),
        ("The host is benign.", "benign or safe"),
        ("The host is a Windows workstation.", "says what the host is"),
    ],
)
def test_invented_names_codes_and_host_claims_are_caught(text: str, problem: str) -> None:
    assert any(problem in found for found in check_prose(text, DIGEST, NOTHING))


def test_prose_must_not_argue_with_the_decision() -> None:
    assert check_prose("This case needs further review.", DIGEST, NOTHING, EXPLAINED)
    assert check_prose("The match can be safely dismissed.", DIGEST, NOTHING, REVIEW)
    assert not check_prose("It does not need review.", DIGEST, NOTHING, EXPLAINED)
    assert not check_prose("The services used are typical of a Windows PC.", DIGEST, NOTHING)


def test_the_host_token_is_restored() -> None:
    found = restore(Narrative("m", {"host": "HOST appears often."}), {"HOST": "192.0.2.10"})
    assert found.fields["host"] == "192.0.2.10 appears often."
