from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from network_behaviour.config import ConfigurationError

from ioc_report.casefile import Observed
from ioc_report.model import (
    REPLY_SCHEMA,
    ModelError,
    OllamaClient,
    OllamaConfig,
    confidence_as_evidence,
    host_state_words,
    unattributed_labels,
    unsupported_shapes,
    unverified_numbers,
)

NOTHING = Observed(held_open=False, regular=False, large_transfer=False)
EVERYTHING = Observed(held_open=True, regular=True, large_transfer=True)
CASE_FILE = (
    "[IOC feed, not re-queried] 1,371 matched minute(s) on 2 day(s): 2026-09-15..2026-09-16.\n"
    "[IOC feed] traffic in the matched minutes: 1.56 MB received, 14.3 KB sent."
)


def _reply(summary: str = "One brief visit to the flagged domain.") -> dict[str, Any]:
    return {"message": {"content": json.dumps({"summary": summary})}, "prompt_eval_count": 900}


class _Transport:
    def __init__(self, replies: list[dict[str, Any] | Exception]) -> None:
        self._replies: Iterator[dict[str, Any] | Exception] = iter(replies)
        self.requests: list[tuple[str, dict[str, Any] | None]] = []

    def __call__(self, url: str, body: bytes | None, timeout: float) -> bytes:
        self.requests.append((url, json.loads(body) if body else None))
        reply = next(self._replies)
        if isinstance(reply, Exception):
            raise reply
        return json.dumps(reply).encode()


def _client(*replies: dict[str, Any] | Exception) -> tuple[OllamaClient, _Transport]:
    transport = _Transport(list(replies))
    return OllamaClient(OllamaConfig(), transport), transport


def test_only_a_loopback_model_server_is_accepted() -> None:
    assert OllamaConfig(url="http://localhost:11434").url
    with pytest.raises(ConfigurationError, match="loopback"):
        OllamaConfig(url="https://ollama.example.com")


def test_numbers_must_come_from_the_case_file_allowing_rounding() -> None:
    assert unverified_numbers("1371 minutes, about 1.6 MB, on 2026-09-15", CASE_FILE) == []
    assert unverified_numbers("one of 3 runs", CASE_FILE) == []
    assert unverified_numbers("it moved 42 MB over 17 hours", CASE_FILE) == ["17", "42"]


def test_host_state_wording_is_caught_but_attribution_is_not() -> None:
    assert host_state_words("The host is compromised and infected.") == ["compromised", "infected"]
    assert host_state_words("ThreatFox lists the indicator as win.nanocore malware.") == []


def test_held_open_and_schedule_claims_need_a_measurement() -> None:
    claim = "The host kept a held-open connection and was beaconing."
    assert len(unsupported_shapes(claim, NOTHING)) == 2
    assert unsupported_shapes(claim, EVERYTHING) == []
    assert unsupported_shapes("There was no held-open connection.", NOTHING) == []
    assert unsupported_shapes("C2 clients usually beacon on a schedule.", NOTHING) == []


@pytest.mark.parametrize(
    "sentence",
    [
        # The five withheld cases of the 2026-10-07 run, verbatim apart from redaction.
        "No long flows, held-open connections, or regular schedules were observed.",
        "There is no evidence of a held-open connection, regular schedule, or large data transfer, "
        "which aligns with ordinary browsing behavior.",
        "There were no long flows, held-open connections, or regular schedules observed, and the "
        "match day is not retained or published.",
        "No long flows, held-open connections, or regular schedules were observed, and the contact "
        "occurred only once on a single day with no prior or subsequent activity.",
        "Regular schedules were not observed.",
        "Regular schedule: no.",
    ],
)
def test_a_negated_list_or_a_trailing_negation_is_not_a_claim(sentence: str) -> None:
    assert unsupported_shapes(sentence, NOTHING) == []


@pytest.mark.parametrize(
    "sentence",
    [
        "There was no long flow, and the host kept a held-open connection.",
        "No large transfer was seen but the contact followed a regular schedule.",
        "No other host matched; the host was beaconing every hour.",
    ],
)
def test_a_negation_in_another_clause_excuses_nothing(sentence: str) -> None:
    assert len(unsupported_shapes(sentence, NOTHING)) == 1


def test_a_negation_excuses_only_the_claim_right_after_it() -> None:
    sentence = "It moved a small data transfer consistent with a page load, and no held-open link."

    problems = unsupported_shapes(sentence, EVERYTHING)

    assert problems == ["says 'small data transfer' but a transfer of about 1 MB or more was seen"]
    assert unsupported_shapes(sentence, NOTHING) == []
    assert unsupported_shapes("The volume is not a page load.", EVERYTHING) == []


def test_the_request_asks_for_a_summary_only_deterministically() -> None:
    client, transport = _client(_reply())

    client.chat([{"role": "user", "content": CASE_FILE}])

    url, payload = transport.requests[0]
    assert url.endswith("/api/chat") and payload is not None
    assert payload["format"] == REPLY_SCHEMA
    assert list(REPLY_SCHEMA["properties"]) == ["summary"]
    assert payload["options"]["temperature"] == 0
    assert payload["stream"] is False


@pytest.mark.parametrize(
    "sentence",
    [
        "The host contacted a botnet command-and-control server at the address.",
        "This activity is consistent with a botnet command-and-control interaction.",
        "This activity aligns with a payload_delivery threat, though no context is available.",
    ],
)
def test_a_threat_label_on_the_host_activity_is_caught(sentence: str) -> None:
    assert len(unattributed_labels(sentence)) == 1


@pytest.mark.parametrize(
    "sentence",
    [
        "ThreatFox lists the indicator as a botnet command-and-control server.",
        "This does not match the typical pattern of a botnet command-and-control server.",
        "It is consistent with ordinary browsing rather than malicious behavior.",
        "This activity is not indicative of malicious behavior.",
        "The usage pattern matches that of normal, non-malicious activity.",
    ],
)
def test_an_attributed_or_negated_label_passes(sentence: str) -> None:
    assert unattributed_labels(sentence) == []


def test_confidence_may_be_mentioned_but_not_used_as_evidence() -> None:
    assert confidence_as_evidence("It has a 75% confidence, suggesting malicious intent.")
    assert not confidence_as_evidence("ThreatFox lists it with 100% confidence, but it was brief.")
    # The 2026-10-07 false alarm: the inference sits in another, negated clause.
    assert not confidence_as_evidence(
        "ThreatFox lists the indicator with 100% confidence, but no evidence shows a large or "
        "repeated transfer that would suggest malicious activity."
    )


def test_a_missing_model_fails_before_the_first_case() -> None:
    client, _ = _client({"models": [{"name": "other:1b"}]})
    with pytest.raises(ModelError, match="not pulled"):
        client.require_model()
