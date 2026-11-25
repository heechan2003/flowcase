"""RDAP registration dates: parsed, cached, asked about once, and never fetched unless enabled."""

from __future__ import annotations

import json
import urllib.error
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path

from ioc_report.registration import (
    BOOTSTRAP_URL,
    ERROR,
    NO_SERVICE,
    NOT_FOUND,
    OK,
    RdapLookup,
    enabled,
    registration_date,
)

NOW = datetime(2026, 10, 22, tzinfo=UTC)
BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.example-registry.test/"]]]}


class _Get:
    def __init__(self, answers: dict[str, bytes | Exception]) -> None:
        self.answers = answers
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> bytes:
        self.urls.append(url)
        answer = self.answers[url]
        if isinstance(answer, Exception):
            raise answer
        return answer


def _domain(date: str) -> bytes:
    events = [{"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
              {"eventAction": "registration", "eventDate": date}]  # fmt: skip
    return json.dumps({"objectClassName": "domain", "events": events}).encode()


def _not_found(url: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, 404, "Not Found", None, None)  # type: ignore[arg-type]


def test_only_an_explicit_setting_turns_lookups_on() -> None:
    assert enabled({"NAME_LOOKUP": "rdap"}) and enabled({"NAME_LOOKUP": " RDAP "})
    assert not enabled({}) and not enabled({"NAME_LOOKUP": "yes"})


def test_dates_come_from_the_registration_event() -> None:
    assert registration_date(json.loads(_domain("2014-03-02T10:00:00Z"))) == datetime(
        2014, 3, 2, 10, tzinfo=UTC
    )
    assert registration_date({"events": [{"eventAction": "expiration"}]}) is None
    assert registration_date("not an object") is None


def test_each_domain_is_asked_once_and_answers_are_cached(tmp_path: Path) -> None:
    base = "https://rdap.example-registry.test/domain/"
    get = _Get(
        {
            BOOTSTRAP_URL: json.dumps(BOOTSTRAP).encode(),
            f"{base}old-site.com": _domain("2014-03-02T10:00:00Z"),
            f"{base}missing.net": _not_found(f"{base}missing.net"),
        }
    )
    lookup = RdapLookup(tmp_path, get, now=lambda: NOW, sleep=lambda _s: None)

    found = lookup.lookup(["old-site.com", "missing.net", "local-shop.zz", "old-site.com."])

    assert found["old-site.com"].status == OK
    assert found["old-site.com"].registered == datetime(2014, 3, 2, 10, tzinfo=UTC)
    assert found["missing.net"].status == NOT_FOUND
    assert found["local-shop.zz"].status == NO_SERVICE
    assert lookup.requests == 3  # the bootstrap file and two registries; .zz has no service
    again = RdapLookup(tmp_path, _Get({}), now=lambda: NOW, sleep=lambda _s: None)
    assert again.lookup(["old-site.com", "missing.net", "local-shop.zz"]) == found
    assert again.requests == 0


def test_a_failed_lookup_is_unknown_and_retried_next_run(tmp_path: Path) -> None:
    url = "https://rdap.example-registry.test/domain/flaky.com"
    get = _Get({BOOTSTRAP_URL: json.dumps(BOOTSTRAP).encode(), url: OSError("timed out")})

    found = RdapLookup(tmp_path, get, now=lambda: NOW, sleep=lambda _s: None).lookup(["flaky.com"])

    assert found["flaky.com"].status == ERROR and found["flaky.com"].registered is None
    retry = _Get({url: _domain("2020-01-01T00:00:00Z")})
    assert (
        RdapLookup(tmp_path, retry, now=lambda: NOW, sleep=lambda _s: None)
        .lookup(["flaky.com"])["flaky.com"]
        .status
        == OK
    )
    assert retry.urls == [url]  # the bootstrap file came from the cache


def test_a_rate_limit_is_waited_out_and_requests_to_one_server_are_spaced(tmp_path: Path) -> None:
    base = "https://rdap.example-registry.test/domain/"
    headers = Message()
    headers["Retry-After"] = "7"
    limited = urllib.error.HTTPError(f"{base}busy.com", 429, "Too Many Requests", headers, None)
    answers: dict[str, list[bytes | Exception]] = {
        BOOTSTRAP_URL: [json.dumps(BOOTSTRAP).encode()],
        f"{base}busy.com": [limited, _domain("2019-05-05T00:00:00Z")],
        f"{base}calm.com": [_domain("2018-01-01T00:00:00Z")],
    }
    slept: list[float] = []

    def get(url: str, timeout: float) -> bytes:
        answer = answers[url].pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    lookup = RdapLookup(tmp_path, get, now=lambda: NOW, sleep=slept.append, clock=lambda: 100.0)
    found = lookup.lookup(["busy.com", "calm.com"])

    assert found["busy.com"].status == OK and found["calm.com"].status == OK
    assert 7.0 in slept  # the server's Retry-After
    assert slept.count(1.5) >= 2  # spacing between requests to the same registry


def test_a_server_that_keeps_rate_limiting_is_left_alone_for_the_run(tmp_path: Path) -> None:
    base = "https://rdap.example-registry.test/domain/"
    asked: list[str] = []

    def get(url: str, timeout: float) -> bytes:
        asked.append(url)
        if url == BOOTSTRAP_URL:
            return json.dumps(BOOTSTRAP).encode()
        raise urllib.error.HTTPError(url, 429, "Too Many Requests", Message(), None)

    lookup = RdapLookup(tmp_path, get, now=lambda: NOW, sleep=lambda _s: None)
    found = lookup.lookup(["one.com", "two.com", "three.com"])

    assert {age.status for age in found.values()} == {ERROR}
    assert asked.count(f"{base}one.com") == 4  # the first try and three retries
    assert f"{base}two.com" not in asked and f"{base}three.com" not in asked
