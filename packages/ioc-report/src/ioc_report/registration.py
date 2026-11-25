"""When a name was registered, from RDAP: opt-in, cached, registered domains only.

Off unless `NAME_LOOKUP=rdap`. Only a registered domain ever leaves the machine (never a full name,
an address or any case text), sent to the RDAP server IANA's bootstrap file lists for its top-level
domain. Every answer is cached under the git-ignored data directory, so a domain is asked about once
a month at most. A domain whose registry runs no RDAP service, or whose lookup fails, has an unknown
age, and an unknown age changes nothing: the E3 check it feeds can only take an explanation away.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_MAX_AGE = timedelta(days=7)
RESULT_MAX_AGE = timedelta(days=30)
TIMEOUT_SECONDS = 20.0
DEFAULT_CACHE_DIR = Path("data/rdap")
USER_AGENT = "ioc-report/0.1 (university network research; RDAP registration dates only)"
RETRIES = 3
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_RETRY_WAIT_SECONDS = 60.0
SERVER_SPACING_SECONDS = 1.5
"""Least time between two requests to one RDAP server: registries rate-limit, auDA's strictly."""

OK = "ok"
NO_SERVICE = "no-service"
NOT_FOUND = "not-found"
NO_DATE = "no-date"
ERROR = "error"

Get = Callable[[str, float], bytes]
"""(url, timeout) -> response body. Raises HTTPError/URLError/OSError."""


def _urllib(url: str, timeout: float) -> bytes:
    headers = {"Accept": "application/rdap+json", "User-Agent": USER_AGENT}
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload: bytes = response.read()
        return payload


def enabled(env: Mapping[str, str]) -> bool:
    return env.get("NAME_LOOKUP", "").strip().lower() == "rdap"


@dataclass(frozen=True, slots=True)
class NameAge:
    domain: str
    registered: datetime | None
    status: str
    """`ok`, `no-service`, `not-found`, `no-date` or `error`."""

    def days_before(self, moment: datetime) -> float | None:
        """Days from registration to `moment`; None when unknown or registered after it (the
        domain was registered again since, so its age at that moment is unknown)."""
        if self.registered is None or self.registered > moment:
            return None
        return (moment - self.registered).total_seconds() / 86400

    @property
    def unknown_reason(self) -> str:
        return {
            NO_SERVICE: "its registry lists no RDAP service",
            NOT_FOUND: "RDAP has no record of it",
            NO_DATE: "its RDAP record gives no registration date",
            ERROR: "the RDAP lookup failed",
        }.get(self.status, "")


class RdapLookup:
    def __init__(
        self,
        cache_dir: Path = DEFAULT_CACHE_DIR,
        get: Get = _urllib,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._dir = cache_dir
        self._get = get
        self._now = now
        self._sleep = sleep
        self._clock = clock
        self._last: dict[str, float] = {}
        self._limited: set[str] = set()
        """Servers still rate-limiting after every retry: not asked again in this run."""
        self.requests = 0
        """Requests sent in this run, the bootstrap file included."""

    def lookup(self, domains: Iterable[str]) -> dict[str, NameAge]:
        wanted = sorted({domain.strip().lower().rstrip(".") for domain in domains if domain})
        if not wanted:
            return {}
        cache = self._read("registrations.json")
        found: dict[str, NameAge] = {}
        servers: dict[str, list[str]] | None = None
        for domain in wanted:
            cached = cache.get(domain)
            if isinstance(cached, dict) and self._fresh(cached.get("fetched_at"), RESULT_MAX_AGE):
                found[domain] = _from_cache(domain, cached)
                continue
            if servers is None:
                servers = self._bootstrap()
            age = self._ask(domain, servers)
            found[domain] = age
            if age.status != ERROR:
                cache[domain] = {
                    "registered": age.registered.isoformat() if age.registered else None,
                    "status": age.status,
                    "fetched_at": self._now().isoformat(),
                }
        self._write("registrations.json", cache)
        return found

    def _ask(self, domain: str, servers: Mapping[str, list[str]]) -> NameAge:
        bases = _servers_for(domain, servers)
        if not bases:
            return NameAge(domain, None, NO_SERVICE)
        url = f"{bases[0].rstrip('/')}/domain/{domain}"
        host = urlsplit(url).netloc
        if host in self._limited:
            return NameAge(domain, None, ERROR)
        for attempt in range(RETRIES + 1):
            try:
                body = json.loads(self._fetch(url))
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return NameAge(domain, None, NOT_FOUND)
                if exc.code not in RETRY_STATUSES or attempt == RETRIES:
                    if exc.code == 429:
                        self._limited.add(host)
                    return NameAge(domain, None, ERROR)
                self._sleep(_retry_wait(exc, attempt))
            except (OSError, ValueError):
                return NameAge(domain, None, ERROR)
        registered = registration_date(body)
        return NameAge(domain, registered, OK if registered else NO_DATE)

    def _fetch(self, url: str) -> bytes:
        """One request, spaced from the last one to the same server."""
        host = urlsplit(url).netloc
        if (last := self._last.get(host)) is not None:
            wait = SERVER_SPACING_SECONDS - (self._clock() - last)
            if wait > 0:
                self._sleep(wait)
        self.requests += 1
        try:
            return self._get(url, TIMEOUT_SECONDS)
        finally:
            self._last[host] = self._clock()

    def _bootstrap(self) -> dict[str, list[str]]:
        cached = self._read("bootstrap.json")
        if self._fresh(cached.get("fetched_at"), BOOTSTRAP_MAX_AGE) and "servers" in cached:
            return _server_map(cached["servers"])
        try:
            body = json.loads(self._fetch(BOOTSTRAP_URL))
            servers = {
                str(tld).lower(): [str(url) for url in service[1]]
                for service in body.get("services", [])
                for tld in service[0]
            }
        except (OSError, ValueError, TypeError, IndexError, AttributeError):
            return _server_map(cached.get("servers", {}))
        self._write("bootstrap.json", {"fetched_at": self._now().isoformat(), "servers": servers})
        return servers

    def _fresh(self, stamp: object, max_age: timedelta) -> bool:
        try:
            when = datetime.fromisoformat(str(stamp))
        except ValueError:
            return False
        return self._now() - when < max_age

    def _read(self, name: str) -> dict[str, object]:
        path = self._dir / name
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, name: str, data: Mapping[str, object]) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        (self._dir / name).write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")


def registration_date(body: object) -> datetime | None:
    """The `registration` event of an RDAP domain object (RFC 9083 §4.5)."""
    if not isinstance(body, dict):
        return None
    for event in body.get("events", []) or []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            raw = str(event.get("eventDate", "")).replace("Z", "+00:00")
            try:
                value = datetime.fromisoformat(raw)
            except ValueError:
                return None
            return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return None


def _retry_wait(exc: urllib.error.HTTPError, attempt: int) -> float:
    """The server's Retry-After when it gives seconds, else a doubling wait; never over a minute."""
    header = exc.headers.get("Retry-After") if exc.headers is not None else None
    try:
        wait = float(header) if header is not None else 2.0 * 2**attempt
    except ValueError:
        wait = 2.0 * 2**attempt
    return min(max(wait, 0.0), MAX_RETRY_WAIT_SECONDS)


def _servers_for(domain: str, servers: Mapping[str, list[str]]) -> list[str]:
    """The longest top-level suffix of `domain` that the bootstrap file lists (RFC 9224 §4)."""
    labels = domain.split(".")
    for start in range(1, len(labels)):
        if (found := servers.get(".".join(labels[start:]))) is not None:
            return found
    return []


def _server_map(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    return {
        str(tld): [str(url) for url in urls]
        for tld, urls in value.items()
        if isinstance(urls, list)
    }


def _from_cache(domain: str, cached: Mapping[str, object]) -> NameAge:
    raw = cached.get("registered")
    registered = datetime.fromisoformat(str(raw)) if raw else None
    return NameAge(domain, registered, str(cached.get("status", ERROR)))
