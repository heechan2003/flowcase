"""Synthetic Zeek logs for the source tests: documentation-range servers, `.test` names, 10.0.0.0/8
hosts. Nothing here is real traffic."""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import duckdb
import pytest

DAY = date(2026, 7, 10)
LOCAL = "10.0.0.0/8"


def at(clock: str, day: date = DAY) -> float:
    """Epoch seconds for `HH:MM:SS` on `day`, UTC."""
    hour, minute, second = (int(part) for part in clock.split(":"))
    return datetime(day.year, day.month, day.day, hour, minute, second, tzinfo=UTC).timestamp()


def conn(
    uid: str,
    ts: float,
    orig: str,
    resp: str,
    *,
    orig_p: int = 50000,
    resp_p: int = 443,
    proto: str = "tcp",
    service: str | None = "ssl",
    duration: float | None = 1.0,
    orig_bytes: int = 100,
    resp_bytes: int = 200,
    orig_pkts: int = 2,
    resp_pkts: int = 3,
    **extra: Any,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "ts": ts,
        "uid": uid,
        "id.orig_h": orig,
        "id.orig_p": orig_p,
        "id.resp_h": resp,
        "id.resp_p": resp_p,
        "proto": proto,
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        **extra,
    }
    if service is not None:
        record["service"] = service
    return record


def dns(
    uid: str,
    ts: float,
    client: str,
    resolver: str,
    query: str,
    answers: Iterable[str] = (),
    ttls: Iterable[float] = (),
    *,
    rtt: float | None = 0.02,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "ts": ts,
        "uid": uid,
        "id.orig_h": client,
        "id.orig_p": 53000,
        "id.resp_h": resolver,
        "id.resp_p": 53,
        "query": query,
        "answers": list(answers),
        "TTLs": list(ttls),
    }
    if rtt is not None:
        record["rtt"] = rtt
        record["rcode"] = 0
    return record


def write_json(
    folder: Path, kind: str, records: Iterable[Mapping[str, Any]], *, gz: bool = True
) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (f"{kind}.log.gz" if gz else f"{kind}.log")
    lines = "".join(json.dumps(record) + "\n" for record in records)
    if gz:
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write(lines)
    else:
        path.write_text(lines, encoding="utf-8")
    return path


def write_tsv(folder: Path, kind: str, fields: list[str], rows: Iterable[list[str]]) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{kind}.log"
    header = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        f"#path\t{kind}",
        "#fields\t" + "\t".join(fields),
        "#types\t" + "\t".join("string" for _ in fields),
    ]
    body = ["\t".join(row) for row in rows]
    path.write_text("\n".join([*header, *body, "#close\t2026-07-11-00-00-00"]) + "\n")
    return path


Query = Callable[[str], list[tuple[Any, ...]]]


@pytest.fixture
def query(tmp_path: Path) -> Query:
    """Run SQL against the test's source file, in UTC."""

    def run(sql: str) -> list[tuple[Any, ...]]:
        with duckdb.connect(str(tmp_path / "source.duckdb"), read_only=True) as connection:
            connection.execute("SET TimeZone = 'UTC'")
            return connection.execute(sql).fetchall()

    return run


@pytest.fixture
def synthetic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETWORK_BEHAVIOUR_SYNTHETIC", "1")
