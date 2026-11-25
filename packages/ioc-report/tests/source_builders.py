"""A source DuckDB file with the four tables, typed as the triage contract requires, for tests that
run the real queries. Hosts use documentation ranges; servers are public resolvers, as in
`conftest.py`. Nothing here is a real indicator."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
from network_behaviour.source.zeek.loader import create_source_tables


def utc(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def activity(
    time: str,
    host: str = "192.0.2.10",
    server: str = "1.1.1.1",
    *,
    port: int = 443,
    transport: int = 6,
    sni: str = "",
    dns: str = "",
    root: str = "",
    up: int = 1000,
    down: int = 5000,
    flows: int = 1,
    asn: str | None = "13335",
) -> tuple[Any, ...]:
    application = root.split(".")[0] if root else ""
    return (
        utc(time), host, server, port, transport, application, "ssl", root, sni, dns, asn,
        up, down, up // 100 + 1, down // 100 + 1, flows,
    )  # fmt: skip


def long_flow(
    flow_id: str,
    start: str,
    finish: str,
    host: str = "192.0.2.10",
    server: str = "1.1.1.1",
    *,
    port: int = 443,
    up: int = 1_500_000,
    down: int = 2_000_000,
    initiator: str = "client",
) -> tuple[Any, ...]:
    first, last = utc(start), utc(finish)
    return (
        flow_id, first, last, (last - first).total_seconds(), host, server, 50000, port, 6,
        up, down, initiator,
    )  # fmt: skip


def write_source(
    path: Path,
    rows: Sequence[tuple[Any, ...]] = (),
    flows: Sequence[tuple[Any, ...]] = (),
) -> Path:
    with duckdb.connect(str(path)) as connection:
        connection.execute("SET TimeZone = 'UTC'")
        create_source_tables(connection)
        if rows:
            connection.executemany(
                f"INSERT INTO flow.activity_1m VALUES ({', '.join('?' * 16)})", list(rows)
            )
        if flows:
            connection.executemany(
                f"INSERT INTO flow.long_flows VALUES ({', '.join('?' * 12)})", list(flows)
            )
    return path
