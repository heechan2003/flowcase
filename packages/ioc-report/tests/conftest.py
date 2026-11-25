"""Shared synthetic inputs.

Hosts use documentation ranges. Server addresses are public resolvers (1.1.1.1, 9.9.9.9), because
`is_public_destination` rejects documentation ranges and a non-public server never forms a service.
Nothing here is a real indicator.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import duckdb
import pytest
from network_behaviour.storage.repository import DuckDbStore, StorageConfig

FIXTURES = Path(__file__).with_name("fixtures")
MIGRATIONS = Path(
    os.environ.get(
        "NETWORK_BEHAVIOUR_MIGRATION_DIR",
        Path(__file__).resolve().parents[2] / "triage" / "sql" / "migrations",
    )
)
NORMALIZATION = "service-id-v1/category-id-v1/port-groups-v1/bitmap-288-lsb-v1/tldextract-5.3.1"


def minute_row(
    time: str,
    host: str = "192.0.2.10",
    server: str = "1.1.1.1",
    *,
    port: int = 443,
    transport: int = 6,
    sni: str = "",
    dns: str = "",
    root: str = "",
    down: int = 5000,
    up: int = 1000,
    asn: str = "13335",
) -> dict[str, Any]:
    return {
        "time": time,
        "client_ip": host,
        "server_ip": server,
        "server_port": port,
        "transport_protocol": transport,
        "sni": sni,
        "dns": dns,
        "root_domain": root,
        "down_bytes": down,
        "up_bytes": up,
        "flow_count": 1,
        "asn": asn,
        "asn_organization": "Example Network",
        "country": "Australia",
    }


def long_flow(
    flow_id: str = "00000000-0000-4000-8000-000000000001",
    *,
    duration: float = 7200.0,
    host: str = "192.0.2.10",
    server: str = "1.1.1.1",
    start: str = "2026-09-15 09:00:00.000000",
    finish: str = "2026-09-15 11:00:00.000000",
    port: int = 443,
    protocol: int = 6,
) -> dict[str, Any]:
    return {
        "start": start,
        "finish": finish,
        "duration_sec": duration,
        "flow_id": flow_id,
        "client_ip": host,
        "server_ip": server,
        "server_port": port,
        "protocol": protocol,
        "down_bytes": 2_000_000,
        "up_bytes": 1_000_000,
    }


def record(
    rows: list[dict[str, Any]],
    *,
    indicator: str = "tunnel.example.com",
    indicator_type: str = "domain",
    host: str = "192.0.2.10",
    flows: list[dict[str, Any]] | None = None,
    match_id: str | None = None,
    threat_type: str = "botnet_cc",
    malware: str = "win.nanocore",
) -> dict[str, Any]:
    return {
        "indicator_type": indicator_type,
        "indicator": indicator,
        "affected_host": host,
        "threatfox": {"confidence": 100, "malware": malware, "threat_type": threat_type},
        "evidence": {
            "activity": rows,
            "long_flows": flows or [],
            "dns_pairs": [],
        },
        "match_id": match_id or f"m_{uuid.uuid4().hex[:10]}",
        "created_at": "2026-09-17T01:00:00Z",
    }


def write_feed(directory: Path, records: list[Any]) -> Path:
    path = directory / "feed.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    return path


@pytest.fixture
def store_path(tmp_path: Path) -> Iterator[Path]:
    if not MIGRATIONS.is_dir():
        pytest.skip("triage repo migrations not found; set NETWORK_BEHAVIOUR_MIGRATION_DIR")
    path = tmp_path / "network_behaviour.duckdb"
    with DuckDbStore(StorageConfig(path, MIGRATIONS)):
        pass
    yield path


def insert(connection: duckdb.DuckDBPyConnection, table: str, values: Mapping[str, object]) -> None:
    """Insert one row, filling every NOT NULL column the test did not name with a neutral value."""
    schema, name = table.split(".")
    columns = connection.execute(
        "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
        "WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position",
        [schema, name],
    ).fetchall()
    row: dict[str, object] = {}
    for column, data_type, nullable in columns:
        if column in values:
            row[column] = values[column]
        elif nullable == "NO":
            row[column] = _neutral(str(data_type))
    names = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    connection.execute(f"INSERT INTO {table} ({names}) VALUES ({marks})", list(row.values()))


def _neutral(data_type: str) -> object:
    if data_type == "UUID":
        return uuid.uuid4()
    if data_type == "DATE":
        return date(2026, 1, 1)
    if data_type.startswith("TIMESTAMP"):
        return datetime(2026, 1, 1, tzinfo=UTC)
    if data_type == "VARCHAR":
        return "x"
    if data_type == "DOUBLE":
        return 0.0
    return 0


def publish(
    connection: duckdb.DuckDBPyConnection,
    day: date,
    *,
    version: str = NORMALIZATION,
    detector: str | None = None,
) -> None:
    """`detector` is the day's detector generation; left out, the column holds a neutral value
    that names none."""
    insert(
        connection,
        "feed.daily_publication",
        {
            "day": day,
            "feed_schema_version": "daily-evidence-stream-v2",
            "feed_sha256": "0" * 64,
            **({"detector_version": detector} if detector is not None else {}),
        },
    )
    insert(
        connection,
        "ops.pipeline_run",
        {"day": day, "status": "published", "normalization_version": version},
    )
