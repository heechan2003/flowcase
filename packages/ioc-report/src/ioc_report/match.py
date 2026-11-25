"""`ioc-match EXPORT.json --day D`: match a ThreatFox export against the source tables and write the
feed `ioc-report` reads.

ThreatFox publishes its indicators under CC0 (https://threatfox.abuse.ch/export/). The JSON export
is an object keyed by indicator id, each holding a list of records with `ioc_value`, `ioc_type`,
`threat_type`, `malware`, `confidence_level`, `first_seen_utc` and `last_seen_utc`; a plain list of
such records is read too.

- **What matches.**
  - An `ip:port` indicator matches a minute whose remote address and port are the listed ones.
  - A `domain` indicator matches a minute whose TLS name or resolved name is the domain or one of
    its subdomains, or whose registered domain is the domain.
  - A `url` indicator is reduced to its host: an address with its port (or the scheme's default) is
    matched as `ip:port`, a name as `domain`.
  - Other types (hashes) name no traffic and are skipped.
- **What is written.** One record per (indicator, host, matched minute), in the format `feed.py`
  reads, with the pair's long flows that overlap the day. As in the original matcher, the record's
  `first_seen_utc` and `last_seen_utc` are the matched minute; ThreatFox's own dates go to the
  listing-dates file (`IOC_METADATA_PATH`) the report already reads.
- **What is printed.** Counts only: no indicator, host or name.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import duckdb
from network_behaviour.config import ConfigurationError, SourceConfig, load_default_environment
from network_behaviour.source.client import (
    ReadOnlyQueryRunner,
    SourceQueryError,
    create_source_client,
)
from network_behaviour.source.sql import SqlKind, SqlLoader
from network_behaviour.source.zeek.asn import AsnTableError, define_ipv4_int, load_asn_table
from network_behaviour.time import UtcBounds, UtcDay

from ioc_report.feed import HOST_KEY
from ioc_report.knowledge import clean
from ioc_report.live import QUERY_TIMEOUT_SECONDS, SQL_ROOT

DEFAULT_PORTS = {"http": 80, "https": 443}
DEFAULT_METADATA = Path("data/ioc_metadata.json")


class MatchError(ValueError):
    """The export or the source cannot be used. The message names files, never indicators."""


@dataclass(frozen=True, slots=True)
class Indicator:
    value: str
    """`address:port` (IPv6 in brackets) or a lowercase domain."""
    kind: str
    """`ip:port` or `domain`."""
    malware: str
    threat_type: str
    confidence: int | None
    first_seen: str | None
    last_seen: str | None

    @property
    def endpoint(self) -> str | None:
        """`address port`, as the minutes query compares it."""
        if self.kind != "ip:port":
            return None
        address, _, port = self.value.rpartition(":")
        return f"{address.strip('[]')} {port}"


@dataclass(frozen=True, slots=True)
class MatchReport:
    indicators: int
    days: int
    records: int
    hosts: int
    matched_indicators: int
    out: Path

    def render(self) -> str:
        return (
            f"ioc-match: {self.indicators} indicator(s) over {self.days} day(s): "
            f"{self.records} matched minute record(s), {self.hosts} host(s), "
            f"{self.matched_indicators} indicator(s) matched; wrote {self.out}"
        )


# --- the export -----------------------------------------------------------------------------------


def load_threatfox(path: Path) -> tuple[Indicator, ...]:
    """Every usable indicator in a ThreatFox JSON export, deduplicated, in a fixed order."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise MatchError(f"{path} is not a readable ThreatFox JSON export") from exc
    records: Iterable[Any]
    if isinstance(raw, Mapping):
        records = (item for group in raw.values() if isinstance(group, list) for item in group)
    elif isinstance(raw, list):
        records = raw
    else:
        raise MatchError(f"{path} is neither a ThreatFox export object nor a list of records")
    found: dict[tuple[str, str], Indicator] = {}
    for record in records:
        if isinstance(record, Mapping) and (indicator := _indicator(record)) is not None:
            found.setdefault((indicator.kind, indicator.value), indicator)
    return tuple(found[key] for key in sorted(found))


def _indicator(record: Mapping[str, Any]) -> Indicator | None:
    kind = str(record.get("ioc_type") or "").strip().lower()
    value = str(record.get("ioc_value") or "").strip()
    if not value:
        return None
    if kind == "url":
        kind, value = _url_target(value) or ("", "")
    elif kind == "ip:port":
        value = _endpoint(value) or ""
    elif kind == "domain":
        value = clean(value).rstrip(".")
    if kind not in {"ip:port", "domain"} or not value:
        return None
    confidence = record.get("confidence_level")
    return Indicator(
        value=value,
        kind=kind,
        malware=str(record.get("malware") or "unknown"),
        threat_type=str(record.get("threat_type") or "unknown"),
        confidence=confidence if isinstance(confidence, int) else None,
        first_seen=_threatfox_time(record.get("first_seen_utc")),
        last_seen=_threatfox_time(record.get("last_seen_utc")),
    )


def _endpoint(value: str) -> str | None:
    address, _, port = value.rpartition(":")
    try:
        parsed = ipaddress.ip_address(address.strip("[]"))
        number = int(port)
    except ValueError:
        return None
    if not 0 < number < 65536:
        return None
    return f"[{parsed}]:{number}" if parsed.version == 6 else f"{parsed}:{number}"


def _url_target(url: str) -> tuple[str, str] | None:
    try:
        parts = urlsplit(url if "://" in url else f"http://{url}")
        host = parts.hostname
        port = parts.port or DEFAULT_PORTS.get(parts.scheme.lower())
    except ValueError:
        return None
    if not host:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "domain", clean(host).rstrip(".")
    if port is None:
        return None
    return "ip:port", (f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}")


def _threatfox_time(value: object) -> str | None:
    """ThreatFox writes `2026-09-15 10:00:00 UTC`; the listing-dates file wants ISO 8601."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().removesuffix(" UTC")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- matching -------------------------------------------------------------------------------------


def match_days(
    runner: ReadOnlyQueryRunner, indicators: Sequence[Indicator], days: Sequence[UtcDay]
) -> list[dict[str, Any]]:
    """Feed records for every matched minute of `days`, in a fixed order."""
    loader = SqlLoader(SQL_ROOT)
    minutes_sql = loader.load(
        "ioc_match_minutes", 1, timeout_seconds=QUERY_TIMEOUT_SECONDS, kind=SqlKind.DATA
    )
    flows_sql = loader.load(
        "ioc_match_long_flows", 1, timeout_seconds=QUERY_TIMEOUT_SECONDS, kind=SqlKind.DATA
    )
    by_endpoint: dict[str, list[Indicator]] = defaultdict(list)
    domains = [indicator for indicator in indicators if indicator.kind == "domain"]
    for indicator in indicators:
        if (endpoint := indicator.endpoint) is not None:
            by_endpoint[endpoint].append(indicator)
    names = sorted({indicator.value for indicator in domains})
    records: list[dict[str, Any]] = []
    for day in days:
        outcome = runner.run(
            minutes_sql,
            bounds=day.bounds,
            parameters={"endpoints": sorted(by_endpoint), "names": names},
        )
        rows = outcome.dictionaries()
        if not rows:
            continue
        pairs = sorted({f"{row['client_ip']} {row['server_ip']}" for row in rows})
        day_start = day.bounds.start
        flows = runner.run(
            flows_sql,
            bounds=UtcBounds(day_start - timedelta(days=1), day.bounds.end),
            parameters={"pairs": pairs, "day_start": day_start},
        ).dictionaries()
        flows_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for flow in flows:
            flows_by_pair[(str(flow["client_ip"]), str(flow["server_ip"]))].append(flow)
        for row in rows:
            endpoint = f"{row['server_ip']} {row['server_port']}"
            matched = [*by_endpoint.get(endpoint, ()), *_domains_matching(row, domains)]
            pair = (str(row["client_ip"]), str(row["server_ip"]))
            for indicator in matched:
                records.append(_record(indicator, row, flows_by_pair[pair]))
    return sorted(
        records,
        key=lambda record: (
            record["evidence"]["activity"][0]["time"],
            record["indicator"],
            record[HOST_KEY],
            record["match_id"],
        ),
    )


def _domains_matching(row: Mapping[str, Any], domains: Sequence[Indicator]) -> Iterator[Indicator]:
    names = [str(row.get(field) or "") for field in ("sni", "dns")]
    root = str(row.get("root_domain") or "")
    for indicator in domains:
        listed = indicator.value
        if root == listed or any(
            name == listed or name.endswith(f".{listed}") for name in names if name
        ):
            yield indicator


def _record(
    indicator: Indicator, row: Mapping[str, Any], flows: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    minute = _as_utc(row["time"])
    stamp = minute.strftime("%Y-%m-%dT%H:%M:%SZ")
    activity = {
        "time": minute.strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": str(row["client_ip"]),
        "server_ip": str(row["server_ip"]),
        "server_port": int(row["server_port"] or 0),
        "transport_protocol": int(row["transport_protocol"] or 0),
        "sni": str(row["sni"] or ""),
        "dns": str(row["dns"] or ""),
        "root_domain": str(row["root_domain"] or ""),
        "up_bytes": int(row["sent_bytes"]),
        "down_bytes": int(row["received_bytes"]),
        "up_packets": int(row["sent_packets"]),
        "down_packets": int(row["received_packets"]),
        "flow_count": int(row["flows"]),
        "asn": str(row["asn"] or ""),
        "asn_organization": str(row.get("asn_organization") or ""),
        "country": str(row.get("country") or ""),
    }
    fields = (
        "client_ip", "server_ip", "server_port", "transport_protocol", "sni", "dns"
    )  # fmt: skip
    key = "\x00".join(
        (indicator.kind, indicator.value, stamp, *(str(activity[field]) for field in fields))
    )
    return {
        "indicator_type": indicator.kind,
        "indicator": indicator.value,
        HOST_KEY: activity["client_ip"],
        "threatfox": {
            "confidence": indicator.confidence,
            "first_seen_utc": stamp,
            "last_seen_utc": stamp,
            "malware": indicator.malware,
            "threat_type": indicator.threat_type,
        },
        "evidence": {
            "activity": [activity],
            "long_flows": [_flow(flow) for flow in flows],
        },
        "match_id": "m_" + hashlib.sha256(key.encode()).hexdigest()[:20],
    }


def _flow(flow: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "flow_id": str(flow["flow_id"]),
        "start": _as_utc(flow["start"]).strftime("%Y-%m-%d %H:%M:%S.%f"),
        "finish": _as_utc(flow["finish"]).strftime("%Y-%m-%d %H:%M:%S.%f"),
        "duration_sec": float(flow["duration_sec"]),
        "client_ip": str(flow["client_ip"]),
        "server_ip": str(flow["server_ip"]),
        "client_port": int(flow["client_port"] or 0),
        "server_port": int(flow["server_port"] or 0),
        "protocol": int(flow["protocol"] or 0),
        "up_bytes": int(flow["sent_bytes"]),
        "down_bytes": int(flow["received_bytes"]),
    }


def _as_utc(value: object) -> datetime:
    found = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return found.replace(tzinfo=UTC) if found.tzinfo is None else found.astimezone(UTC)


def add_networks(records: Sequence[dict[str, Any]], asn_table: Path) -> None:
    """Fill `asn_organization` and `country` from an ip2asn table, where the table knows them."""
    servers = sorted({r["evidence"]["activity"][0]["server_ip"] for r in records})
    if not servers:
        return
    connection = duckdb.connect()
    try:
        define_ipv4_int(connection)
        load_asn_table(connection, asn_table)
        found = {
            str(server): (str(organization or ""), str(country or ""))
            for server, organization, country in connection.execute(
                """
                SELECT s.server, a.organization, a.country
                FROM (SELECT unnest(?::VARCHAR[]) AS server) AS s
                ASOF JOIN asn_ranges AS a ON ipv4_int(s.server) >= a.lo
                WHERE ipv4_int(s.server) <= a.hi AND a.asn NOT IN ('', '0')
                """,
                [servers],
            ).fetchall()
        }
    except (duckdb.Error, AsnTableError) as exc:
        raise MatchError(f"cannot read the ASN table: {exc}") from exc
    finally:
        connection.close()
    for record in records:
        row = record["evidence"]["activity"][0]
        organization, country = found.get(row["server_ip"], ("", ""))
        row["asn_organization"], row["country"] = organization, country


def write_metadata(path: Path, indicators: Iterable[Indicator]) -> int:
    """Merge ThreatFox's own first and last seen dates into the listing-dates file. Returns the
    indicators written."""
    existing: dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MatchError(f"{path} is not readable JSON") from exc
        if isinstance(loaded, dict):
            existing = loaded
    written = 0
    for indicator in indicators:
        if indicator.first_seen is None and indicator.last_seen is None:
            continue
        existing[indicator.value] = {
            "threatfox_first_seen": indicator.first_seen,
            "threatfox_last_seen": indicator.last_seen,
        }
        written += 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return written


# --- the command ----------------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        load_default_environment()
        days = _days(args)
        indicators = load_threatfox(args.export)
        source = SourceConfig.from_env()
        with ReadOnlyQueryRunner(create_source_client(source)) as runner:
            records = match_days(runner, indicators, days)
        asn_raw = os.environ.get("NETWORK_BEHAVIOUR_ASN_TABLE", "").strip()
        asn_table = args.asn_table or (Path(asn_raw) if asn_raw else None)
        if asn_table is not None:
            add_networks(records, asn_table)
        out = args.out or Path("data") / f"ioc-matches-{days[0]}_{days[-1]}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        matched = {(r["indicator_type"], r["indicator"]) for r in records}
        metadata = args.metadata or Path(
            os.environ.get("IOC_METADATA_PATH", "").strip() or DEFAULT_METADATA
        )
        write_metadata(metadata, (i for i in indicators if (i.kind, i.value) in matched))
    except (ConfigurationError, MatchError, SourceQueryError, OSError, ValueError) as exc:
        print(f"ioc-match: {exc}", file=sys.stderr)
        return 2
    print(
        MatchReport(
            indicators=len(indicators),
            days=len(days),
            records=len(records),
            hosts=len({r[HOST_KEY] for r in records}),
            matched_indicators=len(matched),
            out=out,
        ).render()
    )
    return 0


def _days(args: argparse.Namespace) -> list[UtcDay]:
    if args.day is not None and (args.start is not None or args.end is not None):
        raise MatchError("give --day or --start/--end, not both")
    if args.day is not None:
        return [args.day]
    if args.start is None or args.end is None:
        raise MatchError("--day or both --start and --end are required")
    if args.end.value < args.start.value:
        raise MatchError("--end is before --start")
    span = (args.end.value - args.start.value).days
    return [UtcDay(args.start.value + timedelta(days=offset)) for offset in range(span + 1)]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc-match",
        description="Match a ThreatFox JSON export against the source tables and write the feed "
        "ioc-report reads.",
    )
    parser.add_argument("export", type=Path, help="ThreatFox JSON export (CC0)")
    parser.add_argument("--day", type=UtcDay.parse, help="one UTC day (or use --start/--end)")
    parser.add_argument("--start", type=UtcDay.parse)
    parser.add_argument("--end", type=UtcDay.parse)
    parser.add_argument(
        "--out", type=Path, help="feed file (default: data/ioc-matches-<start>_<end>.json)"
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        help="listing-dates file to merge ThreatFox's dates into (default: IOC_METADATA_PATH, "
        "else data/ioc_metadata.json)",
    )
    parser.add_argument(
        "--asn-table",
        type=Path,
        help="ip2asn TSV for network names and countries (default: NETWORK_BEHAVIOUR_ASN_TABLE)",
    )
    return parser
