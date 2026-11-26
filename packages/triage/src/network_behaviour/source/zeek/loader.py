"""Map one UTC day of Zeek logs onto the four source tables.

The rules, each with a test in `tests/unit/source/zeek/`:

- **Orientation.** The local side is `client_ip` and the remote side `server_ip`; `server_port` is
  the remote side's port whoever opened the session, as on the original probe. Local comes from
  `local_nets` when given, otherwise from Zeek's `local_orig`/`local_resp`. A connection with both
  or neither side local is dropped: a border sensor never sees one. `initiator` says who opened it
  (`client` when the local side originated), so direction is known for every connection.
- **Minute grain.** A connection occupies every minute it spans, and its bytes and packets are split
  by overlap so the minutes sum exactly to the connection. `flow_count` counts connections starting
  in the minute. Only minutes inside the day are written; the next day's load writes the rest.
  Plain DNS (port 53) is left out of the activity, rate and long-flow tables, as on the original
  probe, and lives in `flow.dns_pairs`.
- **Names.** `sni` is ssl.log's `server_name` for the connection. `dns` is the name the client last
  resolved to that server address, if the answer's TTL still covered the connection's start.
  `root_domain` is the registered domain of the SNI, else of the DNS name. `application` is the
  registered domain's first label, else Zeek's `service`; `application_category` is Zeek's
  `service`, else `_unknown`.
- **ASN** comes from an ip2asn-format table (IPv4 only; IPv6 servers carry none).
- **Rate.** `host_load_5m` is written from the same split minutes, so activity and rate reconcile
  exactly. `up_rate_p95_bps` approximates the original's 1-second peaks: each minute's rate is the
  sum of the average upload rates of the connections active in it, and the bucket keeps the p95 of
  its minutes. Detectors read it only against history and peers.
- **Long flows** are connections starting in the day that moved `LONG_FLOW_MIN_BYTES` or more.
- **DNS pairs** are hourly per (client, resolver). A transaction with an `rtt` is complete. One
  without an `rtt` is unanswered when it has no `rcode` (no reply was seen) and an unsolicited reply
  when it has one: Zeek 9 logs a reply it cannot match to a query that way. Packets come from the
  transaction's conn.log row, service time from `rtt`. Older Zeek versions flagged such replies in
  weird.log as `dns_unmatched_reply`; those count too, once.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from ipaddress import IPv4Network, ip_network
from pathlib import Path

import duckdb
import pyarrow as pa

from network_behaviour.normalization.service import registered_domain
from network_behaviour.source.contracts import SOURCE_CONTRACTS
from network_behaviour.source.zeek.asn import (
    AsnTableError,
    define_ipv4_int,
    empty_asn_table,
    load_asn_table,
)
from network_behaviour.source.zeek.logs import KINDS_BY_NAME, ZeekLogError, find_logs, stage

LOADER_VERSION = "zeek-loader-v2"
"""The mapping these rules describe. Recorded per day in `zeek.loaded_day`, beside the four tables.

- zeek-loader-v1: the first mapping.
- zeek-loader-v2: a dns.log row with an `rcode` and no `rtt` is an unsolicited reply, not an
  unanswered query (Zeek 9 logs unmatched replies that way and raises no weird).
"""
LONG_FLOW_MIN_BYTES = 1_000_000
"""The floor `sql/source/` applies to long-flow evidence; the loader stores nothing below it."""
UNKNOWN_CATEGORY = "_unknown"
DNS_PORT = 53


class ZeekLoadError(RuntimeError):
    """The day could not be loaded. Nothing was written."""


@dataclass(frozen=True, slots=True)
class LoadReport:
    day: date
    files: int
    connections: int
    dropped_connections: int
    activity_rows: int
    rate_rows: int
    dns_rows: int
    long_flow_rows: int
    named_connections: int
    by_local_nets: bool = False
    loader_version: str = LOADER_VERSION

    def render(self) -> str:
        lines = [
            f"day: {self.day} ({self.loader_version}, local by "
            f"{'--local-nets' if self.by_local_nets else 'Zeek flags'})",
            f"log files: {self.files}",
            f"connections in the day: {self.connections} "
            f"({self.dropped_connections} dropped: both or neither side local)",
            f"connections with a name: {self.named_connections}",
            f"rows written: activity_1m {self.activity_rows}, host_load_5m {self.rate_rows}, "
            f"dns_pairs {self.dns_rows}, long_flows {self.long_flow_rows}",
        ]
        if self.connections and self.dropped_connections == self.connections:
            lines.append(f"warning: {self.locality_hint()}")
        return "\n".join(lines)

    def locality_hint(self) -> str:
        if self.by_local_nets:
            return "no connection had exactly one side inside the local networks given"
        return (
            "no connection had exactly one side local by Zeek's local_orig/local_resp. Zeek "
            "counts private and documentation ranges as local unless "
            "Site::private_address_space_is_local is F; give the local networks instead"
        )


def parse_local_nets(raw: str) -> tuple[IPv4Network, ...]:
    networks = []
    for part in raw.split(","):
        if not part.strip():
            continue
        network = ip_network(part.strip(), strict=False)
        if not isinstance(network, IPv4Network):
            raise ZeekLoadError("local networks must be IPv4; IPv6 locality comes from Zeek")
        networks.append(network)
    return tuple(networks)


def create_source_tables(connection: duckdb.DuckDBPyConnection) -> None:
    """The four tables, typed exactly as `source/contracts.py` requires, and the load record. The
    record lives in schema `zeek`, which no reader queries and the contract check never lists."""
    connection.execute("CREATE SCHEMA IF NOT EXISTS flow")
    for contract in SOURCE_CONTRACTS:
        columns = ", ".join(f"{column.name} {column.type_name}" for column in contract.columns)
        connection.execute(
            f"CREATE TABLE IF NOT EXISTS {contract.database}.{contract.table} ({columns})"
        )
    connection.execute("CREATE SCHEMA IF NOT EXISTS zeek")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS zeek.loaded_day "
        "(day DATE PRIMARY KEY, loader_version VARCHAR NOT NULL, locality VARCHAR NOT NULL)"
    )


def load_day(
    source_path: Path,
    day: date,
    logs: Sequence[Path],
    *,
    local_nets: Sequence[IPv4Network] = (),
    asn_table: Path | None = None,
) -> LoadReport:
    """Replace `day` in the source tables with what the logs say. One transaction: on any error
    the source is left as it was."""
    found = find_logs(logs, day)
    if not found["conn"]:
        raise ZeekLoadError(f"no conn log found for {day}")
    start = datetime.combine(day, time.min, UTC).timestamp()
    end = start + timedelta(days=1).total_seconds()
    source_path.parent.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect(str(source_path))
    try:
        connection.execute("SET TimeZone = 'UTC'")
        create_source_tables(connection)
        _macros(connection, local_nets)
        try:
            for name, kind in KINDS_BY_NAME.items():
                stage(connection, kind, found[name])
            if asn_table is not None:
                load_asn_table(connection, asn_table)
            else:
                empty_asn_table(connection)
        except (ZeekLogError, AsnTableError) as exc:
            raise ZeekLoadError(str(exc)) from exc
        connections, dropped = _orient(connection, start, end, bool(local_nets))
        named = _name(connection)
        connection.execute("BEGIN TRANSACTION")
        try:
            _clear(connection, start, end)
            counts = _write(connection, start, end, bool(local_nets))
            connection.execute(
                "INSERT OR REPLACE INTO zeek.loaded_day VALUES (?, ?, ?)",
                [day, LOADER_VERSION, ",".join(map(str, local_nets)) or "zeek-flags"],
            )
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
    except duckdb.Error as exc:
        raise ZeekLoadError(f"loading {day} failed: {type(exc).__name__}") from exc
    finally:
        connection.close()
    return LoadReport(
        day=day,
        files=sum(len(files) for files in found.values()),
        connections=connections,
        dropped_connections=dropped,
        named_connections=named,
        activity_rows=counts["activity_rows"],
        rate_rows=counts["rate_rows"],
        dns_rows=counts["dns_rows"],
        long_flow_rows=counts["long_flow_rows"],
        by_local_nets=bool(local_nets),
    )


def _macros(connection: duckdb.DuckDBPyConnection, local_nets: Sequence[IPv4Network]) -> None:
    define_ipv4_int(connection)
    connection.execute("CREATE OR REPLACE TEMP TABLE local_nets (lo UBIGINT, hi UBIGINT)")
    if local_nets:
        connection.executemany(
            "INSERT INTO local_nets VALUES (?, ?)",
            [(int(net.network_address), int(net.broadcast_address)) for net in local_nets],
        )
    connection.execute(
        """
        CREATE OR REPLACE TEMP MACRO in_local_nets(ip) AS
            coalesce((SELECT bool_or(ipv4_int(ip) BETWEEN lo AND hi) FROM local_nets), false)
        """
    )


def _orient(
    connection: duckdb.DuckDBPyConnection, start: float, end: float, by_nets: bool
) -> tuple[int, int]:
    """`oriented`: every connection overlapping the day with exactly one local side, turned so
    the local side is the client. Returns (connections overlapping the day, dropped)."""
    local_orig = "in_local_nets(orig_h)" if by_nets else "local_orig"
    local_resp = "in_local_nets(resp_h)" if by_nets else "local_resp"
    connection.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE overlapping AS
        SELECT *, ts AS start_s, ts + greatest(coalesce(duration, 0), 0) AS end_s,
               coalesce({local_orig}, false) AS lo, coalesce({local_resp}, false) AS lr
        FROM zeek_conn
        WHERE ts IS NOT NULL AND orig_h IS NOT NULL AND resp_h IS NOT NULL
          AND ts < {end} AND ts + greatest(coalesce(duration, 0), 0) >= {start}
        """
    )
    connection.execute(
        """
        CREATE OR REPLACE TEMP TABLE oriented AS
        SELECT
            uid, start_s, end_s, end_s - start_s AS duration_s,
            CASE WHEN lo THEN orig_h ELSE resp_h END AS client_ip,
            CASE WHEN lo THEN resp_h ELSE orig_h END AS server_ip,
            CASE WHEN lo THEN orig_p ELSE resp_p END AS client_port,
            CASE WHEN proto = 'icmp' THEN 0 WHEN lo THEN resp_p ELSE orig_p END AS server_port,
            CASE proto WHEN 'tcp' THEN 6 WHEN 'udp' THEN 17 WHEN 'icmp' THEN 1 ELSE 0 END
                AS transport_protocol,
            nullif(service, '') AS service,
            greatest(coalesce(CASE WHEN lo THEN orig_bytes ELSE resp_bytes END, 0), 0) AS up_b,
            greatest(coalesce(CASE WHEN lo THEN resp_bytes ELSE orig_bytes END, 0), 0) AS down_b,
            greatest(coalesce(CASE WHEN lo THEN orig_pkts ELSE resp_pkts END, 0), 0) AS up_p,
            greatest(coalesce(CASE WHEN lo THEN resp_pkts ELSE orig_pkts END, 0), 0) AS down_p,
            CASE WHEN lo THEN 'client' ELSE 'server' END AS initiator
        FROM overlapping
        WHERE lo <> lr
        """
    )
    totals = connection.execute(
        "SELECT count(*), count(*) FILTER (WHERE lo = lr) FROM overlapping"
    ).fetchone()
    return (int(totals[0]), int(totals[1])) if totals else (0, 0)


def _name(connection: duckdb.DuckDBPyConnection) -> int:
    """`named`: `oriented` plus SNI, DNS name, registered domain, application labels and ASN."""
    connection.execute(
        r"""
        CREATE OR REPLACE TEMP TABLE dns_answers AS
        SELECT client_ip, address, name, resolved_at, resolved_at + greatest(coalesce(ttl, 0), 0)
            AS expires_at
        FROM (
            SELECT orig_h AS client_ip, lower(query) AS name, ts AS resolved_at,
                   unnest(answers) AS address, unnest(ttls) AS ttl
            FROM zeek_dns
            WHERE query IS NOT NULL AND ts IS NOT NULL AND len(answers) > 0
        )
        WHERE regexp_full_match(address, '\d{1,3}(\.\d{1,3}){3}') OR contains(address, ':')
        """
    )
    connection.execute(
        """
        CREATE OR REPLACE TEMP TABLE resolved AS
        SELECT o.uid,
               CASE WHEN o.start_s <= a.expires_at THEN a.name END AS dns
        FROM oriented AS o
        ASOF LEFT JOIN dns_answers AS a
          ON o.client_ip = a.client_ip AND o.server_ip = a.address AND o.start_s >= a.resolved_at
        """
    )
    connection.execute(
        """
        CREATE OR REPLACE TEMP TABLE with_names AS
        SELECT o.*, coalesce(lower(s.server_name), '') AS sni, coalesce(r.dns, '') AS dns
        FROM oriented AS o
        LEFT JOIN (
            SELECT uid, arg_min(server_name, ts) AS server_name
            FROM zeek_ssl WHERE server_name IS NOT NULL AND server_name <> '' GROUP BY uid
        ) AS s USING (uid)
        LEFT JOIN resolved AS r USING (uid)
        """
    )
    names = [
        str(row[0])
        for row in connection.execute(
            "SELECT DISTINCT name FROM (SELECT sni AS name FROM with_names UNION ALL "
            "SELECT dns FROM with_names) WHERE name <> ''"
        ).fetchall()
    ]
    roots = [registered_domain(name) or "" for name in names]
    connection.register(
        "name_roots_arrow",
        pa.table(
            {"name": names, "root": roots},
            schema=pa.schema([("name", pa.string()), ("root", pa.string())]),
        ),
    )
    connection.execute(
        "CREATE OR REPLACE TEMP TABLE name_roots AS SELECT name, root FROM name_roots_arrow"
    )
    connection.unregister("name_roots_arrow")
    connection.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE named AS
        SELECT w.*,
               coalesce(nullif(rs.root, ''), nullif(rd.root, ''), '') AS root_domain,
               coalesce(
                   nullif(split_part(coalesce(nullif(rs.root, ''), rd.root, ''), '.', 1), ''),
                   w.service, ''
               ) AS application,
               coalesce(w.service, '{UNKNOWN_CATEGORY}') AS application_category,
               nullif(nullif(asn.asn, ''), '0') AS asn,
               coalesce(w.transport_protocol IN (6, 17) AND (w.server_port = {DNS_PORT}
                   OR w.service = 'dns'), false) AS is_dns
        FROM with_names AS w
        LEFT JOIN name_roots AS rs ON rs.name = w.sni
        LEFT JOIN name_roots AS rd ON rd.name = w.dns
        LEFT JOIN (
            SELECT w2.uid, a.asn
            FROM with_names AS w2
            ASOF JOIN asn_ranges AS a ON ipv4_int(w2.server_ip) >= a.lo
            WHERE ipv4_int(w2.server_ip) <= a.hi
        ) AS asn USING (uid)
        """
    )
    found = connection.execute("SELECT count(*) FROM named WHERE sni <> '' OR dns <> ''").fetchone()
    return int(found[0]) if found else 0


def _clear(connection: duckdb.DuckDBPyConnection, start: float, end: float) -> None:
    bounds = f">= to_timestamp({start}) AND {{column}} < to_timestamp({end})"
    for table, column in (
        ("flow.activity_1m", "time"),
        ("flow.host_load_5m", "time"),
        ("flow.dns_pairs", "time"),
        ("flow.long_flows", "start"),
    ):
        connection.execute(f"DELETE FROM {table} WHERE {column} " + bounds.format(column=column))


def _write(
    connection: duckdb.DuckDBPyConnection, start: float, end: float, by_nets: bool
) -> dict[str, int]:
    first_minute, last_minute = int(start // 60), int(end // 60) - 1
    connection.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE minutes AS
        WITH spans AS (
            SELECT *,
                   CAST(round(start_s * 1e6) AS BIGINT) AS start_us,
                   CAST(round(end_s * 1e6) AS BIGINT) AS end_us,
                   CAST(floor(start_s / 60) AS BIGINT) AS first_m,
                   CAST(floor(greatest(end_s - 1e-6, start_s) / 60) AS BIGINT) AS last_m,
                   up_b * 8.0 / greatest(duration_s, 1.0) AS conn_rate_bps
            FROM named
            WHERE NOT is_dns
        ),
        expanded AS (
            SELECT *, end_us - start_us AS dur_us,
                   unnest(range(greatest(first_m, {first_minute}),
                                least(last_m, {last_minute}) + 1)) AS minute
            FROM spans
        ),
        offsets AS (
            -- How far into the connection each minute starts and ends, in whole microseconds, so
            -- the split below is exact integer arithmetic and the minutes sum to the connection.
            SELECT *,
                CASE WHEN dur_us <= 0 THEN CASE WHEN minute = first_m THEN 1 ELSE 0 END
                     ELSE least(greatest(least((minute + 1) * 60000000, end_us) - start_us, 0),
                                dur_us) END AS off_end,
                CASE WHEN dur_us <= 0 THEN 0
                     ELSE least(greatest(greatest(minute * 60000000, start_us) - start_us, 0),
                                dur_us) END AS off_start,
                CASE WHEN dur_us <= 0 THEN 1 ELSE dur_us END AS den
            FROM expanded
        )
        SELECT
            minute, client_ip, server_ip, server_port, transport_protocol, application,
            application_category, root_domain, sni, dns, asn, conn_rate_bps,
            CAST(CAST(up_b AS HUGEINT) * off_end // den - CAST(up_b AS HUGEINT) * off_start // den
                 AS BIGINT) AS up_b,
            CAST(CAST(down_b AS HUGEINT) * off_end // den
                 - CAST(down_b AS HUGEINT) * off_start // den AS BIGINT) AS down_b,
            CAST(CAST(up_p AS HUGEINT) * off_end // den - CAST(up_p AS HUGEINT) * off_start // den
                 AS BIGINT) AS up_p,
            CAST(CAST(down_p AS HUGEINT) * off_end // den
                 - CAST(down_p AS HUGEINT) * off_start // den AS BIGINT) AS down_p,
            CASE WHEN minute = first_m THEN 1 ELSE 0 END AS starts
        FROM offsets
        """
    )
    connection.execute(
        """
        INSERT INTO flow.activity_1m
        SELECT to_timestamp(minute * 60) AS time, client_ip, server_ip, server_port,
               transport_protocol, application, application_category, root_domain, sni, dns, asn,
               sum(up_b), sum(down_b), sum(up_p), sum(down_p), sum(starts)
        FROM minutes
        GROUP BY ALL
        """
    )
    connection.execute(
        """
        INSERT INTO flow.host_load_5m
        SELECT to_timestamp((minute // 5) * 300) AS time, client_ip,
               count(*) AS active_minutes,
               quantile_cont(rate_bps, 0.95) AS up_rate_p95_bps,
               sum(up_b), sum(down_b)
        FROM (
            SELECT client_ip, minute, sum(up_b) AS up_b, sum(down_b) AS down_b,
                   sum(conn_rate_bps) AS rate_bps
            FROM minutes GROUP BY client_ip, minute
        )
        GROUP BY ALL
        """
    )
    connection.execute(
        f"""
        INSERT INTO flow.long_flows
        SELECT uid, to_timestamp(start_s), to_timestamp(end_s), duration_s, client_ip, server_ip,
               client_port, server_port, transport_protocol, up_b, down_b, initiator
        FROM named
        WHERE NOT is_dns AND start_s >= {start} AND start_s < {end}
          AND up_b + down_b >= {LONG_FLOW_MIN_BYTES}
        """
    )
    _write_dns(connection, start, end, by_nets)
    counts = {}
    for key, table, column in (
        ("activity_rows", "flow.activity_1m", "time"),
        ("rate_rows", "flow.host_load_5m", "time"),
        ("dns_rows", "flow.dns_pairs", "time"),
        ("long_flow_rows", "flow.long_flows", "start"),
    ):
        found = connection.execute(
            f"SELECT count(*) FROM {table} WHERE {column} >= to_timestamp({start}) "
            f"AND {column} < to_timestamp({end})"
        ).fetchone()
        counts[key] = int(found[0]) if found else 0
    return counts


def _dns_locality(alias: str, by_nets: bool) -> tuple[str, str]:
    """(origin is local, responder is local) for a dns.log or weird.log row. Without local
    networks, Zeek's flags come from the transaction's conn.log row (`c`); a querier with none
    counts as local."""
    if by_nets:
        return f"in_local_nets({alias}.orig_h)", f"in_local_nets({alias}.resp_h)"
    return "coalesce(c.local_orig, true)", "coalesce(c.local_resp, false)"


_CONN_FLAGS = """(
            SELECT uid, any_value(orig_pkts) AS orig_pkts, any_value(resp_pkts) AS resp_pkts,
                   any_value(local_orig) AS local_orig, any_value(local_resp) AS local_resp
            FROM zeek_conn GROUP BY uid
        )"""


def _write_dns(
    connection: duckdb.DuckDBPyConnection, start: float, end: float, by_nets: bool
) -> None:
    """Hourly (client, resolver) DNS counters. The local side is the client, as everywhere, and
    a transaction with both or neither side local is dropped."""
    dns_lo, dns_lr = _dns_locality("d", by_nets)
    weird_lo, weird_lr = _dns_locality("w", by_nets)
    connection.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE dns_transactions AS
        SELECT uid, ts, rtt, orig_pkts, resp_pkts,
               CASE WHEN rtt IS NOT NULL THEN 'complete'
                    WHEN rcode IS NULL THEN 'unanswered'
                    ELSE 'unsolicited' END AS outcome,
               CASE WHEN lo THEN orig_h ELSE resp_h END AS client_ip,
               CASE WHEN lo THEN resp_h ELSE orig_h END AS server_ip
        FROM (
            SELECT d.uid, d.ts, d.rtt, d.rcode, d.orig_h, d.resp_h, c.orig_pkts, c.resp_pkts,
                   {dns_lo} AS lo, {dns_lr} AS lr
            FROM zeek_dns AS d
            LEFT JOIN {_CONN_FLAGS} AS c USING (uid)
            WHERE d.ts >= {start} AND d.ts < {end}
              AND d.orig_h IS NOT NULL AND d.resp_h IS NOT NULL
        )
        WHERE lo <> lr
        """
    )
    connection.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE dns_unsolicited AS
        SELECT CAST(floor(ts / 3600) AS BIGINT) AS hour,
               CASE WHEN lo THEN orig_h ELSE resp_h END AS client_ip,
               CASE WHEN lo THEN resp_h ELSE orig_h END AS server_ip,
               count(*) AS replies
        FROM (
            SELECT w.ts, w.orig_h, w.resp_h, {weird_lo} AS lo, {weird_lr} AS lr
            FROM zeek_weird AS w
            LEFT JOIN {_CONN_FLAGS} AS c USING (uid)
            WHERE w.name = 'dns_unmatched_reply' AND w.ts >= {start} AND w.ts < {end}
              AND w.orig_h IS NOT NULL AND w.resp_h IS NOT NULL
              -- The same reply already counted from dns.log is not counted twice.
              AND NOT EXISTS (
                  SELECT 1 FROM dns_transactions AS t
                  WHERE t.uid = w.uid AND t.outcome = 'unsolicited'
              )
        )
        WHERE lo <> lr
        GROUP BY ALL
        """
    )
    connection.execute(
        """
        INSERT INTO flow.dns_pairs
        WITH per_uid AS (
            SELECT uid, client_ip, server_ip, CAST(floor(min(ts) / 3600) AS BIGINT) AS hour,
                   count(*) FILTER (WHERE outcome = 'complete') AS complete,
                   count(*) FILTER (WHERE outcome = 'unanswered') AS unanswered,
                   count(*) FILTER (WHERE outcome = 'unsolicited') AS unsolicited,
                   sum(rtt) FILTER (WHERE outcome = 'complete') AS rtt_sum,
                   coalesce(any_value(orig_pkts), count(*) FILTER (WHERE outcome <> 'unsolicited'))
                       AS query_pkts,
                   -- Each unsolicited reply is one packet, counted as unsolicited instead.
                   greatest(coalesce(any_value(resp_pkts),
                                     count(*) FILTER (WHERE outcome <> 'unanswered'))
                            - count(*) FILTER (WHERE outcome = 'unsolicited'), 0) AS response_pkts
            FROM dns_transactions GROUP BY uid, client_ip, server_ip
        ),
        sessions AS (
            SELECT hour, client_ip, server_ip,
                   sum(complete) AS complete, sum(unanswered) AS unanswered,
                   sum(unsolicited) AS unsolicited,
                   sum(query_pkts) AS query_pkts, sum(response_pkts) AS response_pkts,
                   sum(query_pkts) FILTER (WHERE complete = 0) AS unanswered_pkts,
                   sum(rtt_sum) / nullif(sum(complete), 0) AS mean_rtt
            FROM per_uid GROUP BY ALL
        )
        SELECT to_timestamp(hour * 3600) AS time, client_ip, server_ip,
               coalesce(s.complete, 0), coalesce(s.unanswered, 0),
               coalesce(s.unsolicited, 0) + coalesce(u.replies, 0),
               coalesce(s.query_pkts, 0), coalesce(s.response_pkts, 0),
               coalesce(s.unanswered_pkts, 0), coalesce(s.unsolicited, 0) + coalesce(u.replies, 0),
               CAST(round(coalesce(s.mean_rtt, 0) * 1e9) AS UBIGINT)
        FROM sessions AS s
        FULL OUTER JOIN dns_unsolicited AS u USING (hour, client_ip, server_ip)
        """
    )
