"""Server ASNs from an ip2asn-format table (iptoasn.com's free `ip2asn-v4.tsv`, or a synthetic one).

Each line is `range_start  range_end  AS_number  country_code  AS_description`, tab-separated, with
addresses dotted or as unsigned 32-bit integers. Only IPv4 ranges are read; AS 0 means unrouted.
"""

from __future__ import annotations

from pathlib import Path

import duckdb


class AsnTableError(ValueError):
    """The table could not be read. The message names the file, never its rows."""


def define_ipv4_int(connection: duckdb.DuckDBPyConnection) -> None:
    """`ipv4_int(text)`: a dotted IPv4 address as an unsigned integer, NULL for anything else."""
    connection.execute(
        r"""
        CREATE OR REPLACE TEMP MACRO ipv4_int(ip) AS
            CASE WHEN regexp_full_match(ip, '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') THEN
                CAST(split_part(ip, '.', 1) AS UBIGINT) * 16777216
                + CAST(split_part(ip, '.', 2) AS UBIGINT) * 65536
                + CAST(split_part(ip, '.', 3) AS UBIGINT) * 256
                + CAST(split_part(ip, '.', 4) AS UBIGINT)
            END
        """
    )


def empty_asn_table(connection: duckdb.DuckDBPyConnection) -> None:
    connection.execute(
        "CREATE OR REPLACE TEMP TABLE asn_ranges "
        "(lo UBIGINT, hi UBIGINT, asn VARCHAR, country VARCHAR, organization VARCHAR)"
    )


def load_asn_table(connection: duckdb.DuckDBPyConnection, path: Path) -> int:
    """Create `asn_ranges (lo, hi, asn, country, organization)`, sorted by `lo`. Needs the
    `ipv4_int` macro (`define_ipv4_int`). Returns the ranges read."""
    if not path.is_file():
        raise AsnTableError(f"no ASN table at {path}")
    quoted = "'" + str(path).replace("'", "''") + "'"
    columns = (
        "{'c0': 'VARCHAR', 'c1': 'VARCHAR', 'c2': 'VARCHAR', 'c3': 'VARCHAR', 'c4': 'VARCHAR'}"
    )
    try:
        connection.execute(
            f"""
            CREATE OR REPLACE TEMP TABLE asn_ranges AS
            SELECT lo, hi, asn, country, organization
            FROM (
                SELECT coalesce(try_cast(c0 AS UBIGINT), ipv4_int(c0)) AS lo,
                       coalesce(try_cast(c1 AS UBIGINT), ipv4_int(c1)) AS hi,
                       trim(c2) AS asn, nullif(trim(c3), 'None') AS country,
                       trim(c4) AS organization
                FROM read_csv({quoted}, delim = '\\t', header = false, columns = {columns},
                              quote = '', escape = '', auto_detect = false, null_padding = true)
            )
            WHERE lo IS NOT NULL AND hi IS NOT NULL AND lo <= hi
            ORDER BY lo
            """
        )
    except duckdb.Error as exc:
        raise AsnTableError(f"cannot read {path.name} as an ip2asn table") from exc
    found = connection.execute("SELECT count(*) FROM asn_ranges").fetchone()
    return int(found[0]) if found else 0
