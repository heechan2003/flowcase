"""Find a day's Zeek logs and stage each kind as one typed table, whatever the writer's format.

Zeek writes JSON (one object per line) or its tab-separated ASCII format, either one plain or
gzipped. Every field is read as text and typed here, so both formats, and both of Zeek's timestamp
styles (epoch seconds or ISO 8601), stage to the same columns.
"""

from __future__ import annotations

import gzip
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import TextIO, cast

import duckdb

_DATE_DIR = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ZeekLogError(ValueError):
    """A log could not be read. The message names the file, never its contents."""


@dataclass(frozen=True, slots=True)
class Field:
    source: str
    target: str
    kind: str  # time, text, int, float, bool, texts, floats


@dataclass(frozen=True, slots=True)
class LogKind:
    name: str
    fields: tuple[Field, ...]
    required: bool


LOG_KINDS = (
    LogKind(
        "conn",
        (
            Field("ts", "ts", "time"),
            Field("uid", "uid", "text"),
            Field("id.orig_h", "orig_h", "text"),
            Field("id.orig_p", "orig_p", "int"),
            Field("id.resp_h", "resp_h", "text"),
            Field("id.resp_p", "resp_p", "int"),
            Field("proto", "proto", "text"),
            Field("service", "service", "text"),
            Field("duration", "duration", "float"),
            Field("orig_bytes", "orig_bytes", "int"),
            Field("resp_bytes", "resp_bytes", "int"),
            Field("orig_pkts", "orig_pkts", "int"),
            Field("resp_pkts", "resp_pkts", "int"),
            Field("local_orig", "local_orig", "bool"),
            Field("local_resp", "local_resp", "bool"),
        ),
        required=True,
    ),
    LogKind(
        "ssl",
        (
            Field("ts", "ts", "time"),
            Field("uid", "uid", "text"),
            Field("server_name", "server_name", "text"),
        ),
        required=False,
    ),
    LogKind(
        "dns",
        (
            Field("ts", "ts", "time"),
            Field("uid", "uid", "text"),
            Field("id.orig_h", "orig_h", "text"),
            Field("id.resp_h", "resp_h", "text"),
            Field("id.resp_p", "resp_p", "int"),
            Field("query", "query", "text"),
            Field("rcode", "rcode", "int"),
            Field("rtt", "rtt", "float"),
            Field("answers", "answers", "texts"),
            Field("TTLs", "ttls", "floats"),
        ),
        required=False,
    ),
    LogKind(
        "weird",
        (
            Field("ts", "ts", "time"),
            Field("uid", "uid", "text"),
            Field("id.orig_h", "orig_h", "text"),
            Field("id.resp_h", "resp_h", "text"),
            Field("name", "name", "text"),
        ),
        required=False,
    ),
)
KINDS_BY_NAME = {kind.name: kind for kind in LOG_KINDS}


def find_logs(paths: Sequence[Path], day: date) -> dict[str, list[Path]]:
    """Every log file under `paths`, by kind. A directory holding Zeek's dated folders
    (`YYYY-MM-DD/`) contributes the day's folder and the next one only: Zeek writes a connection
    when it ends, so one that crosses midnight is in the next day's logs."""
    found: dict[str, list[Path]] = {kind.name: [] for kind in LOG_KINDS}
    for path in paths:
        for file in _candidate_files(path, day):
            kind = file.name.split(".", 1)[0]
            if kind in found and ".log" in file.name:
                found[kind].append(file)
    return {kind: sorted(set(files)) for kind, files in found.items()}


def _candidate_files(path: Path, day: date) -> Iterable[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise ZeekLogError(f"no such log path: {path}")
    dated = [child for child in path.iterdir() if child.is_dir() and _DATE_DIR.match(child.name)]
    if dated:
        wanted = {day.isoformat(), (day + timedelta(days=1)).isoformat()}
        roots = [child for child in dated if child.name in wanted]
        return [file for root in roots for file in root.rglob("*") if file.is_file()]
    return [file for file in path.rglob("*") if file.is_file()]


def stage(connection: duckdb.DuckDBPyConnection, kind: LogKind, files: Sequence[Path]) -> int:
    """Create `zeek_<kind>` from every file, typed. Returns the rows staged."""
    table = f"zeek_{kind.name}"
    columns = ", ".join(f"{field.target} {_SQL_TYPE[field.kind]}" for field in kind.fields)
    connection.execute(f"CREATE OR REPLACE TEMP TABLE {table} ({columns})")
    for file in files:
        raw = _raw_relation(file, kind)
        projection = ", ".join(_convert(field) for field in kind.fields)
        try:
            connection.execute(f"INSERT INTO {table} SELECT {projection} FROM {raw}")
        except duckdb.Error as exc:
            raise ZeekLogError(f"cannot read {file.name} as a Zeek {kind.name} log") from exc
    found = connection.execute(f"SELECT count(*) FROM {table}").fetchone()
    return int(found[0]) if found else 0


_SQL_TYPE = {
    "time": "DOUBLE",
    "text": "VARCHAR",
    "int": "BIGINT",
    "float": "DOUBLE",
    "bool": "BOOLEAN",
    "texts": "VARCHAR[]",
    "floats": "DOUBLE[]",
}


def _convert(field: Field) -> str:
    value = f'"{field.source}"'
    if field.kind == "time":
        return f"coalesce(try_cast({value} AS DOUBLE), epoch(try_cast({value} AS TIMESTAMPTZ)))"
    if field.kind == "text":
        return f"CASE WHEN {value} = '(empty)' THEN '' ELSE {value} END"
    if field.kind == "int":
        return f"try_cast(try_cast({value} AS DOUBLE) AS BIGINT)"
    if field.kind == "float":
        return f"try_cast({value} AS DOUBLE)"
    if field.kind == "bool":
        return (
            f"CASE lower({value}) WHEN 'true' THEN true WHEN 't' THEN true "
            f"WHEN 'false' THEN false WHEN 'f' THEN false END"
        )
    texts = (
        f"CASE WHEN {value} IS NULL OR {value} = '(empty)' THEN CAST([] AS VARCHAR[]) "
        f"WHEN starts_with({value}, '[') THEN from_json({value}, '[\"VARCHAR\"]') "
        f"ELSE string_split({value}, ',') END"
    )
    if field.kind == "texts":
        return texts
    return f"list_transform({texts}, x -> try_cast(x AS DOUBLE))"


def _raw_relation(file: Path, kind: LogKind) -> str:
    """A relation over one file with every wanted field as text (absent fields are NULL)."""
    path = _quote(str(file))
    first = _first_line(file)
    if first.startswith("{"):
        spec = ", ".join(f"{_quote(field.source)}: 'VARCHAR'" for field in kind.fields)
        return f"read_json({path}, format = 'newline_delimited', columns = {{{spec}}})"
    if first.startswith("#separator"):
        present = _tsv_fields(file)
        spec = ", ".join(f"{_quote(name)}: 'VARCHAR'" for name in present)
        relation = (
            f"read_csv({path}, delim = '\\t', header = false, comment = '#', "
            f"columns = {{{spec}}}, nullstr = '-', quote = '', escape = '', auto_detect = false)"
        )
        wanted = ", ".join(
            f'"{field.source}"' if field.source in present else f'NULL AS "{field.source}"'
            for field in kind.fields
        )
        return f"(SELECT {wanted} FROM {relation})"
    raise ZeekLogError(f"{file.name} is neither Zeek JSON nor Zeek TSV")


def _tsv_fields(file: Path) -> list[str]:
    with _open(file) as handle:
        for line in handle:
            if line.startswith("#fields"):
                return line.rstrip("\n").split("\t")[1:]
            if not line.startswith("#"):
                break
    raise ZeekLogError(f"{file.name} has no #fields header")


def _first_line(file: Path) -> str:
    with _open(file) as handle:
        for line in handle:
            if line.strip():
                return line.lstrip()
    return ""


def _open(file: Path) -> TextIO:
    if file.suffix == ".gz":
        return cast(TextIO, gzip.open(file, "rt", encoding="utf-8", errors="replace"))
    return file.open(encoding="utf-8", errors="replace")


def _quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"
