"""Versioned SQL loading with fail-closed static safety checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class SqlSafetyError(ValueError):
    """Raised when a SQL file violates the source-query boundary."""


class SqlKind(StrEnum):
    METADATA = "metadata"
    DATA = "data"


_APPROVED_DATA_TABLES = {
    "flow.activity_1m",
    "flow.host_load_5m",
    "flow.dns_pairs",
    "flow.long_flows",
}
_APPROVED_METADATA_TABLES = {"information_schema.columns", "information_schema.tables"}
_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(ALTER|ATTACH|CREATE|DELETE|DETACH|DROP|INSERT|KILL|OPTIMIZE|RENAME|TRUNCATE|UPDATE)\b",
    re.IGNORECASE,
)
_FORBIDDEN_IDENTIFIERS = re.compile(
    r"\b(subscriber_id|client_tag|mobile_no|imsi|imei|msisdn|user_agent)\b", re.IGNORECASE
)
_TABLE_REFERENCE = re.compile(r"\b(?:FROM|JOIN)\s+([a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)?)")
_FILE_NAME = re.compile(r"^(?P<name>[a-z][a-z0-9_]*)\.v(?P<version>[1-9][0-9]*)\.sql$")


@dataclass(frozen=True, slots=True)
class SqlQuery:
    name: str
    version: int
    text: str
    timeout_seconds: int
    kind: SqlKind
    aggregate_only: bool

    @property
    def bounded(self) -> bool:
        return "{start:" in self.text and "{end:" in self.text


class SqlLoader:
    """Load immutable, named SQL versions from a repository directory."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def load(
        self,
        name: str,
        version: int,
        *,
        timeout_seconds: int,
        kind: SqlKind,
        aggregate_only: bool = True,
    ) -> SqlQuery:
        if timeout_seconds <= 0:
            raise SqlSafetyError("query timeout must be positive")
        path = self._root / f"{name}.v{version}.sql"
        match = _FILE_NAME.fullmatch(path.name)
        if match is None or match.group("name") != name or int(match.group("version")) != version:
            raise SqlSafetyError("invalid SQL query name or version")
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SqlSafetyError(f"cannot load SQL query {name} v{version}") from exc
        query = SqlQuery(name, version, text, timeout_seconds, kind, aggregate_only)
        validate_sql(query)
        return query


def validate_sql(query: SqlQuery) -> None:
    without_block_comments = re.sub(r"/\*.*?\*/", " ", query.text, flags=re.DOTALL)
    normalized = re.sub(r"--[^\n]*", " ", without_block_comments).strip()
    if not re.match(r"^(SELECT|WITH)\b", normalized, re.IGNORECASE):
        raise SqlSafetyError("source SQL must begin with SELECT or WITH")
    if ";" in normalized.rstrip(";"):
        raise SqlSafetyError("source SQL must contain exactly one statement")
    if _FORBIDDEN_KEYWORDS.search(normalized):
        raise SqlSafetyError("source SQL contains a write or administrative keyword")
    if re.search(r"\bSELECT\s+(?:DISTINCT\s+)?\*", normalized, re.IGNORECASE):
        raise SqlSafetyError("SELECT * is forbidden")
    if _FORBIDDEN_IDENTIFIERS.search(normalized):
        raise SqlSafetyError("source SQL references a prohibited identifier")

    referenced_tables = {match.group(1).lower() for match in _TABLE_REFERENCE.finditer(normalized)}
    allowed = _APPROVED_METADATA_TABLES if query.kind is SqlKind.METADATA else _APPROVED_DATA_TABLES
    unexpected = referenced_tables - allowed
    if unexpected:
        raise SqlSafetyError(f"source SQL references an unapproved table: {sorted(unexpected)[0]}")
    if query.kind is SqlKind.DATA and not query.bounded:
        raise SqlSafetyError("data SQL requires typed start and end parameters")
    if query.kind is SqlKind.DATA:
        _validate_data_bounds(normalized)
    if query.aggregate_only and not re.search(
        r"\b(count|countIf|min|max|sum|uniq|quantile)[A-Za-z0-9]*\s*\(",
        normalized,
        re.IGNORECASE,
    ):
        raise SqlSafetyError("aggregate-only SQL must contain an aggregate function")


def _validate_data_bounds(normalized: str) -> None:
    branches = re.split(r"\bUNION\s+ALL\b", normalized, flags=re.IGNORECASE)
    source_branches = [
        branch
        for branch in branches
        if any(table in branch.lower() for table in _APPROVED_DATA_TABLES)
    ]
    for branch in source_branches:
        lower_bound = re.search(
            r"\b(?:PREWHERE|WHERE)\b.*\b(?:time|start)\s*>=\s*"
            r"(?:start_utc|\{start:[^}]+\})",
            branch,
            re.IGNORECASE | re.DOTALL,
        )
        upper_bound = re.search(
            r"\b(?:time|start)\s*<\s*(?:end_utc|\{end:[^}]+\})",
            branch,
            re.IGNORECASE | re.DOTALL,
        )
        if lower_bound is None or upper_bound is None:
            raise SqlSafetyError("each source branch requires a half-open UTC predicate")
