"""Typed application configuration loaded without persisting secrets."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


class ConfigurationError(ValueError):
    """Raised when runtime configuration cannot satisfy the safe source contract."""


DEFAULT_ENV_FILE = Path(".env")


def load_default_environment(path: Path = DEFAULT_ENV_FILE) -> None:
    """Load the private repository-local environment without overriding process secrets."""
    if not path.exists():
        return
    if not path.is_file():
        raise ConfigurationError(f"credential path {path} must be a regular file")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConfigurationError(
            f"credential file {path} must not be accessible by group or others"
        )
    if not load_dotenv(dotenv_path=path, override=False):
        raise ConfigurationError(f"credential file {path} could not be loaded")


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be positive")
    return value


DEFAULT_SOURCE_PATH = Path("data/source.duckdb")


@dataclass(frozen=True, slots=True)
class SourceConfig:
    """Where the four source tables live: a DuckDB file the Zeek loader writes and every reader
    opens read-only."""

    path: Path
    query_timeout_seconds: int = 900
    detail_days: int | None = None
    """How long the source keeps a day's detail. None: as long as it stays loaded. The original
    probe kept about fifteen days (`CASE_STUDY` §1); set it to reproduce that."""

    def __post_init__(self) -> None:
        if not str(self.path).strip():
            raise ConfigurationError("NETWORK_BEHAVIOUR_SOURCE_PATH must not be empty")
        if self.query_timeout_seconds <= 0:
            raise ConfigurationError("query timeout must be positive")
        if self.detail_days is not None and self.detail_days <= 0:
            raise ConfigurationError("NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS must be positive")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SourceConfig:
        if env is None:
            load_default_environment()
        values = os.environ if env is None else env
        raw = values.get("NETWORK_BEHAVIOUR_SOURCE_PATH", "").strip()
        detail = values.get("NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS", "").strip()
        return cls(
            path=Path(raw) if raw else DEFAULT_SOURCE_PATH,
            query_timeout_seconds=_positive_int(
                values, "NETWORK_BEHAVIOUR_SOURCE_QUERY_TIMEOUT", 900
            ),
            detail_days=(
                _positive_int(values, "NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS", 1) if detail else None
            ),
        )
