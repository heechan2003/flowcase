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


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"{name} is required")
    return value


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be positive")
    return value


def _boolean(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be a boolean")


@dataclass(frozen=True, slots=True)
class ClickHouseConfig:
    """Connection settings that enforce a read-only ClickHouse session."""

    host: str
    port: int
    username: str
    password: str
    secure: bool = False
    readonly: bool = True
    connect_timeout_seconds: int = 10
    send_receive_timeout_seconds: int = 300
    query_timeout_seconds: int = 900

    def __post_init__(self) -> None:
        if not self.host.strip() or not self.username.strip() or not self.password:
            raise ConfigurationError("ClickHouse host, username, and password are required")
        if not 1 <= self.port <= 65535:
            raise ConfigurationError("CLICKHOUSE_PORT must be between 1 and 65535")
        if not self.readonly:
            raise ConfigurationError("CLICKHOUSE_READONLY must remain true")
        for name, value in (
            ("connect timeout", self.connect_timeout_seconds),
            ("send/receive timeout", self.send_receive_timeout_seconds),
            ("query timeout", self.query_timeout_seconds),
        ):
            if value <= 0:
                raise ConfigurationError(f"{name} must be positive")

    def __repr__(self) -> str:
        return (
            "ClickHouseConfig("
            f"host={self.host!r}, port={self.port!r}, username={self.username!r}, "
            "password=<redacted>, "
            f"secure={self.secure!r}, readonly={self.readonly!r}, "
            f"connect_timeout_seconds={self.connect_timeout_seconds!r}, "
            f"send_receive_timeout_seconds={self.send_receive_timeout_seconds!r}, "
            f"query_timeout_seconds={self.query_timeout_seconds!r})"
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ClickHouseConfig:
        if env is None:
            load_default_environment()
        values = os.environ if env is None else env
        return cls(
            host=_required(values, "CLICKHOUSE_HOST"),
            port=_positive_int(values, "CLICKHOUSE_PORT", 8123),
            username=_required(values, "CLICKHOUSE_USER"),
            password=_required(values, "CLICKHOUSE_PASSWORD"),
            secure=_boolean(values, "CLICKHOUSE_SECURE", False),
            readonly=_boolean(values, "CLICKHOUSE_READONLY", True),
            connect_timeout_seconds=_positive_int(values, "CLICKHOUSE_CONNECT_TIMEOUT", 10),
            send_receive_timeout_seconds=_positive_int(
                values, "CLICKHOUSE_SEND_RECEIVE_TIMEOUT", 300
            ),
            query_timeout_seconds=_positive_int(values, "CLICKHOUSE_QUERY_TIMEOUT", 900),
        )
