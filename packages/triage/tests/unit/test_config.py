import os
from pathlib import Path

import pytest

from network_behaviour.config import (
    ClickHouseConfig,
    ConfigurationError,
    load_default_environment,
)

BASE_ENV = {
    "CLICKHOUSE_HOST": "clickhouse.example.test",
    "CLICKHOUSE_USER": "readonly",
    "CLICKHOUSE_PASSWORD": "not-a-real-secret",
}


def test_config_requires_password() -> None:
    with pytest.raises(ConfigurationError, match="CLICKHOUSE_PASSWORD"):
        ClickHouseConfig.from_env({"CLICKHOUSE_HOST": "host", "CLICKHOUSE_USER": "user"})


def test_config_rejects_non_readonly_mode() -> None:
    with pytest.raises(ConfigurationError, match="must remain true"):
        ClickHouseConfig.from_env({**BASE_ENV, "CLICKHOUSE_READONLY": "false"})


def test_config_repr_redacts_password() -> None:
    config = ClickHouseConfig.from_env(BASE_ENV)

    assert "not-a-real-secret" not in repr(config)
    assert "password=<redacted>" in repr(config)


def test_default_env_file_loads_without_overriding_process_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "CLICKHOUSE_HOST=file-host\nCLICKHOUSE_USER=file-user\nCLICKHOUSE_PASSWORD=file-password\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    monkeypatch.setenv("CLICKHOUSE_HOST", "process-host")
    monkeypatch.delenv("CLICKHOUSE_USER", raising=False)
    monkeypatch.delenv("CLICKHOUSE_PASSWORD", raising=False)

    load_default_environment(env_file)

    assert os.environ["CLICKHOUSE_HOST"] == "process-host"
    assert os.environ["CLICKHOUSE_USER"] == "file-user"
    assert os.environ["CLICKHOUSE_PASSWORD"] == "file-password"


def test_default_env_file_must_be_private(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("CLICKHOUSE_PASSWORD=secret\n", encoding="utf-8")
    env_file.chmod(0o644)

    with pytest.raises(ConfigurationError, match="group or others"):
        load_default_environment(env_file)
