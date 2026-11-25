import os
from pathlib import Path

import pytest

from network_behaviour.config import (
    DEFAULT_SOURCE_PATH,
    ConfigurationError,
    SourceConfig,
    load_default_environment,
)


def test_source_config_defaults_to_the_repository_data_folder() -> None:
    config = SourceConfig.from_env({})

    assert config.path == DEFAULT_SOURCE_PATH and config.query_timeout_seconds == 900


def test_source_config_reads_its_path_and_timeout() -> None:
    config = SourceConfig.from_env(
        {
            "NETWORK_BEHAVIOUR_SOURCE_PATH": "/srv/source.duckdb",
            "NETWORK_BEHAVIOUR_SOURCE_QUERY_TIMEOUT": "60",
        }
    )

    assert config.path == Path("/srv/source.duckdb") and config.query_timeout_seconds == 60


def test_source_config_rejects_a_non_positive_timeout() -> None:
    with pytest.raises(ConfigurationError, match="must be positive"):
        SourceConfig.from_env({"NETWORK_BEHAVIOUR_SOURCE_QUERY_TIMEOUT": "0"})


def test_default_env_file_loads_without_overriding_process_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "NETWORK_BEHAVIOUR_SOURCE_PATH=file-path\nNETWORK_BEHAVIOUR_LOCAL_NETS=10.0.0.0/8\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_SOURCE_PATH", "process-path")
    monkeypatch.delenv("NETWORK_BEHAVIOUR_LOCAL_NETS", raising=False)

    load_default_environment(env_file)

    assert os.environ["NETWORK_BEHAVIOUR_SOURCE_PATH"] == "process-path"
    assert os.environ["NETWORK_BEHAVIOUR_LOCAL_NETS"] == "10.0.0.0/8"


def test_default_env_file_must_be_private(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("OPENROUTER_API_KEY=secret\n", encoding="utf-8")
    env_file.chmod(0o644)

    with pytest.raises(ConfigurationError, match="group or others"):
        load_default_environment(env_file)
