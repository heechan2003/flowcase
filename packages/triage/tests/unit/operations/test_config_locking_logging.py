import json
import logging
from pathlib import Path

import pytest

from network_behaviour.operations.config import (
    OperationsConfigurationError,
    OperationsPaths,
    StorageControls,
)
from network_behaviour.operations.locking import WriterLock, WriterLockError
from network_behaviour.operations.logging import JsonLogFormatter


def test_paths_and_storage_controls_are_typed_and_bounded(tmp_path: Path) -> None:
    database = tmp_path / "triage.duckdb"

    paths = OperationsPaths.from_env(database, {})
    storage = StorageControls.from_env(
        {
            "NETWORK_BEHAVIOUR_STORAGE_ALERT_GIB": "40",
            "NETWORK_BEHAVIOUR_STORAGE_STOP_GIB": "45",
        }
    )

    assert paths.lock_path == Path(f"{database}.lock")
    assert storage.alert_bytes < storage.stop_bytes
    with pytest.raises(OperationsConfigurationError, match="below"):
        StorageControls.from_env(
            {
                "NETWORK_BEHAVIOUR_STORAGE_ALERT_GIB": "45",
                "NETWORK_BEHAVIOUR_STORAGE_STOP_GIB": "45",
            }
        )


def test_writer_lock_fails_closed_on_concurrent_owner(tmp_path: Path) -> None:
    path = tmp_path / "writer.lock"
    first = WriterLock(path)
    second = WriterLock(path)

    first.acquire()
    try:
        with pytest.raises(WriterLockError, match="another"):
            second.acquire()
        assert path.stat().st_mode & 0o077 == 0
    finally:
        first.release()
    second.acquire()
    second.release()


def test_json_logs_omit_sensitive_extra_fields() -> None:
    record = logging.LogRecord("network_behaviour.test", logging.INFO, "", 1, "done", (), None)
    record.query_count = 1
    record.password = "secret"
    record.client_ip = "192.0.2.1"

    parsed = json.loads(JsonLogFormatter().format(record))

    assert parsed["event"] == "done"
    assert parsed["query_count"] == 1
    assert "password" not in parsed
    assert "client_ip" not in parsed
