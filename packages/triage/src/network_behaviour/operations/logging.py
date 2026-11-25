"""Privacy-safe structured operational logging."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

_STANDARD_FIELDS = set(logging.makeLogRecord({}).__dict__)
_REDACTED_FIELDS = {
    "password",
    "client_ip",
    "server_ip",
    "domain",
    "sni",
    "dns",
    "subscriber_id",
}


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        for name, value in sorted(record.__dict__.items()):
            if (
                name not in _STANDARD_FIELDS
                and name not in {"message", "asctime"}
                and name.casefold() not in _REDACTED_FIELDS
            ):
                fields[name] = value
        return json.dumps(fields, default=str, ensure_ascii=True, separators=(",", ":"))


def configure_json_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger("network_behaviour")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False
