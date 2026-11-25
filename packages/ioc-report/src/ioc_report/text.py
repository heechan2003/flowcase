"""How the report writes times, sizes and lists: shared by the case file and both renderers, so a
number reads the same wherever it appears."""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

REPORT_TIMEZONE = "REPORT_TIMEZONE"
"""An IANA zone (`Europe/Berlin`) whose clock the reports show beside UTC. Unset, empty, `UTC`, or
a zone the time-zone database does not hold: UTC only."""


def report_zone() -> tuple[ZoneInfo, str] | None:
    """The local zone and the label written after its times, or None for UTC only. Read on every
    call, so a value loaded from `.env` after import still counts."""
    name = os.environ.get(REPORT_TIMEZONE, "").strip()
    if not name or name.upper() in ("UTC", "ETC/UTC"):
        return None
    try:
        zone = ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return None
    return zone, name.rsplit("/", 1)[-1].replace("_", " ")


HOST_TOKEN = "HOST"


def without_addresses(text: str, addresses: Iterable[str]) -> str:
    """Each address replaced with `HOST_TOKEN`, the longest first so none is cut short."""
    for address in sorted(set(addresses), key=len, reverse=True):
        text = text.replace(address, HOST_TOKEN)
    return text


def minute(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M")


def when(value: datetime) -> str:
    """UTC, with the report zone's clock beside it when one is set (`REPORT_TIMEZONE`)."""
    if (local := local_time(value)) is None:
        return f"{minute(value)} UTC"
    return f"{minute(value)} UTC ({local[0]} {local[1]})"


def local_time(value: datetime) -> tuple[str, str] | None:
    """The report zone's clock and its label, or None when reports show UTC only."""
    if (found := report_zone()) is None:
        return None
    zone, label = found
    return minute(value.astimezone(zone)), label


def day_list(days: Iterable[date]) -> str:
    ordered = sorted(set(days))
    runs: list[list[date]] = []
    for day in ordered:
        if runs and day - runs[-1][-1] == timedelta(days=1):
            runs[-1].append(day)
        else:
            runs.append([day])
    return ", ".join(str(run[0]) if len(run) == 1 else f"{run[0]}..{run[-1]}" for run in runs)


def size(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if amount < 1000 or unit == "GB":
            return f"{value} B" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1000
    raise AssertionError("unreachable")


def duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f} s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"


def network(asn: str, org: str, country: str) -> str:
    label = " ".join(part for part in (f"AS{asn}" if asn else "", org) if part)
    return f"{label} ({country})" if country else label


def transport(value: int) -> str:
    return {6: "tcp", 17: "udp"}.get(value, str(value))
