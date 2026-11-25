"""Transport and versioned server-port normalization."""

from __future__ import annotations

from dataclasses import dataclass

PORT_GROUP_VERSION = "port-groups-v1"
UNKNOWN_PORT_GROUP = 0
OTHER_SYSTEM_PORT_GROUP = 65_536
OTHER_REGISTERED_PORT_GROUP = 65_537
DYNAMIC_PORT_GROUP = 65_538

# Exact values are intentionally small, explicit, and versioned. Changing them creates V2 behavior.
MEANINGFUL_SERVICE_PORTS = frozenset(
    {
        20,
        21,
        22,
        23,
        25,
        53,
        67,
        68,
        80,
        110,
        123,
        143,
        161,
        389,
        443,
        445,
        465,
        500,
        587,
        636,
        853,
        993,
        995,
        1433,
        1521,
        2049,
        2375,
        2376,
        3306,
        3389,
        5060,
        5061,
        5432,
        5671,
        5672,
        5900,
        6379,
        6443,
        8080,
        8443,
        8883,
        9200,
        9300,
        11211,
        27017,
    }
)


@dataclass(frozen=True, slots=True)
class PortGroup:
    code: int
    version: str = PORT_GROUP_VERSION

    @property
    def is_meaningful(self) -> bool:
        return self.code in MEANINGFUL_SERVICE_PORTS


def normalize_transport(raw: str | int | None) -> int:
    if raw is None or str(raw).strip() == "":
        return 0
    if isinstance(raw, str):
        named = {"unknown": 0, "tcp": 6, "udp": 17}
        candidate = raw.strip().casefold()
        if candidate in named:
            return named[candidate]
        if not candidate.isdecimal():
            raise ValueError("transport protocol must be a name or integer")
        value = int(candidate)
    else:
        value = raw
    if not 0 <= value <= 255:
        raise ValueError("transport protocol is outside the UInt8 range")
    return value


def port_group(raw: str | int | None) -> PortGroup:
    if raw is None or str(raw).strip() == "":
        return PortGroup(UNKNOWN_PORT_GROUP)
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError("server port must be an integer") from exc
    if not 0 <= port <= 65_535:
        raise ValueError("server port is outside the UInt16 range")
    if port == 0:
        return PortGroup(UNKNOWN_PORT_GROUP)
    if port in MEANINGFUL_SERVICE_PORTS:
        return PortGroup(port)
    if port <= 1_023:
        return PortGroup(OTHER_SYSTEM_PORT_GROUP)
    if port <= 49_151:
        return PortGroup(OTHER_REGISTERED_PORT_GROUP)
    return PortGroup(DYNAMIC_PORT_GROUP)
