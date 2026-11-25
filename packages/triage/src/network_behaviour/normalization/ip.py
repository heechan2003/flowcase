"""Canonical client and public-destination IP handling."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address

from network_behaviour.synthetic import SYNTHETIC_PUBLIC_NETWORKS, synthetic_world


class IpNormalizationError(ValueError):
    """Raised when a source value is not a supported IPv4 or IPv6 address."""


@dataclass(frozen=True, order=True, slots=True)
class NormalizedIp:
    value: str
    version: int

    @classmethod
    def parse(cls, raw: str) -> NormalizedIp:
        candidate = raw.strip()
        if not candidate or "%" in candidate:
            raise IpNormalizationError(
                "IP address is empty or contains an unsupported zone identifier"
            )
        try:
            parsed = ip_address(candidate)
        except ValueError as exc:
            raise IpNormalizationError("value is not a supported IPv4 or IPv6 address") from exc
        if isinstance(parsed, IPv6Address) and parsed.ipv4_mapped is not None:
            parsed = parsed.ipv4_mapped
        version = 4 if isinstance(parsed, IPv4Address) else 6
        return cls(str(parsed), version)

    @property
    def is_public_destination(self) -> bool:
        parsed = ip_address(self.value)
        if synthetic_world() and any(parsed in network for network in SYNTHETIC_PUBLIC_NETWORKS):
            return True
        return parsed.is_global and not (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
        )
