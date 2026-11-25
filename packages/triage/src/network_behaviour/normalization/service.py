"""Logical-service construction and compact deterministic identifiers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

import tldextract

from network_behaviour.synthetic import SYNTHETIC_PUBLIC_SUFFIXES, synthetic_world

SERVICE_ID_VERSION = "service-id-v1"
CATEGORY_ID_VERSION = "category-id-v1"
_SERVICE_PERSON = b"nb-service-v1"
_CATEGORY_PERSON = b"nb-cat-v1"
_EXTRACT = tldextract.TLDExtract(
    cache_dir=None, suffix_list_urls=(), include_psl_private_domains=False
)
_EXTRACT_SYNTHETIC = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    include_psl_private_domains=False,
    extra_suffixes=SYNTHETIC_PUBLIC_SUFFIXES,
)
_WHITESPACE = re.compile(r"\s+")

# The single definition of a canonical registered domain, shared with `feed/domain.py`'s stream
# validation so the two can never drift apart. They did once: `registered_domain` rejected only
# control bytes (0x01-0x19) after a 2026-09-01 corruption, and 2026-09-07 produced two more
# corrupted domains that were fully printable -- a literal apostrophe and a literal space spliced
# into known Microsoft 365 hostnames, consistent with single-byte corruption at the source landing
# on an arbitrary ASCII value rather than reliably a control byte. Extraction must reject anything
# validation would, or a new corrupted byte value reaches `_require_service_domain` and aborts a
# whole day's publication again.
CANONICAL_DOMAIN = re.compile(
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+"
)
MAX_DOMAIN_LENGTH = 253
_ASN = re.compile(r"^(?:AS)?([0-9]+)$", re.IGNORECASE)


class ServiceBasis(StrEnum):
    DOMAIN = "domain"
    APPLICATION_ASN = "application_asn"
    ASN = "asn"
    SERVER_IP = "server_ip"


class DestinationIp(Protocol):
    @property
    def value(self) -> str: ...

    @property
    def is_public_destination(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class LogicalService:
    """A destination reduced to a hashed identity, plus the domain it was hashed from.

    `domain` is carried for the current day only. It is what makes a published episode
    resolvable; it is never written to retained history, which stays hashed.
    """

    service_id: bytes
    basis: ServiceBasis
    domain: str | None = None

    def __post_init__(self) -> None:
        if len(self.service_id) != 16:
            raise ValueError("service_id must contain exactly 128 bits")
        if self.domain is not None and self.basis is not ServiceBasis.DOMAIN:
            raise ValueError("only a domain-basis service carries a domain")


def normalize_asn(raw: str | int | None) -> int:
    if raw is None:
        return 0
    candidate = str(raw).strip()
    if not candidate:
        return 0
    match = _ASN.fullmatch(candidate)
    if match is None:
        raise ValueError("ASN must be an integer or AS-prefixed integer")
    value = int(match.group(1))
    if not 0 <= value <= 4_294_967_295:
        raise ValueError("ASN is outside the 32-bit range")
    return value


def normalize_label(raw: str | None) -> str | None:
    if raw is None:
        return None
    normalized = _WHITESPACE.sub(" ", raw.strip()).casefold()
    return normalized or None


def registered_domain(raw: str | None) -> str | None:
    """Extract the registered domain, or `None` if the source did not carry a usable one.

    The result is checked against `CANONICAL_DOMAIN` before it is returned, not merely against
    the printable-character checks upstream, because those have already proven insufficient once.
    `registered_domain` rejected only control bytes (0x01-0x19) after a 2026-09-01 corruption
    (12 of 15,243 domains, e.g. "sha\\x12epoint.com"); 2026-09-07 produced two more corrupted
    domains that were fully printable -- a literal apostrophe and a literal space spliced into
    known Microsoft 365 hostnames -- consistent with single-byte corruption at the source landing
    on an arbitrary ASCII value, not reliably a control byte. tldextract only splits on literal
    dots and has no opinion about what sits inside a label, so every one of these survived
    extraction as a "domain." Checking the output against the exact shape
    `_require_service_domain` enforces, rather than guessing at the input's character class,
    guarantees this function can never hand back a value the stream would later reject --
    whatever byte the source corrupts next. A rejected candidate falls through to the next
    service-identity tier (SNI, DNS, application/ASN, server IP), which is what a non-domain
    candidate should always have done.
    """
    normalized = normalize_label(raw)
    if normalized is None or any(character in normalized for character in "/@[]:"):
        return None
    hostname = normalized.rstrip(".")
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    extracted = (_EXTRACT_SYNTHETIC if synthetic_world() else _EXTRACT)(ascii_hostname)
    domain = extracted.top_domain_under_public_suffix
    if not domain or not extracted.suffix:
        return None
    domain = domain.casefold()
    if len(domain) > MAX_DOMAIN_LENGTH or not CANONICAL_DOMAIN.fullmatch(domain):
        return None
    return domain


def category_id(raw: str | None) -> int:
    normalized = normalize_label(raw)
    if normalized is None:
        return 0
    digest = hashlib.blake2b(
        normalized.encode("utf-8"), digest_size=8, person=_CATEGORY_PERSON
    ).digest()
    value = int.from_bytes(digest, "big")
    return value or 1


def build_logical_service(
    *,
    server_ip: DestinationIp,
    root_domain: str | None,
    sni: str | None,
    dns: str | None,
    application: str | None,
    asn: str | int | None,
) -> LogicalService | None:
    """Apply the authoritative service precedence to one public destination."""
    if not server_ip.is_public_destination:
        return None

    for candidate in (root_domain, sni, dns):
        domain = registered_domain(candidate)
        if domain is not None:
            return _logical_service(ServiceBasis.DOMAIN, domain, domain=domain)

    asn_id = normalize_asn(asn)
    application_name = normalize_label(application)
    if application_name is not None and asn_id:
        return _logical_service(ServiceBasis.APPLICATION_ASN, f"{application_name}\0{asn_id}")
    if asn_id:
        return _logical_service(ServiceBasis.ASN, str(asn_id))
    return _logical_service(ServiceBasis.SERVER_IP, server_ip.value)


def _logical_service(
    basis: ServiceBasis, value: str, *, domain: str | None = None
) -> LogicalService:
    payload = f"{SERVICE_ID_VERSION}\0{basis.value}\0{value}".encode()
    return LogicalService(
        hashlib.blake2b(payload, digest_size=16, person=_SERVICE_PERSON).digest(),
        basis,
        domain,
    )
