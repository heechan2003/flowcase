from dataclasses import dataclass
from itertools import permutations

import pytest

from network_behaviour.normalization.ip import NormalizedIp
from network_behaviour.normalization.service import (
    LogicalService,
    ServiceBasis,
    build_logical_service,
    category_id,
    normalize_asn,
    registered_domain,
)


@dataclass(frozen=True, slots=True)
class SyntheticEligibleDestination:
    value: str = "203.0.113.10"
    is_public_destination: bool = True


PUBLIC_DESTINATION = SyntheticEligibleDestination()
DEFAULTS = {
    "root_domain": None,
    "sni": None,
    "dns": None,
    "application": None,
    "asn": None,
}


@pytest.mark.parametrize(
    ("overrides", "basis", "golden_hex"),
    [
        (
            {"root_domain": "WWW.Example.COM.", "sni": "ignored.example.net"},
            ServiceBasis.DOMAIN,
            "a9dba2a545626563a05057cc37cc43e1",
        ),
        (
            {"root_domain": "invalid", "sni": "api.example.net"},
            ServiceBasis.DOMAIN,
            "f53e25e969c11d45f4183e49323bb0ca",
        ),
        (
            {"root_domain": "invalid", "sni": "invalid", "dns": "x.example.org"},
            ServiceBasis.DOMAIN,
            "8305eb53eb01e50e0ad4f2f38e89726f",
        ),
        (
            {"application": " Web   App ", "asn": "AS64500"},
            ServiceBasis.APPLICATION_ASN,
            "fcb140eb913483decf2996faf9e4c9df",
        ),
        (
            {"asn": "AS64500"},
            ServiceBasis.ASN,
            "76d4ed3a402005a48228eb08d11b3871",
        ),
        ({}, ServiceBasis.SERVER_IP, "d81d8545fd8d15d87f50b44159b832fd"),
        (
            {"application": "application without route"},
            ServiceBasis.SERVER_IP,
            "d81d8545fd8d15d87f50b44159b832fd",
        ),
    ],
)
def test_service_precedence_and_golden_ids(
    overrides: dict[str, str], basis: ServiceBasis, golden_hex: str
) -> None:
    service = build_logical_service(
        server_ip=PUBLIC_DESTINATION,
        **(DEFAULTS | overrides),
    )

    assert service is not None
    assert service.basis is basis
    assert service.service_id.hex() == golden_hex


def test_domain_service_id_does_not_include_asn() -> None:
    without_asn = build_logical_service(
        server_ip=PUBLIC_DESTINATION, **(DEFAULTS | {"root_domain": "example.com"})
    )
    with_asn = build_logical_service(
        server_ip=PUBLIC_DESTINATION,
        **(DEFAULTS | {"root_domain": "example.com", "asn": "64500"}),
    )

    assert without_asn == with_asn


def test_special_destination_never_creates_service_history() -> None:
    for raw in ("192.0.2.10", "10.0.0.1", "127.0.0.1", "2001:db8::10"):
        assert (
            build_logical_service(
                server_ip=NormalizedIp.parse(raw),
                **(DEFAULTS | {"root_domain": "example.com", "asn": "64500"}),
            )
            is None
        )


def test_registered_domain_and_unknown_values() -> None:
    assert registered_domain("subdomain.example.co.uk") == "example.co.uk"
    assert registered_domain("localhost") is None
    assert registered_domain("https://example.com/path") is None
    assert category_id(None) == 0
    assert category_id("  ") == 0
    assert category_id(" Web   Browsing ") == 13_227_408_840_173_475_771


def test_registered_domain_rejects_corrupted_domains_whatever_the_corrupted_byte_is() -> None:
    """A corrupted domain is not a domain, whatever tldextract thinks and whatever byte it is.

    Observed live and fixed twice. 2026-09-01: 12 of 15,243 extracted domains carried embedded
    0x01-0x19 control bytes, consistent with DNS wire-format label-length octets leaking through
    at the source (e.g. "sha\x12epoint.com") -- the first fix rejected control bytes specifically.
    2026-09-07 produced two more corrupted domains that were fully printable and passed that
    narrower check: a literal apostrophe and a literal space spliced into the same class of known
    Microsoft 365 hostnames, consistent with single-byte corruption landing on an arbitrary ASCII
    value rather than reliably a control byte. tldextract only splits on literal dots and has no
    opinion about what sits inside a label, so every one of these survived extraction as a
    "domain," reached the stream's canonical-shape validation four steps later, and aborted the
    entire day's publication because that validation is whole-day and fail-closed.
    `registered_domain` now checks its own output against that exact shape rather than guessing
    at the corrupted byte's character class, so no further byte value can repeat this.
    """
    for raw in (
        "officeapps\x01live.com",
        "sha\x12epoint.com",
        "comm\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02office.com",
        "offic\x07.com",
        "shaq'point.com",
        "officeapps live.com",
    ):
        assert registered_domain(raw) is None


@pytest.mark.parametrize(
    ("raw", "expected"), [(None, 0), ("", 0), (0, 0), ("AS64500", 64500), (64500, 64500)]
)
def test_asn_normalization(raw: str | int | None, expected: int) -> None:
    assert normalize_asn(raw) == expected


@pytest.mark.parametrize("raw", ["ASbad", -1, 4_294_967_296])
def test_invalid_asn_fails_closed(raw: str | int) -> None:
    with pytest.raises(ValueError):
        normalize_asn(raw)


def test_reordered_source_values_produce_identical_identifier_sets() -> None:
    values = ["Web", "DNS", "File Transfer"]
    expected = {category_id(value) for value in values}

    for ordering in permutations(values):
        assert {category_id(value) for value in ordering} == expected


def test_domain_basis_service_carries_the_domain_it_was_hashed_from() -> None:
    service = build_logical_service(
        server_ip=PUBLIC_DESTINATION, **(DEFAULTS | {"root_domain": "Example.COM"})
    )

    assert service is not None
    assert service.basis is ServiceBasis.DOMAIN
    assert service.domain == "example.com"


def test_non_domain_basis_services_carry_no_domain() -> None:
    for overrides in ({"asn": "64500"}, {"application": "web", "asn": "64500"}, {}):
        service = build_logical_service(server_ip=PUBLIC_DESTINATION, **(DEFAULTS | overrides))

        assert service is not None
        assert service.basis is not ServiceBasis.DOMAIN
        assert service.domain is None


def test_domain_is_rejected_on_a_non_domain_basis() -> None:
    with pytest.raises(ValueError, match="only a domain-basis service"):
        LogicalService(b"\x00" * 16, ServiceBasis.ASN, "example.com")


def test_the_domain_does_not_change_the_service_id() -> None:
    """The domain rides alongside the hash; it must not perturb the wire identity."""
    service = build_logical_service(
        server_ip=PUBLIC_DESTINATION, **(DEFAULTS | {"root_domain": "example.com"})
    )

    assert service is not None
    assert service.service_id == LogicalService(service.service_id, ServiceBasis.DOMAIN).service_id
