import pytest

from network_behaviour.normalization.ip import IpNormalizationError, NormalizedIp


@pytest.mark.parametrize(
    ("raw", "expected", "version"),
    [
        (" 192.0.2.10 ", "192.0.2.10", 4),
        ("2001:db8:0:0::10", "2001:db8::10", 6),
        ("::ffff:192.0.2.10", "192.0.2.10", 4),
    ],
)
def test_client_ip_normalization(raw: str, expected: str, version: int) -> None:
    assert NormalizedIp.parse(raw) == NormalizedIp(expected, version)


@pytest.mark.parametrize("raw", ["", "not-an-ip", "fe80::1%en0"])
def test_unsupported_ip_values_fail_closed(raw: str) -> None:
    with pytest.raises(IpNormalizationError):
        NormalizedIp.parse(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "192.0.2.10",
        "198.51.100.10",
        "203.0.113.10",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "2001:db8::10",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::1",
    ],
)
def test_private_and_special_destinations_are_ineligible(raw: str) -> None:
    assert not NormalizedIp.parse(raw).is_public_destination
