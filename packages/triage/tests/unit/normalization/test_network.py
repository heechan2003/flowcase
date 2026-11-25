import pytest

from network_behaviour.normalization.network import (
    DYNAMIC_PORT_GROUP,
    OTHER_REGISTERED_PORT_GROUP,
    OTHER_SYSTEM_PORT_GROUP,
    PORT_GROUP_VERSION,
    UNKNOWN_PORT_GROUP,
    normalize_transport,
    port_group,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, 0), ("", 0), ("unknown", 0), ("tcp", 6), ("UDP", 17), (6, 6), ("17", 17)],
)
def test_transport_normalization(raw: str | int | None, expected: int) -> None:
    assert normalize_transport(raw) == expected


@pytest.mark.parametrize("raw", ["sctp-name", -1, 256])
def test_invalid_transport_fails_closed(raw: str | int) -> None:
    with pytest.raises(ValueError):
        normalize_transport(raw)


@pytest.mark.parametrize(
    ("raw", "expected", "meaningful"),
    [
        (None, UNKNOWN_PORT_GROUP, False),
        (0, UNKNOWN_PORT_GROUP, False),
        (443, 443, True),
        (81, OTHER_SYSTEM_PORT_GROUP, False),
        (1023, OTHER_SYSTEM_PORT_GROUP, False),
        (1024, OTHER_REGISTERED_PORT_GROUP, False),
        (49151, OTHER_REGISTERED_PORT_GROUP, False),
        (49152, DYNAMIC_PORT_GROUP, False),
        (65535, DYNAMIC_PORT_GROUP, False),
    ],
)
def test_versioned_port_groups(raw: int | None, expected: int, meaningful: bool) -> None:
    normalized = port_group(raw)

    assert normalized.code == expected
    assert normalized.version == PORT_GROUP_VERSION
    assert normalized.is_meaningful is meaningful


@pytest.mark.parametrize("raw", ["bad", -1, 65536])
def test_invalid_port_fails_closed(raw: str | int) -> None:
    with pytest.raises(ValueError):
        port_group(raw)
