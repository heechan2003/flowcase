"""The synthetic-world switch, for the demo and tests only.

A synthetic world uses documentation and benchmarking address ranges for servers and `.test` names,
so nothing in it falls in real address space or names a real site. Normalization drops servers that
are not public destinations and names without a public suffix, so without this switch every
synthetic destination would vanish. With `NETWORK_BEHAVIOUR_SYNTHETIC=1`:

- `SYNTHETIC_PUBLIC_NETWORKS` count as public destinations (`normalization/ip.py`);
- `test` counts as a public suffix (`normalization/service.py`);
- the normalization bundle version recorded for each published day gains `+synthetic`, so a store
  always says which world it was built in.

The switch is read on every call, so a test can turn it on and off.
"""

from __future__ import annotations

import os
from ipaddress import ip_network

SYNTHETIC_ENV = "NETWORK_BEHAVIOUR_SYNTHETIC"
SYNTHETIC_PUBLIC_NETWORKS = tuple(
    ip_network(network)
    for network in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "198.18.0.0/15",
        "2001:db8::/32",
    )
)
SYNTHETIC_PUBLIC_SUFFIXES = ("test",)
SYNTHETIC_VERSION_SUFFIX = "+synthetic"


def synthetic_world() -> bool:
    return os.environ.get(SYNTHETIC_ENV, "").strip().lower() in {"1", "true", "yes", "on"}
