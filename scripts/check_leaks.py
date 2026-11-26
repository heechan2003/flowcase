"""The public leak check: no routable address and no data file outside what is meant to be here.

    python scripts/check_leaks.py          # every tracked and untracked, non-ignored file

The repository is synthetic (see `CLAUDE.md`). This check fails on:

- **an IPv4 address outside the ranges below**, in any text file, unless it is one of the few public
  service addresses listed with its reason;
- **a data file**: a database, capture, log, table or archive anywhere but `fixtures/zeek-real/`,
  or any file over `MAX_BYTES`.

It prints paths and counts only. It cannot read PDFs or IPv6, and it knows nothing of names:
`demo/sample-output/` is checked as generated, and names follow the `.test` convention by review.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ALLOWED_RANGES = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",  # private: local hosts
        "172.16.0.0/12",  # private
        "192.168.0.0/16",  # private
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local
        "224.0.0.0/4",  # multicast
        "0.0.0.0/32",
        "255.255.255.255/32",
        "192.0.2.0/24",  # documentation (TEST-NET-1)
        "198.51.100.0/24",  # documentation (TEST-NET-2)
        "203.0.113.0/24",  # documentation (TEST-NET-3)
        "198.18.0.0/15",  # benchmarking: the demo's synthetic servers
        "192.88.99.0/24",  # 6to4 relay anycast (deprecated, special-purpose)
    )
)

PUBLIC_ADDRESSES = {
    "1.1.1.1": "Cloudflare's public resolver",
    "8.8.8.8": "Google's public resolver",
    "9.9.9.9": "Quad9's public resolver",
    "104.16.132.229": "a Cloudflare edge address: the eval's shared-network case",
    "159.223.171.199": "the bore.pub tunnelling service: the eval's tunnel cases",
    "45.77.10.20": "a stand-in VPS address in the eval cases, kept so their digest is unchanged",
}

DATA_SUFFIXES = {
    ".duckdb", ".db", ".sqlite", ".sqlite3", ".wal", ".parquet", ".arrow", ".feather",
    ".csv", ".tsv", ".jsonl", ".ndjson", ".log", ".pcap", ".pcapng", ".gz", ".zip", ".tar",
    ".xz", ".bz2", ".7z",
}  # fmt: skip
DATA_ALLOWED = ("fixtures/zeek-real/",)
MAX_BYTES = 2_000_000

IPV4 = re.compile(rb"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def candidate_files() -> list[str]:
    listing = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    return sorted({name for name in listing.decode().split("\0") if name})


def routable(text: bytes) -> list[str]:
    found = []
    for match in IPV4.findall(text):
        try:
            address = ipaddress.ip_address(match.decode())
        except ValueError:
            continue  # a version number or the like, not an address
        if str(address) in PUBLIC_ADDRESSES:
            continue
        if not any(address in network for network in ALLOWED_RANGES):
            found.append(str(address))
    return found


def check(files: list[str]) -> list[str]:
    problems = []
    addresses: dict[str, int] = defaultdict(int)
    for name in files:
        path = ROOT / name
        if not path.is_file():
            continue  # deleted in the working tree, not yet staged
        size = path.stat().st_size
        if size > MAX_BYTES:
            problems.append(f"{name}: {size:,} bytes, over the {MAX_BYTES:,}-byte limit")
        if Path(name).suffix.lower() in DATA_SUFFIXES and not name.startswith(DATA_ALLOWED):
            problems.append(f"{name}: a data file outside {', '.join(DATA_ALLOWED)}")
        content = path.read_bytes()
        if b"\0" in content[:8192]:
            continue  # binary: PDFs and the capture
        hits = routable(content)
        if hits:
            addresses[name] += len(hits)
    for name, count in sorted(addresses.items()):
        problems.append(f"{name}: {count} routable IPv4 address(es) outside the allowed ranges")
    return problems


def main() -> int:
    files = candidate_files()
    problems = check(files)
    if problems:
        print(f"leak check: {len(problems)} problem(s) in {len(files)} file(s)", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"leak check: {len(files)} file(s) clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
