#!/usr/bin/env python3
"""Composition of a published evidence stream. Read-only.

    python scripts/stream_stats.py candidate-feeds/*.jsonl
    python scripts/stream_stats.py --ties candidate-feeds/daily-candidate-feed-2026-08-05.jsonl

Reports per-file counts by family, tier and history confidence, host concentration, and — with
--ties — how
much of each tier's ordering is decided by tie-break rather than by evidence. That last figure is
the one
worth watching: it is the share of the stream whose position carries no information.

Reads both stream schema v2 (episode / evidence_tier / tie_group) and the v1 feeds in candidate-
feeds/
(candidate / priority_tier / daily_rank).

Caveat on the tie share: no published stream carries every term of the ordering key. v1 feeds carry
neither independent_primary_family_count nor corroboration_present, so those terms are constant here
and the reported share under-estimates what the ranking engine ties on. v2 does not carry them
either, but it does carry tie_group — the publisher's own dense rank over the true key — which is
used directly and is exact.
"""

from __future__ import annotations

import argparse
import collections
import itertools
import json
import pathlib
import sys


def load(path: pathlib.Path) -> tuple[dict, list[dict]]:
    header, records = {}, []
    with path.open() as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            kind = row.get("record_type")
            if kind == "header":
                header = row
            elif kind in ("episode", "candidate"):
                records.append(row.get("episode") or row.get("candidate") or {})
    return header, records


def tier_of(record: dict) -> str:
    return record.get("evidence_tier") or record.get("priority_tier") or "?"


def tie_key(record: dict) -> tuple:
    """The substantive ordering key, excluding the stable-ID tie-break.

    v2 states it directly. Recomputing it from the fields a v2 episode happens to carry would be
    a second implementation of the ranking engine's key, and a wrong one — corroboration has not
    been readable from an episode's own fields since `episode-ordering-v4` made it depend on the
    strength carried by the evidence rows.
    """
    group = record.get("tie_group")
    if group is not None:
        return ("tie_group", group)
    return (
        tier_of(record),
        round(record.get("family_strength") or 0.0, 6),
        record.get("independent_primary_family_count"),
        bool(record.get("corroboration_present")),
        record.get("history_confidence"),
        record.get("data_quality_confidence"),
    )


def report(path: pathlib.Path, show_ties: bool) -> None:
    header, records = load(path)
    if not records:
        print(f"{path.name}: empty")
        return

    families = collections.Counter(r.get("family") for r in records)
    tiers = collections.Counter(tier_of(r) for r in records)
    history = collections.Counter(r.get("history_confidence") for r in records)
    hosts = collections.Counter(r.get("client_ip") for r in records)
    total = len(records)

    print(f"\n{path.name}")
    print(f"  day {header.get('day', '?')}  episodes {total:,}  hosts {len(hosts):,}")
    print(f"  family  {dict(families.most_common())}")
    print(f"  tier    {dict(sorted(tiers.items()))}")
    print(f"  history {dict(history.most_common())}")

    for k in (10, 100):
        share = sum(n for _, n in hosts.most_common(k)) / total
        print(f"  top {k:>3} hosts -> {share:6.1%} of the stream")
    noisy = [n for n in hosts.values() if n >= 10]
    if noisy:
        print(f"  hosts with >=10 episodes: {len(noisy)} covering {sum(noisy) / total:.1%}")

    if not show_ties:
        return

    print("  --- ordering ---")
    for tier in sorted({tier_of(r) for r in records}):
        members = [r for r in records if tier_of(r) == tier]
        if len(members) < 2:
            continue
        tied = sum(1 for a, b in itertools.pairwise(members) if tie_key(a) == tie_key(b))
        groups = len({tie_key(r) for r in members})
        largest = collections.Counter(tie_key(r) for r in members).most_common(1)[0][1]
        print(
            f"  {tier}: n={len(members):,}  adjacent tied {tied:,}/{len(members) - 1:,} "
            f"({tied / (len(members) - 1):.1%})  distinct groups {groups:,}  largest {largest:,}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=pathlib.Path)
    parser.add_argument("--ties", action="store_true", help="report ordering tie structure")
    args = parser.parse_args()

    for path in args.paths:
        if not path.is_file():
            print(f"skip {path}: not a file", file=sys.stderr)
            continue
        report(path, args.ties)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
