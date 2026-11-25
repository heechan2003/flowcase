#!/usr/bin/env python3
"""Publish every eligible day in a trailing window that is not already published.

    python scripts/publish_available_days.py                       # trailing 15 days
    python scripts/publish_available_days.py --days 7
    python scripts/publish_available_days.py --output-dir /tmp/feeds

Skips days that are already published, incomplete at source, or legacy selected-only. Writes each
stream atomically through a .partial file. See docs/runbooks/publish-a-day.md.

Source detail expires in roughly fifteen days (docs/CASE_STUDY.md §1), so a window longer than
that will fail on days whose source is gone rather than silently skip them.
"""

import argparse
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--days", type=int, default=15, help="trailing window size (default 15)")
parser.add_argument(
    "--output-dir", type=Path, default=Path("candidate-feeds"), help="destination directory"
)
args = parser.parse_args()

output_dir = args.output_dir
output_dir.mkdir(parents=True, exist_ok=True)

now = datetime.now(UTC)
latest = now.date() - timedelta(days=1 if now.hour >= 8 else 2)
first = latest - timedelta(days=args.days - 1)

for offset in range((latest - first).days + 1):
    day = (first + timedelta(days=offset)).isoformat()
    print(f"checking {day}", flush=True)

    preflight = subprocess.run(
        ["network-behaviour", "run-day", "--day", day, "--dry-run"],
        text=True,
        capture_output=True,
    )

    if preflight.returncode:
        if "only pre-cutover selected output" in preflight.stderr:
            print(f"skipping legacy selected-only day {day}")
            continue

        sys.stderr.write(preflight.stdout)
        sys.stderr.write(preflight.stderr)
        raise SystemExit(preflight.returncode)

    already_published = "status: already_published" in preflight.stdout

    if not already_published:
        check = subprocess.run(
            ["network-behaviour", "source-check", "--day", day],
            text=True,
            capture_output=True,
        )
        if check.returncode:
            issues = [line for line in check.stdout.splitlines() if line.startswith("issue:")]
            if (
                check.returncode == 1
                and issues
                and all(" incomplete_day " in f" {line} " for line in issues)
            ):
                print(f"skipping incomplete day {day}")
                continue

            sys.stderr.write(check.stdout)
            sys.stderr.write(check.stderr)
            raise SystemExit(check.returncode)

    destination = output_dir / f"daily-candidate-feed-{day}.jsonl"
    temporary = destination.with_suffix(".jsonl.partial")

    with temporary.open("wb") as output:
        result = subprocess.run(
            ["network-behaviour", "run-day", "--day", day],
            stdout=output,
        )

    if result.returncode:
        temporary.unlink(missing_ok=True)
        raise SystemExit(result.returncode)

    os.replace(temporary, destination)
    print(f"published {destination}")
