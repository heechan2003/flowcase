"""`make demo`: run the whole pipeline on the synthetic network and check every planted case.

1. **generate** the world (`demo/generate.py`): Zeek logs, an ip2asn table, a ThreatFox export and
   an RDAP cache, under `demo/work/` (git-ignored).
2. **load** every day into the source tables (`network-behaviour load-zeek`).
3. **triage** every day into the retained store (`network-behaviour backfill`).
4. **match** the export against the scenario days (`ioc-match`).
5. **report** on the matches, with live context and no model (`ioc-report --no-model
   --case-reports`): code decides every case, and every page carries code's own text.
6. **check** each case's disposition and rules against `demo/expected.json`, and that triage
   published every day.

Nothing leaves the machine: no model runs, and the RDAP cache answers every lookup the run makes.
`--from STEP` resumes at a step over the files an earlier run left.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import duckdb

DEMO = Path(__file__).resolve().parent
ROOT = DEMO.parent
TRIAGE = ROOT / "packages" / "triage"
BIN = Path(sys.executable).parent
sys.path.insert(0, str(DEMO))

import generate  # noqa: E402

STEPS = ("generate", "load", "triage", "match", "report", "check")
# The cases whose PDFs `--sample` keeps, beside the HTML report.
SAMPLE_CASES = ("beacon", "flagged-domain", "download")


def here(path: Path) -> str:
    """`path` relative to the repository root, where every command runs, so that no file the run
    writes records where the checkout lives."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def environment(work: Path) -> dict[str, str]:
    """Every setting the commands read, pinned here so a developer's `.env` changes nothing."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(
            (
                "NETWORK_BEHAVIOUR_",
                "IOC_",
                "MODEL_",
                "SHADOW_",
                "OPENROUTER_",
                "OLLAMA_",
                "RDAP_",
                "NAME_LOOKUP",
                "REPORT_TIMEZONE",
            )
        )
    }
    env |= {
        "NETWORK_BEHAVIOUR_SYNTHETIC": "1",
        "NETWORK_BEHAVIOUR_SOURCE_PATH": here(work / "source.duckdb"),
        "NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS": "",
        "NETWORK_BEHAVIOUR_LOCAL_NETS": "10.0.0.0/8",
        "NETWORK_BEHAVIOUR_ASN_TABLE": here(work / "ip2asn.tsv"),
        "NETWORK_BEHAVIOUR_DUCKDB_PATH": here(work / "store.duckdb"),
        "NETWORK_BEHAVIOUR_LOCK_PATH": here(work / "store.duckdb.lock"),
        "NETWORK_BEHAVIOUR_MIGRATION_DIR": here(TRIAGE / "sql" / "migrations"),
        "NETWORK_BEHAVIOUR_SQL_DIR": here(TRIAGE / "sql" / "source"),
        "NETWORK_BEHAVIOUR_RUN_DIR": here(work / "runs"),
        "IOC_METADATA_PATH": here(work / "ioc_metadata.json"),
        "NAME_LOOKUP": "rdap",
        "RDAP_CACHE_DIR": here(work / "rdap"),
        "REPORT_TIMEZONE": "",
    }
    return env


def run(command: list[str], env: dict[str, str], log: Path) -> None:
    started = time.monotonic()
    print(
        f"$ {' '.join(Path(command[0]).name if i == 0 else part for i, part in enumerate(command))}"
    )
    with log.open("w", encoding="utf-8") as handle:
        result = subprocess.run(
            command, env=env, stdout=handle, stderr=subprocess.STDOUT, cwd=ROOT, check=False
        )
    if result.returncode != 0:
        print(log.read_text(encoding="utf-8")[-4000:], file=sys.stderr)
        raise SystemExit(f"failed ({result.returncode}): see {log}")
    print(f"  done in {time.monotonic() - started:.0f}s (log: {here(log)})")


def world(work: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((work / "world.json").read_text(encoding="utf-8"))
    return data


def check(work: Path) -> list[str]:
    """Every planted case decided as expected, and triage published every day."""
    expected = json.loads((DEMO / "expected.json").read_text(encoding="utf-8"))
    report = json.loads((work / "report" / "demo.json").read_text(encoding="utf-8"))
    cases = {(case["indicator"], case["host"]): case for case in report["cases"]}
    info = world(work)
    # The small world leaves some peer-percentile rules to chance (`_small_world_optional`).
    optional: dict[str, list[str]] = (
        {k: v for k, v in expected["_small_world_optional"].items() if not k.startswith("_")}
        if info.get("hosts_per_profile") is not None
        else {}
    )
    problems = []
    lines = []
    for scenario in generate.SCENARIOS:
        want = expected[scenario.id]
        case = cases.pop((scenario.indicator, scenario.host), None)
        if case is None:
            problems.append(f"{scenario.id}: no case")
            lines.append(f"  MISSING  {scenario.id}")
            continue
        items = case["contacts"] + case["flows"]
        got = {
            "disposition": case["disposition"],
            "rules": sorted(case["rules"]),
            "explained_by": sorted({f["rule"] for item in items for f in item["explained_by"]}),
        }
        loose = set(optional.get(scenario.id, ()))
        ok = {**got, "rules": sorted(set(got["rules"]) - loose)} == {
            key: sorted(set(value) - loose) if key == "rules"
            else sorted(value) if key != "disposition" else value
            for key, value in want.items()
        }  # fmt: skip
        explains = f" (contacts: {', '.join(got['explained_by'])})" if got["explained_by"] else ""
        lines.append(
            f"  {'ok' if ok else 'WRONG':7}  {scenario.id:20} {got['disposition']:9} "
            + ", ".join(got["rules"])
            + (explains if got["disposition"] == "review" else "")
        )
        if not ok:
            problems.append(f"{scenario.id}: expected {want}, got {got}")
    for indicator, host in cases:
        problems.append(f"unplanted case: {indicator} on {host}")
    with duckdb.connect(here(work / "store.duckdb"), read_only=True) as store:
        published = {
            str(row[0])
            for row in store.execute(
                "SELECT DISTINCT day FROM ops.pipeline_run WHERE status = 'published'"
            ).fetchall()
        }
        beacon = next(s for s in generate.SCENARIOS if s.id == "beacon").host
        streamed = store.execute(
            "SELECT count(DISTINCT day) FROM feed.episode WHERE client_ip = ? AND day >= ?",
            [beacon, info["scenario_days"][0]],
        ).fetchone()
    if not streamed or streamed[0] != len(info["scenario_days"]):
        problems.append("the beacon host is not in triage's stream on every scenario day")
    start, end = date.fromisoformat(info["start"]), date.fromisoformat(info["end"])
    missing = [
        day.isoformat()
        for day in generate.all_days(end, (end - start).days + 1)
        if day.isoformat() not in published
    ]
    if missing:
        problems.append(f"triage did not publish {len(missing)} day(s): {', '.join(missing)}")
    print("\n".join(lines))
    print(f"  triage published {len(published)} of {(end - start).days + 1} days")
    return problems


def sample(work: Path, out: Path) -> None:
    """Copy the HTML report and the `SAMPLE_CASES` PDFs into `out`, named for their scenarios.
    Other files there (the paid Haiku sample, `haiku-*`) are left alone."""
    out.mkdir(parents=True, exist_ok=True)
    for stale in out.glob("case-*.pdf"):
        stale.unlink()
    report = work / "report"
    (out / "demo.html").write_bytes((report / "demo.html").read_bytes())
    wanted = {(s.indicator, s.host): s.id for s in generate.SCENARIOS if s.id in SAMPLE_CASES}
    for audit in sorted(report.glob("*.json")):
        if audit.name == "demo.json":
            continue
        data = json.loads(audit.read_text(encoding="utf-8"))
        found = wanted.pop((data.get("indicator"), data.get("host")), None)
        if found is not None:
            (out / f"case-{found}.pdf").write_bytes(audit.with_suffix(".pdf").read_bytes())
    if wanted:
        raise SystemExit(f"no case PDF for: {', '.join(sorted(wanted.values()))}")
    print(f"sample output written to {here(out)}")


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description="Run the demo end to end and check it.")
    parser.add_argument("--work", type=Path, default=DEMO / "work")
    parser.add_argument("--from", dest="start", choices=STEPS, default="generate")
    parser.add_argument("--end", help=f"last generated day (default: {generate.DEMO_END})")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument(
        "--hosts-per-profile",
        type=int,
        help="the small world (see generate.py): the same cases on fewer background hosts",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="after a passing check, copy the report and three case PDFs to demo/sample-output/",
    )
    args = parser.parse_args(argv)
    if args.sample and args.hosts_per_profile is not None:
        parser.error("--sample keeps the full world's output; run it without --hosts-per-profile")
    work: Path = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    env = environment(work)
    steps = STEPS[STEPS.index(args.start) :]
    logs = work / "logs-run"
    logs.mkdir(exist_ok=True)

    if "generate" in steps:
        for stale in ("source.duckdb", "store.duckdb"):
            (work / stale).unlink(missing_ok=True)
        extra = ["--end", args.end] if args.end else []
        if args.hosts_per_profile is not None:
            extra += ["--hosts-per-profile", str(args.hosts_per_profile)]
        run(
            [
                str(BIN / "python"),
                here(DEMO / "generate.py"),
                "--out",
                here(work),
                "--jobs",
                str(args.jobs),
                *extra,
            ],
            env,
            logs / "generate.log",
        )
    info = world(work)
    first, last = info["start"], info["end"]
    scenario_days = info["scenario_days"]
    if "load" in steps:
        (work / "source.duckdb").unlink(missing_ok=True)
        run(
            [
                str(BIN / "network-behaviour"),
                "load-zeek",
                "--start",
                first,
                "--end",
                last,
                "--logs",
                here(work / "logs"),
            ],
            env,
            logs / "load.log",
        )
    if "triage" in steps:
        (work / "store.duckdb").unlink(missing_ok=True)
        run(
            [str(BIN / "network-behaviour"), "backfill", "--start", first, "--end", last],
            env,
            logs / "triage.log",
        )
    if "match" in steps or "report" in steps:
        # The cache's bootstrap expires a week after it is written. Stamped afresh, it keeps a late
        # `--from match|report` run offline, as the first run was.
        generate.write_rdap_cache(work / "rdap", date.fromisoformat(last), datetime.now(UTC))
    if "match" in steps:
        (work / "ioc_metadata.json").unlink(missing_ok=True)
        run(
            [
                str(BIN / "ioc-match"),
                here(work / "threatfox.json"),
                "--start",
                scenario_days[0],
                "--end",
                scenario_days[-1],
                "--out",
                here(work / "matches.json"),
            ],
            env,
            logs / "match.log",
        )
        print("  " + (logs / "match.log").read_text(encoding="utf-8").strip().replace("\n", "\n  "))
    if "report" in steps:
        run(
            [
                str(BIN / "ioc-report"),
                here(work / "matches.json"),
                "--out",
                here(work / "report"),
                "--name",
                "demo",
                "--no-model",
                "--case-reports",
            ],
            env,
            logs / "report.log",
        )
    problems = check(work)
    if problems:
        print("\nthe demo does not match demo/expected.json:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"\nevery planted case decided as expected; report in {here(work / 'report')}")
    if args.sample:
        sample(work, DEMO / "sample-output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
