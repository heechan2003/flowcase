#!/usr/bin/env python3
"""Produce the five artifacts `docs/EVALUATION.md` requires before a behaviour change ships.

    python scripts/evaluate.py bundle --day 2026-08-21 --change "R1 support definition"
    python scripts/evaluate.py bundle --day 2026-08-21 --change "R4 relationship" --sections 3,5
    python scripts/evaluate.py bundle --day 2026-08-21 --change "R3 DNS floor" --source
    python scripts/evaluate.py volume --start 2026-08-15 --end 2026-08-21
    python scripts/evaluate.py seed  --day 2026-08-21 --into /tmp/replay
    python scripts/evaluate.py shadow --day 2026-08-21
    python scripts/evaluate.py shadow --day 2026-08-21 --sensitivity

`shadow` is R6/I10: one behavioural profile (`network_behaviour.evaluation.shadow`, a scheduled
low-volume channel — see its module docstring), scored against retained history and never against
anything the publisher touches. `--sensitivity` adds a §1-style sweep for that profile alone.

`bundle` seeds an isolated database with retained history strictly before the day, loads the day
once, and runs every requested section against it. The production database is opened read-only and
is never written. Sections not requested are written into the bundle as *not measured, and why* —
that is the point of the file, and a silently short bundle is the failure it exists to prevent.

Day D is reconstructed from retained history by default, which costs no live query and works after
the source detail has expired. `--source` re-derives it from the source tables instead, which is the
only way to measure the DNS family; it reports its own footprint either way.

## Cost

One scoring pass over a real day is minutes, not seconds — roughly seven at 12,234 hosts and
156,933 service rows, measured 2026-08-24. Every section is a multiple of that:

| Section | Passes at default settings |
|---|---|
| 1 sensitivity | one per grid point — 8 by default, 27 with `--full-grid` |
| 2 permutation | `--replicates`, default 5 |
| 3 stability   | `--resamples` plus 4 parameter perturbations, default 9 |
| 4 volume      | none — reads published days from storage |
| 5 redundancy  | none — reads the baseline pass |

So a default five-section bundle is about 22 passes, and `--full-grid` roughly triples it. Run
narrow sections during the day and the wide sweep overnight; `--sections` exists for exactly that.

The §1 defaults are a **pilot** — two points per axis. `docs/EVALUATION.md` §1 asks for a region of
parameter space, and the report says plainly when the grid was too coarse to be one.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from network_behaviour.config import (  # noqa: E402
    SourceConfig,
    load_default_environment,
)
from network_behaviour.evaluation import (  # noqa: E402
    DayEvaluator,
    measure_permutation_null,
    measure_redundancy,
    measure_sensitivity,
    measure_volume,
    perturb_parameters,
    resample_hosts,
    seed_history_before,
    sweep_profiles,
)
from network_behaviour.evaluation import bundle as bundle_module  # noqa: E402
from network_behaviour.evaluation.inputs import (  # noqa: E402
    DayInputs,
    load_from_history,
    load_from_source,
    open_product_database,
)
from network_behaviour.evaluation.shadow import (  # noqa: E402
    BeaconPolicy,
    beacon_candidates,
    measure_beacon_sensitivity,
)
from network_behaviour.evaluation.stability import build_report  # noqa: E402
from network_behaviour.evaluation.volume import VolumeUnavailableError  # noqa: E402
from network_behaviour.operations.config import OperationsPaths  # noqa: E402
from network_behaviour.publication import StorageGuard  # noqa: E402
from network_behaviour.source.client import (  # noqa: E402
    ReadOnlyQueryRunner,
    create_source_client,
)
from network_behaviour.storage.repository import (  # noqa: E402
    DuckDbStore,
    StorageConfig,
)
from network_behaviour.time import UtcDay  # noqa: E402

# §1 costs one full scoring pass per grid point, and a pass over a real day is minutes, not
# seconds — roughly seven at 12,234 hosts. The 3x3x3 grid this started with is twenty-seven
# passes, so the default is a 2x2x2 pilot that finishes and reports itself as a pilot. Widen it
# deliberately with --periods/--occurrences/--amplitudes when sweeping a real envelope.
DEFAULT_PERIODS = (60, 240)
DEFAULT_OCCURRENCES = (6, 40)
DEFAULT_AMPLITUDES = (10_000, 100_000_000)
FULL_PERIODS = (15, 60, 240)
FULL_OCCURRENCES = (6, 20, 60)
FULL_AMPLITUDES = (10_000, 1_000_000, 100_000_000)
ALL_SECTIONS = (1, 2, 3, 4, 5)

_SKIPPED = "Not requested on this run. Re-run with --sections {section} to measure it."
NOT_REACHED = (
    "Requested, but this run had not reached it when the bundle was last written. The run was "
    "interrupted or is still going; re-run to complete it."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evaluate.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    day_bundle = commands.add_parser("bundle", help="run the sections and write an evidence bundle")
    day_bundle.add_argument("--day", required=True, type=UtcDay.parse)
    day_bundle.add_argument("--change", required=True, help="what this bundle is evidence about")
    day_bundle.add_argument(
        "--sections",
        default="1,2,3,4,5",
        help="comma-separated section numbers to measure (default: all five)",
    )
    day_bundle.add_argument("--seed", type=int, default=20260824)
    day_bundle.add_argument("--hosts", type=int, default=10, help="§1 hosts injected per profile")
    day_bundle.add_argument(
        "--periods",
        type=_integers,
        default=DEFAULT_PERIODS,
        help="§1 contact periods in minutes, comma-separated",
    )
    day_bundle.add_argument(
        "--occurrences",
        type=_integers,
        default=DEFAULT_OCCURRENCES,
        help="§1 contact counts per day, comma-separated",
    )
    day_bundle.add_argument(
        "--amplitudes",
        type=_integers,
        default=DEFAULT_AMPLITUDES,
        help="§1 up-bytes per contact, comma-separated",
    )
    day_bundle.add_argument(
        "--full-grid",
        action="store_true",
        help="§1 sweep three points per axis: 27 scoring passes, hours on a real day",
    )
    day_bundle.add_argument("--jitter", type=int, default=2, help="§1 jitter in minutes")
    day_bundle.add_argument("--replicates", type=int, default=5, help="§2 permutation replicates")
    day_bundle.add_argument("--resamples", type=int, default=5, help="§3 population resamples")
    day_bundle.add_argument("--keep-fraction", type=float, default=0.8)
    day_bundle.add_argument("--volume-start", type=UtcDay.parse)
    day_bundle.add_argument("--volume-end", type=UtcDay.parse)
    day_bundle.add_argument(
        "--source",
        action="store_true",
        help="re-derive day D from the source tables instead of retained history",
    )
    day_bundle.add_argument("--output", type=Path, default=ROOT / "docs" / "evaluations")
    day_bundle.add_argument("--stdout", action="store_true", help="print, write nothing")

    volume = commands.add_parser("volume", help="§4 only, straight from the product database")
    volume.add_argument("--start", required=True, type=UtcDay.parse)
    volume.add_argument("--end", required=True, type=UtcDay.parse)

    seed = commands.add_parser("seed", help="seed an isolated replay database with day < D history")
    seed.add_argument("--day", required=True, type=UtcDay.parse)
    seed.add_argument("--into", required=True, type=Path, help="path of the replay database")
    seed.add_argument(
        "--exclude",
        default="",
        help="comma-separated days to hold out of history as well",
    )

    shadow = commands.add_parser(
        "shadow",
        help="R6/I10: score the beacon shape against retained history, publisher untouched",
    )
    shadow.add_argument("--day", required=True, type=UtcDay.parse)
    shadow.add_argument(
        "--sensitivity",
        action="store_true",
        help="also sweep synthesised beacons across period and jitter (§1 for this shape alone)",
    )
    shadow.add_argument(
        "--hosts", type=int, default=10, help="hosts injected per period/jitter cell"
    )
    shadow.add_argument(
        "--periods",
        type=_integers,
        default=(15, 60, 120, 240),
        help="periods in minutes to sweep, comma-separated",
    )
    shadow.add_argument("--occurrences", type=int, default=10)
    shadow.add_argument("--amplitude", type=int, default=2_000, help="up-bytes per contact")
    shadow.add_argument("--seed", type=int, default=20260908)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_default_environment()
    if args.command == "bundle":
        return _bundle(args)
    if args.command == "volume":
        return _volume(args)
    if args.command == "seed":
        return _seed(args)
    if args.command == "shadow":
        return _shadow(args)
    raise ValueError("unsupported command")


def _bundle(args: argparse.Namespace) -> int:
    """Run the requested sections, checkpointing the bundle after each one completes.

    A section over a real day is minutes and a five-section bundle is hours, so a run that dies
    partway through must not leave nothing behind. Every completed section is written immediately,
    and the sections that have not run yet say so — a partial bundle states what it reached rather
    than looking like a finished one that measured little.
    """

    sections = _sections(args.sections)
    storage = StorageConfig.from_env()
    reached: dict[int, bundle_module.Section] = {}

    def checkpoint() -> Path | None:
        assembled = bundle_module.Bundle(
            args.change,
            datetime.now(UTC).date(),
            f"day {args.day}"
            + (
                f", volume {args.volume_start} to {args.volume_end}"
                if 4 in sections and args.volume_start
                else ""
            ),
            tuple(_all_sections(reached, sections)),
        )
        if args.stdout:
            return None
        return assembled.write(args.output)

    with tempfile.TemporaryDirectory(prefix="network-behaviour-evaluation") as workspace:
        replay_path = Path(workspace) / f"evaluation-{args.day}.duckdb"
        seed = seed_history_before(
            storage.database_path, replay_path, args.day, migrations=storage.migration_path
        )
        print(seed.render(), file=sys.stderr)

        inputs = _load_day(args, storage)
        print(inputs.render(), file=sys.stderr)

        with DuckDbStore(StorageConfig(replay_path, storage.migration_path)) as store:
            evaluator = DayEvaluator(store.connection, args.day, inputs.staged, inputs.dns)
            for section in _run_sections(args, evaluator, inputs, sections, storage):
                reached[section.number] = section
                written = checkpoint()
                state = "measured" if section.body else "not measured"
                print(
                    f"section {section.number}: {state}"
                    + (f" — checkpointed to {written}" if written else ""),
                    file=sys.stderr,
                )

    path = checkpoint()
    if path is None:
        print(
            bundle_module.Bundle(
                args.change,
                datetime.now(UTC).date(),
                f"day {args.day}",
                tuple(_all_sections(reached, sections)),
            ).render()
        )
        return 0
    print(f"wrote {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")
    print("Fill in the verdict. A bundle without one is incomplete.")
    return 0


def _all_sections(
    reached: dict[int, bundle_module.Section], requested: frozenset[int]
) -> list[bundle_module.Section]:
    """Completed sections, plus an honest placeholder for every one not reached yet."""

    return [
        reached.get(number)
        or bundle_module.missing(
            number,
            NOT_REACHED if number in requested else _SKIPPED.format(section=number),
        )
        for number, _title, _question in bundle_module.SECTIONS
    ]


def _run_sections(
    args: argparse.Namespace,
    evaluator: DayEvaluator,
    inputs: DayInputs,
    sections: frozenset[int],
    storage: StorageConfig,
) -> Iterator[bundle_module.Section]:
    """Yield each section as it finishes, so the caller can checkpoint before the next starts."""
    header = inputs.render() + "\n\n"

    if 1 in sections:
        hosts = _hosts(evaluator, args.hosts)
        periods = FULL_PERIODS if args.full_grid else args.periods
        occurrences = FULL_OCCURRENCES if args.full_grid else args.occurrences
        amplitudes = FULL_AMPLITUDES if args.full_grid else args.amplitudes
        profiles = sweep_profiles(
            "scheduled",
            periods=periods,
            occurrences=occurrences,
            amplitudes=amplitudes,
            jitter_minutes=args.jitter,
        )
        print(
            f"section 1: {len(profiles)} scoring passes over {len(hosts)} hosts",
            file=sys.stderr,
        )
        envelope = measure_sensitivity(evaluator, hosts, profiles, seed=args.seed)
        yield bundle_module.measured(1, header + envelope.render())
    else:
        yield bundle_module.missing(1, _SKIPPED.format(section=1))

    if 2 in sections:
        null = measure_permutation_null(evaluator, seed=args.seed, replicates=args.replicates)
        yield bundle_module.measured(2, header + null.render())
    else:
        yield bundle_module.missing(2, _SKIPPED.format(section=2))

    if 3 in sections:
        variants = (
            *resample_hosts(
                evaluator,
                seed=args.seed,
                replicates=args.resamples,
                keep_fraction=args.keep_fraction,
            ),
            *perturb_parameters(evaluator),
        )
        report = build_report(evaluator, variants, seed=args.seed)
        yield bundle_module.measured(3, header + report.render())
    else:
        yield bundle_module.missing(3, _SKIPPED.format(section=3))

    if 4 in sections and args.volume_start and args.volume_end:
        try:
            with open_product_database(storage.database_path) as connection:
                volume = measure_volume(
                    connection, args.volume_start, args.volume_end, guard=StorageGuard()
                )
        except VolumeUnavailableError as error:
            yield bundle_module.missing(4, str(error))
        else:
            yield bundle_module.measured(4, volume.render())
    elif 4 in sections:
        yield (
            bundle_module.missing(
                4,
                "No day range was given. §4 needs at least one full week including a weekend; "
                "re-run with --volume-start and --volume-end.",
            )
        )
    else:
        yield bundle_module.missing(4, _SKIPPED.format(section=4))

    if 5 in sections:
        redundancy = measure_redundancy(str(evaluator.day), evaluator.baseline().conditions)
        yield bundle_module.measured(5, header + redundancy.render())
    else:
        yield bundle_module.missing(5, _SKIPPED.format(section=5))


def _load_day(args: argparse.Namespace, storage: StorageConfig) -> DayInputs:
    if not args.source:
        with open_product_database(storage.database_path) as connection:
            return load_from_history(connection, args.day)
    paths = OperationsPaths.from_env(storage.database_path)
    source = SourceConfig.from_env()
    with ReadOnlyQueryRunner(create_source_client(source)) as runner:
        return load_from_source(
            runner,
            paths.sql_dir,
            args.day,
            timeout_seconds=source.query_timeout_seconds,
        )


def _hosts(evaluator: DayEvaluator, count: int) -> tuple[str, ...]:
    """A deterministic host sample: the first `count` addresses in canonical order.

    Deterministic rather than random on purpose — a sweep that draws different hosts each run
    cannot be compared to the last one, and §1 is a claim about a region, not about a draw.
    """
    population = sorted({row.client_ip for row in evaluator.staged.client_rows})
    if not population:
        raise ValueError("the day has no hosts to inject into")
    return tuple(population[:count])


def _volume(args: argparse.Namespace) -> int:
    storage = StorageConfig.from_env()
    with open_product_database(storage.database_path) as connection:
        print(measure_volume(connection, args.start, args.end, guard=StorageGuard()).render())
    return 0


def _seed(args: argparse.Namespace) -> int:
    storage = StorageConfig.from_env()
    excluded = tuple(
        date.fromisoformat(value.strip()) for value in args.exclude.split(",") if value.strip()
    )
    report = seed_history_before(
        storage.database_path,
        args.into,
        args.day,
        migrations=storage.migration_path,
        exclude_days=excluded,
    )
    print(report.render())
    return 0


def _shadow(args: argparse.Namespace) -> int:
    storage = StorageConfig.from_env()
    with open_product_database(storage.database_path) as connection:
        inputs = load_from_history(connection, args.day)
    print(inputs.render(), file=sys.stderr)

    policy = BeaconPolicy()
    funnel = beacon_candidates(args.day, inputs.staged.service_rows, policy)
    print(funnel.render())

    if args.sensitivity:
        population = sorted({row.client_ip for row in inputs.staged.client_rows})
        hosts = tuple(population[: args.hosts])
        if not hosts:
            print("\nno hosts available to inject into", file=sys.stderr)
            return 1
        print(
            f"\nsensitivity sweep: {len(args.periods)} periods x 2 jitter settings x "
            f"{len(hosts)} hosts",
            file=sys.stderr,
        )
        cells = measure_beacon_sensitivity(
            args.day,
            hosts,
            args.periods,
            occurrences=args.occurrences,
            up_bytes_per_contact=args.amplitude,
            policy=policy,
            seed=args.seed,
        )
        print("\nperiod(min)  jitter(min)  injections  surfaced  rate")
        for cell in cells:
            print(
                f"{cell.period_minutes:>11}  {cell.jitter_minutes:>11}  "
                f"{cell.injections:>10}  {cell.surfaced:>8}  {cell.surfaced_rate:.0%}"
            )
    return 0


def _integers(raw: str) -> tuple[int, ...]:
    values = tuple(int(item) for item in raw.split(",") if item.strip())
    if not values:
        raise ValueError("expected at least one comma-separated integer")
    return values


def _sections(raw: str) -> frozenset[int]:
    values = {int(item) for item in raw.split(",") if item.strip()}
    unknown = values - set(ALL_SECTIONS)
    if unknown:
        raise ValueError(f"unknown section(s): {sorted(unknown)}")
    return frozenset(values)


if __name__ == "__main__":
    raise SystemExit(main())
