"""Command-line workflows for the deterministic behavioural publisher."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

import duckdb

from network_behaviour import __version__
from network_behaviour.config import (
    ClickHouseConfig,
    ConfigurationError,
    load_default_environment,
)
from network_behaviour.operations.config import OperationsPaths, StorageControls
from network_behaviour.operations.locking import WriterLock
from network_behaviour.operations.logging import configure_json_logging
from network_behaviour.operations.pipeline import (
    ClickHouseDayInputProvider,
    DayRunService,
    run_days_sequentially,
)
from network_behaviour.operations.storage import (
    create_backup,
    restore_backup,
    storage_report,
)
from network_behaviour.publication import StorageGuard
from network_behaviour.ranking import RankingPolicy
from network_behaviour.source.client import ReadOnlyQueryRunner, create_clickhouse_client
from network_behaviour.source.contracts import run_source_contract_check
from network_behaviour.source.sql import SqlLoader
from network_behaviour.storage.feed import DailyFeedRepository
from network_behaviour.storage.repository import DuckDbStore, StorageConfig
from network_behaviour.time import UtcDay


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-behaviour",
        description="Publish one deterministic daily behavioural candidate feed.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="{run-day}")

    def internal_parser(name: str, *, description: str | None = None) -> argparse.ArgumentParser:
        command = subparsers.add_parser(name, help=argparse.SUPPRESS, description=description)
        subparsers._choices_actions.pop()
        return command

    source_check = internal_parser("source-check")
    source_check.add_argument("--day", type=UtcDay.parse)
    source_check.add_argument("--metadata-only", action="store_true")

    run_day = subparsers.add_parser("run-day", help="process and publish one completed UTC day")
    run_day.add_argument("--day", required=True, type=UtcDay.parse)
    run_day.add_argument("--dry-run", action="store_true", help=argparse.SUPPRESS)

    for name, description in (
        ("backfill", "process an inclusive UTC day range sequentially"),
        ("replay", "idempotently replay an inclusive UTC day range sequentially"),
    ):
        command = internal_parser(name, description=description)
        command.add_argument("--start", required=True, type=UtcDay.parse)
        command.add_argument("--end", required=True, type=UtcDay.parse)

    internal_parser("storage-report")
    backup = internal_parser("backup")
    backup.add_argument("--output", required=True, type=Path)
    restore = internal_parser("restore")
    restore.add_argument("--input", required=True, type=Path)
    restore.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command is None:
        return 0
    try:
        load_default_environment()
        configure_json_logging()
        if args.command == "source-check":
            return _source_check(args)
        if args.command == "run-day":
            return _run_day(args)
        if args.command in {"backfill", "replay"}:
            return _run_range(args)
        if args.command == "storage-report":
            return _storage_report()
        if args.command == "backup":
            return _backup(args)
        if args.command == "restore":
            return _restore(args)
        raise ValueError("unsupported command")
    except (ConfigurationError, ValueError, RuntimeError, OSError, duckdb.Error) as exc:
        print(f"{args.command} blocked: {exc}", file=sys.stderr)
        return 2


def _source_check(args: argparse.Namespace) -> int:
    day = args.day or UtcDay.latest_completed()
    day.ensure_completed()
    config = ClickHouseConfig.from_env()
    sql_dir = Path(os.getenv("NETWORK_BEHAVIOUR_SQL_DIR", "sql/clickhouse"))
    with ReadOnlyQueryRunner(create_clickhouse_client(config)) as runner:
        report = run_source_contract_check(
            runner,
            SqlLoader(sql_dir),
            day,
            timeout_seconds=config.query_timeout_seconds,
            metadata_only=args.metadata_only,
        )
    print(report.render())
    return 0 if report.passed else 1


def _run_day(args: argparse.Namespace) -> int:
    storage_config = StorageConfig.from_env()
    paths = OperationsPaths.from_env(storage_config.database_path)
    controls = StorageControls.from_env()
    with WriterLock(paths.lock_path), DuckDbStore(storage_config) as store:
        service = DayRunService(
            store.connection,
            RankingPolicy(),
            StorageGuard(controls.alert_bytes, controls.stop_bytes),
        )
        if args.dry_run:
            report = service.preflight(args.day)
        else:
            report = service.preflight(args.day)
            if report.status != "already_published":
                clickhouse = ClickHouseConfig.from_env()
                with ReadOnlyQueryRunner(create_clickhouse_client(clickhouse)) as runner:
                    service.run(
                        args.day,
                        ClickHouseDayInputProvider(
                            runner, paths.sql_dir, timeout_seconds=clickhouse.query_timeout_seconds
                        ),
                    )
            _write_stream(DailyFeedRepository(store.connection).load_jsonl(args.day))
    if args.dry_run:
        print(report.render())
    return 0


def _run_range(args: argparse.Namespace) -> int:
    storage_config = StorageConfig.from_env()
    paths = OperationsPaths.from_env(storage_config.database_path)
    controls = StorageControls.from_env()
    clickhouse = ClickHouseConfig.from_env()
    with (
        WriterLock(paths.lock_path),
        DuckDbStore(storage_config) as store,
        ReadOnlyQueryRunner(create_clickhouse_client(clickhouse)) as runner,
    ):
        service = DayRunService(
            store.connection,
            RankingPolicy(),
            StorageGuard(controls.alert_bytes, controls.stop_bytes),
        )
        provider = ClickHouseDayInputProvider(
            runner, paths.sql_dir, timeout_seconds=clickhouse.query_timeout_seconds
        )
        reports = run_days_sequentially(
            args.start, args.end, lambda day: service.run(day, provider)
        )
    print("\n\n".join(report.render() for report in reports))
    return 0


def _storage_report() -> int:
    config = StorageConfig.from_env()
    paths = OperationsPaths.from_env(config.database_path)
    controls = StorageControls.from_env()
    with WriterLock(paths.lock_path), DuckDbStore(config) as store:
        report = storage_report(store.connection, controls)
    print(report.render())
    return 2 if report.stop else 1 if report.alert else 0


def _backup(args: argparse.Namespace) -> int:
    config = StorageConfig.from_env()
    paths = OperationsPaths.from_env(config.database_path)
    with WriterLock(paths.lock_path), DuckDbStore(config) as store:
        create_backup(store.connection, config.database_path, args.output)
    print(f"backup created: {args.output}")
    return 0


def _restore(args: argparse.Namespace) -> int:
    migrations = Path(os.getenv("NETWORK_BEHAVIOUR_MIGRATION_DIR", "sql/migrations"))
    lock_path = Path(f"{args.output}.lock")
    with WriterLock(lock_path):
        restore_backup(args.input, args.output, migrations)
    print(f"restore created: {args.output}")
    return 0


def _write_stream(records: Iterator[bytes]) -> None:
    """Write the published day in whatever encoding it was published under."""
    if not hasattr(sys.stdout, "buffer"):
        raise RuntimeError("standard output does not support binary stream output")
    for record in records:
        sys.stdout.buffer.write(record)
    sys.stdout.buffer.flush()
