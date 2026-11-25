"""A generated Zeek day, loaded, passes every source check and publishes through the unchanged
pipeline. The day is synthetic: `10.1.0.0/24` hosts, documentation-range servers, `.test` names."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from pathlib import Path

import duckdb
import pytest
from zeek_logs import DAY, at, conn, dns, write_json

from network_behaviour.config import SourceConfig
from network_behaviour.operations.pipeline import (
    DayRunError,
    DayRunService,
    SourceDayInputProvider,
)
from network_behaviour.publication import StorageGuard
from network_behaviour.ranking import RankingPolicy
from network_behaviour.source.client import ReadOnlyQueryRunner, create_source_client
from network_behaviour.source.contracts import run_source_contract_check
from network_behaviour.source.sql import SqlLoader
from network_behaviour.source.zeek import load_day
from network_behaviour.storage.migrations import MigrationRunner
from network_behaviour.time import UtcDay

ROOT = Path(__file__).parents[3]
SQL_ROOT = ROOT / "sql" / "source"
MIGRATIONS = ROOT / "sql" / "migrations"
HOSTS = [f"10.1.0.{n}" for n in range(1, 7)]
SITES = [("198.51.100.10", "www.news.test"), ("198.51.100.20", "api.mail.test"),
         ("203.0.113.30", "cdn.video.test")]  # fmt: skip
RESOLVER = "198.51.100.53"


def _write_day(logs: Path) -> None:
    conns, ssl, answers = [], [], []
    start = at("00:00:00")
    for h, host in enumerate(HOSTS):
        for minute in range(1440):
            address, name = SITES[(h + minute) % len(SITES)]
            uid = f"C{h}-{minute}"
            ts = start + minute * 60 + 5 + h
            conns.append(conn(uid, ts, host, address, duration=20.0, orig_bytes=300 + h,
                              resp_bytes=4000 + minute % 7))  # fmt: skip
            ssl.append({"ts": ts, "uid": uid, "server_name": name})
        for hour in range(24):
            uid = f"D{h}-{hour}"
            ts = start + hour * 3600 + h
            address, name = SITES[hour % len(SITES)]
            answers.append(dns(uid, ts, host, RESOLVER, name, [address], [300.0]))
            conns.append(conn(uid, ts, host, RESOLVER, proto="udp", resp_p=53, service="dns",
                              orig_pkts=1, resp_pkts=1, duration=0.02))  # fmt: skip
    conns.append(conn("BIG", start + 3 * 3600, HOSTS[0], "203.0.113.30", duration=900.0,
                      orig_bytes=2_500_000, resp_bytes=100_000))  # fmt: skip
    folder = logs / DAY.isoformat()
    write_json(folder, "conn", conns)
    write_json(folder, "ssl", ssl)
    write_json(folder, "dns", answers)


@pytest.mark.usefixtures("synthetic")
def test_a_loaded_zeek_day_passes_the_source_checks_and_publishes(tmp_path: Path) -> None:
    source = tmp_path / "source.duckdb"
    _write_day(tmp_path / "logs")
    report = load_day(source, DAY, [tmp_path / "logs"], local_nets=(IPv4Network("10.0.0.0/8"),))
    day = UtcDay(DAY)

    with ReadOnlyQueryRunner(create_source_client(SourceConfig(source))) as runner:
        contract = run_source_contract_check(
            runner, SqlLoader(SQL_ROOT), day, timeout_seconds=60, metadata_only=False
        )
        assert contract.passed, contract.render()
        reconciliation = contract.reconciliation
        assert reconciliation is not None
        # The rate table is written from the activity minutes: the two agree exactly.
        assert reconciliation.activity_up_bytes == reconciliation.rate_up_bytes > 0
        assert reconciliation.activity_down_bytes == reconciliation.rate_down_bytes
        # Rows are aggregated per grain, so the duplicate check finds none.
        assert reconciliation.activity_rows == reconciliation.unique_activity_grain_rows
        assert contract.long_flow_rows == 1
        assert contract.read_rows > 0

        # A loaded source keeps the day's detail, so the day publishes long after the original
        # probe's fifteen days; a source configured with that retention still refuses.
        later = datetime.combine(DAY + timedelta(days=60), datetime.min.time(), UTC)
        store = duckdb.connect(":memory:")
        MigrationRunner(MIGRATIONS).apply(store)
        service = DayRunService(store, RankingPolicy(), StorageGuard())
        with pytest.raises(DayRunError, match="detail has expired"):
            service.run(
                day,
                SourceDayInputProvider(runner, SQL_ROOT, timeout_seconds=60, detail_ttl_days=15),
                now=later,
            )
        published = service.run(
            day, SourceDayInputProvider(runner, SQL_ROOT, timeout_seconds=60), now=later
        )

    assert report.connections == len(HOSTS) * (1440 + 24) + 1
    assert published.status == "published"
    assert published.client_rows == len(HOSTS)
    assert published.service_rows >= len(HOSTS) * len(SITES)
    assert store.execute("SELECT normalization_version FROM ops.pipeline_run").fetchone() == (
        "service-id-v1/category-id-v1/port-groups-v1/bitmap-288-lsb-v1/tldextract-5.3.1+synthetic",
    )
