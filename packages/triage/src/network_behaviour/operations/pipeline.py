"""Atomic all-eligible day publication over the deterministic core."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

import duckdb

from network_behaviour.aggregation import COMPATIBLE_AGGREGATION_VERSIONS, StagedDay
from network_behaviour.baselines import COMPATIBLE_BASELINE_VERSIONS, SourceQualityInput
from network_behaviour.detectors import (
    DetectorPolicy,
    DnsDailyObservation,
    DnsSourceReader,
)
from network_behaviour.detectors.dns import DNS_QUERY_VERSION, dns_population_by_day
from network_behaviour.drift import (
    DayShape,
    DnsCoverage,
    DriftAssessment,
    DriftPolicy,
    assess,
    assess_dns_coverage,
    basis_counts,
)
from network_behaviour.feed import StreamBuildMetadata, build_daily_evidence_stream
from network_behaviour.operations.scoring import ScoringPolicies, score_day
from network_behaviour.population import PopulationCensus
from network_behaviour.publication import (
    COMPATIBLE_NORMALIZATION_BUNDLE_VERSIONS,
    COMPATIBLE_RECONCILIATION_VERSIONS,
    DayPublisher,
    PublicationResult,
    StorageGuard,
    normalization_bundle_version,
)
from network_behaviour.ranking import COMPATIBLE_BEHAVIOUR_VERSION_PAIRS, RankingPolicy
from network_behaviour.source.client import ReadOnlyQueryRunner, bytes_read
from network_behaviour.source.contracts import run_source_contract_check
from network_behaviour.source.day import (
    COMPATIBLE_QUERY_VERSIONS_JSON,
    COMPATIBLE_SOURCE_QUERY_BUNDLE_VERSIONS,
    SOURCE_QUERY_BUNDLE_VERSION,
    SOURCE_QUERY_VERSIONS,
    SourceDayInputs,
    SourceDayReader,
)
from network_behaviour.source.sql import SqlLoader
from network_behaviour.storage.feed import (
    DailyFeedRepository,
    FeedDayKind,
    FeedStorageError,
    FeedStorageGuard,
)
from network_behaviour.storage.migrations import COMPATIBLE_SCHEMA_VERSIONS
from network_behaviour.time import UtcDay

ACTIVITY_DETAIL_TTL_DAYS = 15
"""The original probe's detail retention (`CASE_STUDY` §1), for a provider that does not say its own
(`detail_ttl_days`). A day older than this cannot be re-derived there, only replayed."""
_LOGGER = logging.getLogger("network_behaviour.operations")


class DayRunError(RuntimeError):
    """Raised when a day cannot safely progress through publication."""


class DayInputProvider(Protocol):
    def load(
        self, day: UtcDay
    ) -> tuple[SourceDayInputs, StagedDay, tuple[DnsDailyObservation, ...]]: ...


@dataclass(frozen=True, slots=True)
class DayRunReport:
    day: str
    status: str
    run_id: UUID | None
    client_rows: int
    supported_client_rows: int
    out_of_scope_client_rows: int
    service_rows: int
    candidate_rows: int
    query_count: int
    source_read_rows: int
    source_read_bytes: int
    storage_bytes: int | None

    def render(self) -> str:
        return "\n".join(
            (
                f"status: {self.status}",
                f"day: {self.day}",
                f"run_id: {self.run_id or 'none'}",
                f"client rows: {self.client_rows}",
                f"supported client rows: {self.supported_client_rows}",
                f"out-of-scope client rows: {self.out_of_scope_client_rows}",
                f"service rows: {self.service_rows}",
                f"candidate rows: {self.candidate_rows}",
                f"query footprint: {self.query_count} queries, {self.source_read_rows} rows read"
                f"{bytes_read(self.source_read_bytes)}",
                "projected storage bytes: "
                f"{self.storage_bytes if self.storage_bytes is not None else 'not_measured'}",
            )
        )


class SourceDayInputProvider:
    """Perform the bounded source checks and streamed day aggregation exactly once."""

    def __init__(
        self,
        runner: ReadOnlyQueryRunner,
        sql_root: Path,
        *,
        timeout_seconds: int,
        detail_ttl_days: int | None = None,
    ) -> None:
        self._runner = runner
        self._sql_root = sql_root
        self._timeout_seconds = timeout_seconds
        self.detail_ttl_days = detail_ttl_days
        """None: the source keeps a day's detail for as long as it stays loaded."""

    def load(
        self, day: UtcDay
    ) -> tuple[SourceDayInputs, StagedDay, tuple[DnsDailyObservation, ...]]:
        contract = run_source_contract_check(
            self._runner,
            SqlLoader(self._sql_root),
            day,
            timeout_seconds=self._timeout_seconds,
            metadata_only=False,
        )
        if not contract.passed:
            raise DayRunError("source contract or completed-day coverage failed")
        source, staged = SourceDayReader(
            self._runner,
            self._sql_root,
            timeout_seconds=self._timeout_seconds,
        ).read_and_aggregate(day, contract)
        dns = DnsSourceReader(
            self._runner,
            self._sql_root,
            timeout_seconds=self._timeout_seconds,
        ).read(day)
        dns_audits = dns.audits
        source = replace(
            source,
            query_versions_json=_source_query_versions_json(),
            query_count=source.query_count + len(dns_audits),
            returned_rows=source.returned_rows + sum(audit.returned_rows for audit in dns_audits),
            read_rows=source.read_rows + sum(audit.read_rows for audit in dns_audits),
            read_bytes=source.read_bytes + sum(audit.read_bytes for audit in dns_audits),
            elapsed_seconds=source.elapsed_seconds
            + sum(audit.elapsed_seconds for audit in dns_audits),
        )
        return source, staged, dns.observations


class DayRunService:
    def __init__(
        self,
        connection: duckdb.DuckDBPyConnection,
        ranking_policy: RankingPolicy,
        storage_guard: StorageGuard,
        *,
        feed_storage_guard: FeedStorageGuard | None = None,
        drift_policy: DriftPolicy | None = None,
        detector_policy: DetectorPolicy | None = None,
    ) -> None:
        self._connection = connection
        self._ranking_policy = ranking_policy
        self._storage_guard = storage_guard
        self._drift_policy = drift_policy or DriftPolicy()
        # Pinnable for the same reason `ranking_policy` is: a replay of a day published under an
        # earlier detector generation has to be able to state that generation rather than silently
        # re-derive it under the current one. Reruns are forward-only, so nothing in the ordinary
        # publication path passes this.
        self._detector_policy = detector_policy or DetectorPolicy()
        self._feed_storage_guard = feed_storage_guard or FeedStorageGuard(
            storage_guard.alert_bytes,
            storage_guard.stop_bytes,
        )
        if (
            self._feed_storage_guard.alert_bytes != storage_guard.alert_bytes
            or self._feed_storage_guard.stop_bytes != storage_guard.stop_bytes
        ):
            raise ValueError("history and feed storage guards must use the same thresholds")

    def preflight(self, day: UtcDay, *, now: datetime | None = None) -> DayRunReport:
        current = datetime.now(UTC) if now is None else now
        day.ensure_completed(current)
        published = self._published(day)
        if published is not None:
            return published
        history = self._history_counts(day)
        if history != (0, 0):
            raise DayRunError("day history exists without a published manifest")
        return DayRunReport(str(day), "ready", None, 0, 0, 0, 0, 0, 0, 0, 0, None)

    def run(
        self,
        day: UtcDay,
        provider: DayInputProvider,
        *,
        now: datetime | None = None,
    ) -> DayRunReport:
        current = datetime.now(UTC) if now is None else now
        day.ensure_completed(current)
        published = self._published(day)
        if published is not None:
            return published
        self._recover_interrupted(day, current)
        run_id = self._start_run(day, current)
        _LOGGER.info("day run started", extra={"day": str(day), "run_id": str(run_id)})
        try:
            source, staged, dns = provider.load(day)
            if source.day != day or staged.day != day:
                raise DayRunError("source provider returned a different UTC day")
            if source.query_versions_json != _source_query_versions_json():
                raise DayRunError("source provider query versions are incompatible")
            ttl = getattr(provider, "detail_ttl_days", ACTIVITY_DETAIL_TTL_DAYS)
            # None: the source keeps the day's detail, so the stream names no expiry.
            detail_expires_at = None if ttl is None else day.bounds.end + timedelta(days=ttl)
            if detail_expires_at is not None and current >= detail_expires_at:
                raise DayRunError("principal source detail has expired for this day")
            _LOGGER.info(
                "day source aggregation completed",
                extra={
                    "day": str(day),
                    "run_id": str(run_id),
                    "query_count": source.query_count,
                    "read_rows": source.read_rows,
                    "read_bytes": source.read_bytes,
                    "client_rows": len(staged.client_rows),
                    "service_rows": len(staged.service_rows),
                },
            )
            # Tier 0 invariant 5. Checked here rather than inside the publication transaction:
            # a source that has changed shape underneath this day should cost nothing to
            # discover, and nothing has been written yet, so the abort has nothing to roll back.
            drift = self._assess_drift(day, staged)
            dns_coverage = self._assess_dns_coverage(day, dns)
            _LOGGER.info(
                "day drift assessment completed",
                extra={
                    "day": str(day),
                    "run_id": str(run_id),
                    "drift_passed": drift.passed,
                    "drift_policy": drift.policy.version,
                    "dns_enabled": dns_coverage is None or dns_coverage.dns_enabled,
                    "dns_coverage": None if dns_coverage is None else dns_coverage.check.detail,
                },
            )
            reason = drift.failure_reason()
            if reason is not None:
                raise DayRunError(f"source drift gate: {reason}")
        except Exception as exc:
            self._fail_run(run_id, datetime.now(UTC), type(exc).__name__)
            _LOGGER.error(
                "day run failed",
                extra={"day": str(day), "run_id": str(run_id), "failure_code": type(exc).__name__},
            )
            raise

        # The census is produced inside the transaction and reported outside it, so a run
        # states what it put in scope whether or not anything downstream reads the column.
        captured: dict[str, PopulationCensus] = {}

        def score_and_publish(
            connection: duckdb.DuckDBPyConnection, scored_day: UtcDay, run_id: UUID
        ) -> int:
            scored = score_day(
                connection,
                scored_day,
                staged,
                dns,
                policies=ScoringPolicies(
                    ranking=self._ranking_policy,
                    detector=self._detector_policy,
                    # DNS and long flows are optional context. A DNS population that moved beyond
                    # tolerance turns the DNS family off for the day, as an absent source would; an
                    # absent long-flow source is reported as missing context. Neither lowers a
                    # strength or fails the day.
                    source_quality=SourceQualityInput(
                        dns_context_available=dns_coverage is None or dns_coverage.dns_enabled,
                        long_flow_context_available=source.long_flow_context_available,
                    ),
                ),
            )
            ranking = scored.ranking
            captured["census"] = scored.census
            stream = build_daily_evidence_stream(
                ranking,
                StreamBuildMetadata(
                    run_id,
                    current,
                    current,
                    detail_expires_at,
                ),
                {service_id.hex(): domain for service_id, domain in staged.service_domains.items()},
            )
            expected_evidence = sum(len(item.evidence) for item in stream.episodes)
            history_reserved_bytes = (
                len(staged.client_rows) * self._storage_guard.estimated_client_row_bytes
                + len(staged.service_rows) * self._storage_guard.estimated_service_row_bytes
            )
            feed_publication = DailyFeedRepository(
                connection,
                self._feed_storage_guard,
            ).publish_in_transaction(
                stream,
                reserved_bytes=history_reserved_bytes,
            )
            if (
                stream.header.episode_count != len(ranking.ranked_eligible)
                or feed_publication.candidate_rows != len(ranking.ranked_eligible)
                or feed_publication.evidence_rows != expected_evidence
            ):
                raise DayRunError("ranked and persisted stream populations did not reconcile")
            connection.execute(
                """
                UPDATE ops.pipeline_run
                SET detector_version = ?, baseline_version = ?,
                    supported_client_rows = ?, out_of_scope_client_rows = ?,
                    population_definition_version = ?
                WHERE run_id = ?
                """,
                [
                    f"{self._detector_policy.version}/{self._ranking_policy.version}",
                    scored.baselines.version,
                    scored.census.supported,
                    scored.census.out_of_scope,
                    scored.census.definition_version,
                    run_id,
                ],
            )
            return feed_publication.storage.projected_bytes

        publication = DayPublisher(self._connection, storage_guard=self._storage_guard).publish(
            source,
            staged,
            score_and_publish,
            now=current,
            existing_run_id=run_id,
        )
        stored_stream = DailyFeedRepository(self._connection).published_metadata(day)
        if stored_stream.run_id != publication.run_id:
            raise DayRunError("published history and complete stream use different runs")
        candidate_count = stored_stream.candidate_count
        census = captured.get("census")
        if census is None:
            raise DayRunError("publication completed without a population census")
        report = _publication_report(publication, source, candidate_count, census)
        _LOGGER.info(
            "day publication completed",
            extra={
                "day": str(day),
                "run_id": str(run_id),
                "candidate_rows": candidate_count,
                "projected_storage_bytes": publication.storage.projected_bytes,
            },
        )
        return report

    def _recover_interrupted(self, day: UtcDay, now: datetime) -> None:
        self._connection.execute(
            """
            UPDATE ops.pipeline_run
            SET status = 'failed', completed_at = ?, failure_code = 'interrupted_before_publication'
            WHERE day = ? AND status IN ('created', 'running')
            """,
            [now, day.value],
        )

    def _start_run(self, day: UtcDay, now: datetime) -> UUID:
        run_id = uuid4()
        schema_version = _scalar_int(
            self._connection,
            "SELECT max(version) FROM _schema_migrations",
            [],
        )
        self._connection.execute(
            """
            INSERT INTO ops.pipeline_run (
                run_id, day, status, started_at, source_sql_version, schema_version,
                normalization_version
            ) VALUES (?, ?, 'running', ?, ?, ?, ?)
            """,
            [
                run_id,
                day.value,
                now,
                SOURCE_QUERY_BUNDLE_VERSION,
                schema_version,
                normalization_bundle_version(),
            ],
        )
        return run_id

    def _fail_run(self, run_id: UUID, now: datetime, failure_code: str) -> None:
        self._connection.execute(
            """
            UPDATE ops.pipeline_run
            SET status = 'failed', completed_at = ?, failure_code = ?
            WHERE run_id = ? AND status = 'running'
            """,
            [now, failure_code[:80], run_id],
        )

    def _published(self, day: UtcDay) -> DayRunReport | None:
        row = self._connection.execute(
            """
            SELECT run_id, staged_client_rows, staged_service_rows, query_count,
                   source_read_rows, source_read_bytes, projected_storage_bytes,
                   source_sql_version, schema_version, normalization_version,
                   query_versions_json, aggregation_version, reconciliation_version,
                   detector_version, baseline_version,
                   supported_client_rows, out_of_scope_client_rows
            FROM ops.pipeline_run
            WHERE day = ? AND status = 'published'
            ORDER BY completed_at DESC LIMIT 1
            """,
            [day.value],
        ).fetchone()
        if row is None:
            return None
        feed_repository = DailyFeedRepository(self._connection)
        kind = feed_repository.day_kind(day)
        if kind is FeedDayKind.LEGACY_SELECTED:
            raise DayRunError(
                "published day has only pre-cutover selected output, not a complete feed"
            )
        if kind is FeedDayKind.ABSENT:
            raise DayRunError("published day is missing its complete feed")
        try:
            stored = feed_repository.published_metadata(day)
        except FeedStorageError as exc:
            raise DayRunError("published complete feed failed stored-boundary validation") from exc
        if stored.run_id != row[0]:
            raise DayRunError("published history and complete feed use different runs")
        feed_behavior_versions = (
            stored.detector_version,
            stored.ranking_version,
        )
        if feed_behavior_versions not in COMPATIBLE_BEHAVIOUR_VERSION_PAIRS:
            raise DayRunError(
                "published day uses incompatible versions; chronological replay is required"
            )
        # An allow-list, not strict equality, and NULL is a day published before migration 0009.
        # Both are the forward-only policy: a published day keeps the generation it was built
        # under and stays readable, because it cannot be re-derived once its source has expired.
        stored_baseline = row[14]
        if stored_baseline is not None and str(stored_baseline) not in (
            COMPATIBLE_BASELINE_VERSIONS
        ):
            raise DayRunError(
                "published day uses an incompatible baseline generation; "
                "chronological replay is required"
            )
        # Membership, not equality, for every generation the day was written under: the same
        # forward-only reason as the two allow-lists above. Strict equality with the current schema
        # stranded the 25 days published at schema 7. What stays strict is integrity — the run
        # record and the stored feed must name the same behaviour pair.
        if (
            str(row[7]) not in COMPATIBLE_SOURCE_QUERY_BUNDLE_VERSIONS
            or int(row[8]) not in COMPATIBLE_SCHEMA_VERSIONS
            or str(row[9]) not in COMPATIBLE_NORMALIZATION_BUNDLE_VERSIONS
            or str(row[10]) not in COMPATIBLE_QUERY_VERSIONS_JSON
            or str(row[11]) not in COMPATIBLE_AGGREGATION_VERSIONS
            or str(row[12]) not in COMPATIBLE_RECONCILIATION_VERSIONS
            or str(row[13]) != "/".join(feed_behavior_versions)
        ):
            raise DayRunError(
                "published day uses incompatible versions; chronological replay is required"
            )
        candidate_count = stored.candidate_count
        return DayRunReport(
            str(day),
            "already_published",
            row[0],
            int(row[1] or 0),
            int(row[15] or 0),
            int(row[16] or 0),
            int(row[2] or 0),
            candidate_count,
            int(row[3] or 0),
            int(row[4] or 0),
            int(row[5] or 0),
            int(row[6]) if row[6] is not None else None,
        )

    def _assess_drift(self, day: UtcDay, staged: StagedDay) -> DriftAssessment:
        """Compare this day's scored population and service mix against their priors."""

        scored = {row.client_ip for row in staged.service_rows}
        observed = {row.client_ip for row in staged.client_rows}
        current = DayShape(
            day.value,
            len(scored),
            basis_counts([row.service_basis for row in staged.service_rows]),
            unaddressed_only=len(observed - scored),
        )
        return assess(
            current,
            self._population_prior(day),
            self._composition_prior(day),
            self._drift_policy,
        )

    def _assess_dns_coverage(
        self, day: UtcDay, dns: tuple[DnsDailyObservation, ...]
    ) -> DnsCoverage | None:
        """The DNS population against the same weekday, from the observations already read.

        `None` when there are no DNS observations at all: the DNS family is then already off for
        want of context, and there is nothing to compare.
        """

        if not dns:
            return None
        populations = dns_population_by_day(dns, self._detector_policy)
        today = populations.get(day.value)
        earlier = [
            item
            for item in populations.values()
            if item.day < day.value
            and item.day.isoweekday() == day.value.isoweekday()
            and item.clients
        ]
        prior = max(earlier, key=lambda item: item.day) if earlier else None
        return assess_dns_coverage(
            day.value,
            len(today.clients) if today is not None else 0,
            None if prior is None else (prior.day, len(prior.clients)),
            self._drift_policy,
        )

    def _population_prior(self, day: UtcDay) -> DayShape | None:
        """The most recent retained day with the same UTC weekday, or `None` if there is none.

        Counted from `history.client_service_day`, the population relationship and persistence
        prevalence are drawn from, so the prior is measured exactly as the current day is whatever
        support definition either day ran under. The scored population tracks the week, which is
        why the comparison is weekday to weekday rather than day to day (`drift.py`).
        """

        row = self._connection.execute(
            """
            SELECT day, count(DISTINCT client_ip) FROM history.client_service_day
            WHERE day = (
                SELECT max(day) FROM history.client_service_day
                WHERE day < ? AND isodow(day) = ?
            )
            GROUP BY day
            """,
            [day.value, day.value.isoweekday()],
        ).fetchone()
        if row is None or row[0] is None:
            return None
        return DayShape(row[0], int(row[1]), ())

    def _composition_prior(self, day: UtcDay) -> DayShape | None:
        """The most recent published day before `day`, or `None` on a deployment's first run."""

        prior = self._connection.execute(
            "SELECT max(day) FROM history.client_day WHERE day < ?", [day.value]
        ).fetchone()
        if prior is None or prior[0] is None:
            return None
        prior_day: date = prior[0]
        bases = self._connection.execute(
            """
            SELECT service_basis, count(*) FROM history.client_service_day
            WHERE day = ? GROUP BY service_basis
            """,
            [prior_day],
        ).fetchall()
        return DayShape(prior_day, 0, tuple(sorted((str(row[0]), int(row[1])) for row in bases)))

    def _history_counts(self, day: UtcDay) -> tuple[int, int]:
        row = self._connection.execute(
            """
            SELECT
                (SELECT count(*) FROM history.client_day WHERE day = ?),
                (SELECT count(*) FROM history.client_service_day WHERE day = ?)
            """,
            [day.value, day.value],
        ).fetchone()
        if row is None:
            raise DayRunError("history counts are unavailable")
        return int(row[0]), int(row[1])


def run_days_sequentially(
    start: UtcDay,
    end: UtcDay,
    run_day: Callable[[UtcDay], DayRunReport],
) -> tuple[DayRunReport, ...]:
    if end < start:
        raise ValueError("end day cannot precede start day")
    reports = []
    current: date = start.value
    while current <= end.value:
        reports.append(run_day(UtcDay(current)))
        current += timedelta(days=1)
    return tuple(reports)


def _publication_report(
    publication: PublicationResult,
    source: SourceDayInputs,
    candidate_count: int,
    census: PopulationCensus,
) -> DayRunReport:
    return DayRunReport(
        str(publication.day),
        "already_published" if publication.idempotent else "published",
        publication.run_id,
        publication.client_rows,
        census.supported,
        census.out_of_scope,
        publication.service_rows,
        candidate_count,
        source.query_count,
        source.read_rows,
        source.read_bytes,
        publication.storage.projected_bytes,
    )


def _scalar_int(connection: duckdb.DuckDBPyConnection, query: str, parameters: list[object]) -> int:
    row = connection.execute(query, parameters).fetchone()
    if row is None:
        raise DayRunError("operational count is unavailable")
    return int(row[0])


def _source_query_versions_json() -> str:
    versions = dict(SOURCE_QUERY_VERSIONS)
    versions["dns_daily_observations"] = DNS_QUERY_VERSION
    return json.dumps(versions, sort_keys=True, separators=(",", ":"))
