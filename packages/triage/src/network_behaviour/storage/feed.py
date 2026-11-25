"""Bulk, transactional DuckDB persistence for complete versioned daily feeds."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

import duckdb
import pyarrow as pa

from network_behaviour.baselines.models import HistoryConfidence
from network_behaviour.detectors.models import DetectorFamily
from network_behaviour.domain import EvidenceGroup
from network_behaviour.feed import (
    STREAM_SCHEMA_VERSION,
    DailyEvidenceStream,
    StreamEpisode,
    StreamEvidence,
    StreamHeader,
    iter_daily_evidence_stream_jsonl,
)
from network_behaviour.feed.legacy_v1 import (
    LEGACY_FEED_SCHEMA_VERSION,
    DailyCandidateFeed,
    DailyFeedCandidate,
    DailyFeedEvidence,
    DailyFeedHeader,
    LegacyPriorityTier,
    iter_daily_candidate_feed_jsonl,
)
from network_behaviour.ranking import DataQualityConfidence, EvidenceTier
from network_behaviour.time import UtcDay

GIB: Final = 1024**3
DEFAULT_FEED_ALERT_BYTES: Final = 40 * GIB
DEFAULT_FEED_STOP_BYTES: Final = 45 * GIB
_EPISODE_REGISTRATION = "_daily_stream_episodes"
_EVIDENCE_REGISTRATION = "_daily_stream_evidence"
_SIZE = re.compile(r"^(?P<value>[0-9]+(?:\.[0-9]+)?)\s+(?P<unit>bytes|KiB|MiB|GiB|TiB)$")


class FeedStorageError(RuntimeError):
    """Raised when complete-feed storage cannot preserve the feed contract."""


class FeedNotFoundError(FeedStorageError):
    """Raised when a day has neither complete nor legacy candidate output."""


class LegacySelectedDayError(FeedStorageError):
    """Raised when a pre-cutover selected-only day is requested as a complete feed."""


class LegacySchemaVersionError(FeedStorageError):
    """Raised when a day published under the frozen v1 schema is requested as a v2 stream."""


class FeedDayKind(StrEnum):
    ABSENT = "absent"
    LEGACY_SELECTED = "legacy_selected"
    COMPLETE = "complete_feed"


@dataclass(frozen=True, slots=True)
class FeedStorageAssessment:
    current_bytes: int
    projected_bytes: int
    alert: bool


@dataclass(frozen=True, slots=True)
class FeedStorageGuard:
    """Conservative pre-insert estimate for complete-feed retained growth."""

    alert_bytes: int = DEFAULT_FEED_ALERT_BYTES
    stop_bytes: int = DEFAULT_FEED_STOP_BYTES
    # A first row in each of the three feed tables allocates several DuckDB blocks.
    # Keep that fixed allocation conservative; per-row values are separately measured.
    estimated_header_bytes: int = 4 * 1024**2
    estimated_candidate_bytes: int = 1024
    estimated_evidence_bytes: int = 512

    def __post_init__(self) -> None:
        estimates = (
            self.estimated_header_bytes,
            self.estimated_candidate_bytes,
            self.estimated_evidence_bytes,
        )
        if not 0 < self.alert_bytes < self.stop_bytes:
            raise ValueError("feed storage alert must be positive and below the stop threshold")
        if any(value <= 0 for value in estimates):
            raise ValueError("feed storage row estimates must be positive")

    def assess(
        self,
        connection: duckdb.DuckDBPyConnection,
        *,
        candidate_rows: int,
        evidence_rows: int,
        reserved_bytes: int = 0,
    ) -> FeedStorageAssessment:
        if candidate_rows < 0 or evidence_rows < 0 or reserved_bytes < 0:
            raise ValueError("feed storage row counts and reserve cannot be negative")
        current = _database_bytes(connection)
        projected = (
            current
            + reserved_bytes
            + self.estimated_header_bytes
            + candidate_rows * self.estimated_candidate_bytes
            + evidence_rows * self.estimated_evidence_bytes
        )
        if projected >= self.stop_bytes:
            raise FeedStorageError(
                "projected complete-feed storage reaches the configured stop threshold"
            )
        return FeedStorageAssessment(current, projected, projected >= self.alert_bytes)


@dataclass(frozen=True, slots=True)
class FeedPublicationResult:
    day: str
    run_id: UUID
    candidate_rows: int
    evidence_rows: int
    serialized_bytes: int
    feed_sha256: str
    idempotent: bool
    storage: FeedStorageAssessment


@dataclass(frozen=True, slots=True)
class _StoredPublication:
    day: str
    feed_schema_version: str
    published_at: datetime
    run_id: UUID
    detector_version: str
    ranking_version: str
    candidate_count: int
    evidence_count: int
    serialized_bytes: int
    feed_sha256: str


class DailyFeedRepository:
    """Persist and reconstruct complete feeds without touching the legacy selected queue."""

    def __init__(
        self,
        connection: duckdb.DuckDBPyConnection,
        storage_guard: FeedStorageGuard | None = None,
    ) -> None:
        self._connection = connection
        self._storage_guard = storage_guard or FeedStorageGuard()

    def day_kind(self, day: UtcDay) -> FeedDayKind:
        if self._stored_publication(day) is not None:
            return FeedDayKind.COMPLETE
        if self._is_legacy_day(day):
            return FeedDayKind.LEGACY_SELECTED
        return FeedDayKind.ABSENT

    def load(self, day: UtcDay) -> DailyEvidenceStream:
        """Return a day published under the current stream schema."""

        self._require_complete(day)
        return self._load_complete(day)

    def load_jsonl(self, day: UtcDay) -> Iterator[bytes]:
        """Yield a published day in the encoding it was published under.

        A day written under the frozen v1 schema streams back as v1. Re-encoding it as v2 would
        change bytes whose digest is already stored, which Tier 0 forbids.
        """
        self._require_complete(day)
        stored = self._stored_publication(day)
        assert stored is not None  # _require_complete guarantees it
        if stored.feed_schema_version == LEGACY_FEED_SCHEMA_VERSION:
            yield from iter_daily_candidate_feed_jsonl(self._load_legacy_v1(day))
            return
        yield from iter_daily_evidence_stream_jsonl(self._load_complete(day))

    def published_metadata(self, day: UtcDay) -> _StoredPublication:
        """Header metadata for a published day, whatever schema it was written under.

        Replay and verification paths use this rather than loading a typed object, so a day
        published under the frozen v1 schema stays inspectable without being re-encoded.
        """
        self._require_complete(day)
        stored = self._stored_publication(day)
        if stored is None:  # pragma: no cover - _require_complete guarantees it
            raise FeedNotFoundError(f"no complete feed exists for {day}")
        return stored

    def _require_complete(self, day: UtcDay) -> None:
        kind = self.day_kind(day)
        if kind is FeedDayKind.LEGACY_SELECTED:
            raise LegacySelectedDayError(
                f"{day} has only pre-cutover legacy selected output, not a complete feed"
            )
        if kind is FeedDayKind.ABSENT:
            raise FeedNotFoundError(f"no complete feed exists for {day}")

    def publish(self, stream: DailyEvidenceStream) -> FeedPublicationResult:
        """Bulk-insert one complete feed atomically or prove an exact idempotent retry."""

        return self._publish(stream, manage_transaction=True)

    def publish_in_transaction(
        self, stream: DailyEvidenceStream, *, reserved_bytes: int = 0
    ) -> FeedPublicationResult:
        """Persist inside a transaction owned and completed by the day publisher."""

        return self._publish(
            stream,
            manage_transaction=False,
            reserved_bytes=reserved_bytes,
        )

    def _publish(
        self,
        stream: DailyEvidenceStream,
        *,
        manage_transaction: bool,
        reserved_bytes: int = 0,
    ) -> FeedPublicationResult:

        day = UtcDay.parse(stream.header.day)
        payload = stream.to_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        evidence_count = sum(len(episode.evidence) for episode in stream.episodes)
        existing = self._stored_publication(day)
        if existing is not None:
            return self._require_idempotent(stream, existing, payload, digest)
        if self._is_legacy_day(day):
            raise LegacySelectedDayError(f"{day} already has pre-cutover legacy selected output")
        self._require_running_run(stream)
        storage = self._storage_guard.assess(
            self._connection,
            candidate_rows=len(stream.episodes),
            evidence_rows=evidence_count,
            reserved_bytes=reserved_bytes,
        )
        episode_arrow = _episode_arrow(stream.episodes)
        evidence_arrow = _evidence_arrow(stream.episodes)
        registrations: list[str] = []
        try:
            if episode_arrow.num_rows:
                self._connection.register(_EPISODE_REGISTRATION, episode_arrow)
                registrations.append(_EPISODE_REGISTRATION)
            if evidence_arrow.num_rows:
                self._connection.register(_EVIDENCE_REGISTRATION, evidence_arrow)
                registrations.append(_EVIDENCE_REGISTRATION)
            if manage_transaction:
                self._connection.execute("BEGIN TRANSACTION")
            try:
                if self._stored_publication(day) is not None or self._is_legacy_day(day):
                    raise FeedStorageError("feed day changed while publication was starting")
                self._insert_header(stream, evidence_count, len(payload), digest)
                self._insert_episodes(episode_arrow.num_rows)
                self._insert_evidence(evidence_arrow.num_rows)
                self._reconcile(stream, evidence_count, len(payload), digest)
                stored = self._load_complete(day)
                if stored.to_bytes() != payload:
                    raise FeedStorageError(
                        "persisted stream bytes do not match the supplied stream"
                    )
                if manage_transaction:
                    self._connection.execute("COMMIT")
            except Exception:
                if manage_transaction:
                    self._connection.execute("ROLLBACK")
                raise
        except FeedStorageError:
            raise
        except Exception as exc:
            raise FeedStorageError("complete-feed publication failed") from exc
        finally:
            for registration in reversed(registrations):
                self._connection.unregister(registration)
        return FeedPublicationResult(
            stream.header.day,
            stream.header.run_id,
            len(stream.episodes),
            evidence_count,
            len(payload),
            digest,
            False,
            storage,
        )

    def _require_idempotent(
        self,
        stream: DailyEvidenceStream,
        existing: _StoredPublication,
        payload: bytes,
        digest: str,
    ) -> FeedPublicationResult:
        stored = self._load_complete(UtcDay.parse(stream.header.day))
        if (
            stored.to_bytes() != payload
            or existing.feed_sha256 != digest
            or existing.serialized_bytes != len(payload)
        ):
            raise FeedStorageError("complete-feed retry conflicts with the published feed")
        current = _database_bytes(self._connection)
        return FeedPublicationResult(
            stream.header.day,
            stream.header.run_id,
            len(stream.episodes),
            existing.evidence_count,
            len(payload),
            digest,
            True,
            FeedStorageAssessment(
                current,
                current,
                current >= self._storage_guard.alert_bytes,
            ),
        )

    def _require_running_run(self, stream: DailyEvidenceStream) -> None:
        row = self._connection.execute(
            "SELECT day, status, started_at FROM ops.pipeline_run WHERE run_id = ?",
            [stream.header.run_id],
        ).fetchone()
        if row is None:
            raise FeedStorageError("complete feed run does not exist")
        if str(row[0]) != stream.header.day:
            raise FeedStorageError("complete feed day does not match its run")
        if str(row[1]) != "running":
            raise FeedStorageError("complete feed requires a running publication run")
        started_at = _utc(row[2])
        day = UtcDay.parse(stream.header.day)
        if started_at < day.eligible_at:
            raise FeedStorageError("complete feed run started before day-D eligibility")
        if started_at > stream.header.published_at:
            raise FeedStorageError("complete feed publication precedes its run start")

    def _is_legacy_day(self, day: UtcDay) -> bool:
        row = self._connection.execute(
            """
            SELECT
                EXISTS (
                    SELECT 1 FROM ops.pipeline_run
                    WHERE day = ? AND status = 'published'
                )
                OR EXISTS (
                    SELECT 1 FROM detect.legacy_selected_episode WHERE day = ?
                )
            """,
            [day.value, day.value],
        ).fetchone()
        if row is None:
            raise FeedStorageError("legacy-day status is unavailable")
        return bool(row[0])

    def _insert_header(
        self,
        stream: DailyEvidenceStream,
        evidence_count: int,
        serialized_bytes: int,
        digest: str,
    ) -> None:
        header = stream.header
        self._connection.execute(
            """
            INSERT INTO feed.daily_publication (
                day, feed_schema_version, published_at, run_id, detector_version,
                ranking_version, candidate_count, evidence_count, serialized_bytes,
                feed_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                header.day,
                header.stream_schema_version,
                header.published_at,
                header.run_id,
                header.detector_version,
                header.ordering_version,
                header.episode_count,
                evidence_count,
                serialized_bytes,
                digest,
            ],
        )

    def _insert_episodes(self, count: int) -> None:
        if not count:
            return
        self._connection.execute(
            f"""
            INSERT INTO feed.episode (
                episode_id, run_id, day, detected_at, client_ip, family,
                episode_start, episode_end, service_id, service_domain, asn_id,
                family_strength, evidence_tier, sequence, tie_group, evidence_group_mask,
                history_confidence, data_quality_confidence, reason_code_mask,
                detector_version, ordering_version, source_detail_expires_at
            )
            SELECT
                episode_id::UUID, run_id::UUID, day, detected_at, client_ip, family,
                episode_start, episode_end, service_id, service_domain, asn_id,
                family_strength, evidence_tier, sequence, tie_group, evidence_group_mask,
                history_confidence, data_quality_confidence, reason_code_mask,
                detector_version, ordering_version, source_detail_expires_at
            FROM {_EPISODE_REGISTRATION}
            """
        )

    def _insert_evidence(self, count: int) -> None:
        if not count:
            return
        self._connection.execute(
            f"""
            INSERT INTO feed.episode_evidence (
                episode_id, evidence_group, metric_code, observed_value,
                client_baseline_value, peer_reference_value, self_strength,
                peer_strength, metric_strength, support_count
            )
            SELECT episode_id::UUID, evidence_group, metric_code, observed_value,
                   client_baseline_value, peer_reference_value, self_strength,
                   peer_strength, metric_strength, support_count
            FROM {_EVIDENCE_REGISTRATION}
            """
        )

    def _reconcile(
        self,
        stream: DailyEvidenceStream,
        evidence_count: int,
        serialized_bytes: int,
        digest: str,
    ) -> None:
        day = UtcDay.parse(stream.header.day)
        header = self._stored_publication(day)
        if header is None or (
            header.candidate_count != len(stream.episodes)
            or header.evidence_count != evidence_count
            or header.serialized_bytes != serialized_bytes
            or header.feed_sha256 != digest
        ):
            raise FeedStorageError("feed publication metadata did not reconcile")
        row = self._connection.execute(
            """
            SELECT count(*), count(DISTINCT episode_id),
                   coalesce(min(sequence), 0), coalesce(max(sequence), 0),
                   count(DISTINCT sequence),
                   count(*) FILTER (
                       WHERE run_id <> ? OR detector_version <> ? OR ordering_version <> ?
                   )
            FROM feed.episode WHERE day = ?
            """,
            [
                stream.header.run_id,
                stream.header.detector_version,
                stream.header.ordering_version,
                day.value,
            ],
        ).fetchone()
        if row is None:
            raise FeedStorageError("stream episode reconciliation is unavailable")
        expected_sequence_min = 1 if stream.episodes else 0
        expected_sequence_max = len(stream.episodes)
        expected = (
            len(stream.episodes),
            len(stream.episodes),
            expected_sequence_min,
            expected_sequence_max,
            len(stream.episodes),
            0,
        )
        if tuple(int(value) for value in row) != expected:
            raise FeedStorageError("stream episode count, identity, sequence, or version mismatch")
        evidence_row = self._connection.execute(
            """
            SELECT count(*)
            FROM feed.episode_evidence AS evidence
            JOIN feed.episode AS episode USING (episode_id)
            WHERE episode.day = ?
            """,
            [day.value],
        ).fetchone()
        if evidence_row is None or int(evidence_row[0]) != evidence_count:
            raise FeedStorageError("stream evidence count did not reconcile")
        invalid = self._connection.execute(
            """
            SELECT count(*) FROM (
                SELECT episode.episode_id, episode.evidence_group_mask,
                       count(evidence.episode_id) AS evidence_rows,
                       coalesce(
                           bit_or((1::UBIGINT) << evidence.evidence_group),
                           0
                       ) AS observed_mask
                FROM feed.episode AS episode
                LEFT JOIN feed.episode_evidence AS evidence USING (episode_id)
                WHERE episode.day = ?
                GROUP BY episode.episode_id, episode.evidence_group_mask
                HAVING evidence_rows = 0 OR observed_mask <> episode.evidence_group_mask
            )
            """,
            [day.value],
        ).fetchone()
        if invalid is None or int(invalid[0]):
            raise FeedStorageError("stream evidence groups did not reconcile")

    def _stored_publication(self, day: UtcDay) -> _StoredPublication | None:
        row = self._connection.execute(
            """
            SELECT day, feed_schema_version, published_at, run_id, detector_version,
                   ranking_version, candidate_count, evidence_count, serialized_bytes,
                   feed_sha256
            FROM feed.daily_publication WHERE day = ?
            """,
            [day.value],
        ).fetchone()
        if row is None:
            return None
        return _StoredPublication(
            str(row[0]),
            str(row[1]),
            _utc(row[2]),
            _uuid(row[3]),
            str(row[4]),
            str(row[5]),
            int(row[6]),
            int(row[7]),
            int(row[8]),
            str(row[9]),
        )

    def _load_complete(self, day: UtcDay) -> DailyEvidenceStream:
        stored = self._stored_publication(day)
        if stored is None:
            raise FeedNotFoundError(f"no complete stream exists for {day}")
        if stored.feed_schema_version == LEGACY_FEED_SCHEMA_VERSION:
            raise LegacySchemaVersionError(
                f"{day} was published under {LEGACY_FEED_SCHEMA_VERSION}; "
                "use load_jsonl to stream it back unchanged"
            )
        if stored.feed_schema_version != STREAM_SCHEMA_VERSION:
            raise FeedStorageError(
                f"{day} was published under unsupported schema {stored.feed_schema_version}"
            )
        try:
            evidence_rows = self._connection.execute(
                """
                SELECT evidence.episode_id, evidence.evidence_group,
                       evidence.metric_code, evidence.observed_value,
                       evidence.client_baseline_value, evidence.peer_reference_value,
                       evidence.self_strength, evidence.peer_strength,
                       evidence.metric_strength, evidence.support_count
                FROM feed.episode_evidence AS evidence
                JOIN feed.episode AS episode USING (episode_id)
                WHERE episode.day = ?
                ORDER BY episode.sequence, evidence.evidence_group
                """,
                [day.value],
            ).fetchall()
            by_episode: dict[UUID, list[StreamEvidence]] = {}
            for row in evidence_rows:
                by_episode.setdefault(_uuid(row[0]), []).append(
                    StreamEvidence(
                        EvidenceGroup(int(row[1])),
                        str(row[2]),
                        float(row[3]),
                        _optional_float(row[4]),
                        _optional_float(row[5]),
                        _optional_float(row[6]),
                        _optional_float(row[7]),
                        _optional_float(row[8]),
                        int(row[9]) if row[9] is not None else None,
                    )
                )
            episode_rows = self._connection.execute(
                """
                SELECT episode_id, run_id, day, detected_at, client_ip, family,
                       episode_start, episode_end, service_id, service_domain, asn_id,
                       family_strength, evidence_tier, sequence, tie_group,
                       evidence_group_mask, history_confidence, data_quality_confidence,
                       reason_code_mask, detector_version, ordering_version,
                       source_detail_expires_at
                FROM feed.episode
                WHERE day = ? ORDER BY sequence
                """,
                [day.value],
            ).fetchall()
            episodes = tuple(
                _episode_from_row(row, tuple(by_episode.get(_uuid(row[0]), ())))
                for row in episode_rows
            )
            header = StreamHeader(
                stored.feed_schema_version,
                stored.day,
                stored.published_at,
                stored.run_id,
                stored.detector_version,
                stored.ranking_version,
                stored.candidate_count,
            )
            stream = DailyEvidenceStream(header, episodes)
        except (TypeError, ValueError) as exc:
            raise FeedStorageError("persisted stream violates its typed contract") from exc
        self._verify(stream.to_bytes(), len(evidence_rows), stored)
        return stream

    def _load_legacy_v1(self, day: UtcDay) -> DailyCandidateFeed:
        """Reconstruct a day published under the frozen v1 schema, from its original tables.

        Nothing here may change. The stored digest was taken over these exact bytes, and Tier 0
        requires that a compatible rerun return them unchanged.
        """
        stored = self._stored_publication(day)
        if stored is None:
            raise FeedNotFoundError(f"no complete feed exists for {day}")
        try:
            evidence_rows = self._connection.execute(
                """
                SELECT evidence.candidate_id, evidence.evidence_group,
                       evidence.metric_code, evidence.observed_value,
                       evidence.client_baseline_value, evidence.peer_reference_value,
                       evidence.self_strength, evidence.peer_strength,
                       evidence.metric_strength, evidence.support_count
                FROM feed.candidate_evidence AS evidence
                JOIN feed.candidate_episode AS candidate USING (candidate_id)
                WHERE candidate.day = ?
                ORDER BY candidate.daily_rank, evidence.evidence_group
                """,
                [day.value],
            ).fetchall()
            by_candidate: dict[UUID, list[DailyFeedEvidence]] = {}
            for row in evidence_rows:
                by_candidate.setdefault(_uuid(row[0]), []).append(
                    DailyFeedEvidence(
                        EvidenceGroup(int(row[1])),
                        str(row[2]),
                        float(row[3]),
                        _optional_float(row[4]),
                        _optional_float(row[5]),
                        _optional_float(row[6]),
                        _optional_float(row[7]),
                        _optional_float(row[8]),
                        int(row[9]) if row[9] is not None else None,
                    )
                )
            candidate_rows = self._connection.execute(
                """
                SELECT candidate_id, run_id, day, detected_at, client_ip, family,
                       episode_start, episode_end, service_id, asn_id, family_strength,
                       priority_tier, daily_rank, priority_score, evidence_group_mask,
                       history_confidence, data_quality_confidence, reason_code_mask,
                       detector_version, ranking_version, source_detail_expires_at
                FROM feed.candidate_episode
                WHERE day = ? ORDER BY daily_rank
                """,
                [day.value],
            ).fetchall()
            candidates = tuple(
                _candidate_from_row(row, tuple(by_candidate.get(_uuid(row[0]), ())))
                for row in candidate_rows
            )
            header = DailyFeedHeader(
                stored.feed_schema_version,
                stored.day,
                stored.published_at,
                stored.run_id,
                stored.detector_version,
                stored.ranking_version,
                stored.candidate_count,
            )
            feed = DailyCandidateFeed(header, candidates)
        except (TypeError, ValueError) as exc:
            raise FeedStorageError("persisted legacy feed violates its typed contract") from exc
        self._verify(feed.to_bytes(), len(evidence_rows), stored)
        return feed

    def _verify(self, payload: bytes, evidence_rows: int, stored: _StoredPublication) -> None:
        if evidence_rows != stored.evidence_count:
            raise FeedStorageError("persisted evidence count is inconsistent")
        if len(payload) != stored.serialized_bytes:
            raise FeedStorageError("persisted byte count is inconsistent")
        if hashlib.sha256(payload).hexdigest() != stored.feed_sha256:
            raise FeedStorageError("persisted digest is inconsistent")


def _candidate_from_row(
    row: tuple[Any, ...], evidence: tuple[DailyFeedEvidence, ...]
) -> DailyFeedCandidate:
    service = row[8]
    if service is not None and not isinstance(service, bytes | bytearray | memoryview):
        raise TypeError("DuckDB returned an invalid complete-feed service ID")
    return DailyFeedCandidate(
        _uuid(row[0]),
        _uuid(row[1]),
        str(row[2]),
        _utc(row[3]),
        str(row[4]),
        DetectorFamily(str(row[5])),
        _utc(row[6]),
        _utc(row[7]),
        bytes(service).hex() if service is not None else None,
        int(row[9]) if row[9] is not None else None,
        float(row[10]),
        LegacyPriorityTier(str(row[11])),
        int(row[12]),
        int(row[13]),
        int(row[14]),
        HistoryConfidence(str(row[15])),
        DataQualityConfidence(str(row[16])),
        int(row[17]),
        str(row[18]),
        str(row[19]),
        _utc(row[20]) if row[20] is not None else None,
        evidence,
    )


def _episode_from_row(row: tuple[Any, ...], evidence: tuple[StreamEvidence, ...]) -> StreamEpisode:
    return StreamEpisode(
        _uuid(row[0]),
        _uuid(row[1]),
        str(row[2]),
        _utc(row[3]),
        str(row[4]),
        DetectorFamily(str(row[5])),
        _utc(row[6]),
        _utc(row[7]),
        str(row[8]) if row[8] is not None else None,
        str(row[9]) if row[9] is not None else None,
        int(row[10]) if row[10] is not None else None,
        float(row[11]),
        EvidenceTier(str(row[12])),
        int(row[13]),
        int(row[14]),
        int(row[15]),
        HistoryConfidence(str(row[16])),
        DataQualityConfidence(str(row[17])),
        int(row[18]),
        str(row[19]),
        str(row[20]),
        _utc(row[21]) if row[21] is not None else None,
        evidence,
    )


def _episode_arrow(episodes: tuple[StreamEpisode, ...]) -> pa.Table:
    return pa.table(
        {
            "episode_id": pa.array([str(item.episode_id) for item in episodes]),
            "run_id": pa.array([str(item.run_id) for item in episodes]),
            "day": pa.array([UtcDay.parse(item.day).value for item in episodes], type=pa.date32()),
            "detected_at": _timestamps([item.detected_at for item in episodes]),
            "client_ip": pa.array([item.client_ip for item in episodes]),
            "family": pa.array([item.family.value for item in episodes]),
            "episode_start": _timestamps([item.episode_start for item in episodes]),
            "episode_end": _timestamps([item.episode_end for item in episodes]),
            "service_id": pa.array([item.service_id for item in episodes]),
            "service_domain": pa.array([item.service_domain for item in episodes]),
            "asn_id": pa.array([item.asn_id for item in episodes], type=pa.uint64()),
            "family_strength": pa.array(
                [item.family_strength for item in episodes], type=pa.float64()
            ),
            "evidence_tier": pa.array([item.evidence_tier.value for item in episodes]),
            "sequence": pa.array([item.sequence for item in episodes], type=pa.uint32()),
            "tie_group": pa.array([item.tie_group for item in episodes], type=pa.uint32()),
            "evidence_group_mask": pa.array(
                [item.evidence_group_mask for item in episodes], type=pa.uint64()
            ),
            "history_confidence": pa.array([item.history_confidence.value for item in episodes]),
            "data_quality_confidence": pa.array(
                [item.data_quality_confidence.value for item in episodes]
            ),
            "reason_code_mask": pa.array(
                [item.reason_code_mask for item in episodes], type=pa.uint64()
            ),
            "detector_version": pa.array([item.detector_version for item in episodes]),
            "ordering_version": pa.array([item.ordering_version for item in episodes]),
            "source_detail_expires_at": _timestamps(
                [item.source_detail_expires_at for item in episodes]
            ),
        }
    )


def _evidence_arrow(episodes: tuple[StreamEpisode, ...]) -> pa.Table:
    rows = tuple(
        (episode.episode_id, evidence) for episode in episodes for evidence in episode.evidence
    )
    return pa.table(
        {
            "episode_id": pa.array([str(episode_id) for episode_id, _ in rows]),
            "evidence_group": pa.array(
                [int(evidence.evidence_group) for _, evidence in rows], type=pa.uint8()
            ),
            "metric_code": pa.array([evidence.metric_code for _, evidence in rows]),
            "observed_value": pa.array(
                [evidence.observed_value for _, evidence in rows], type=pa.float64()
            ),
            "client_baseline_value": pa.array(
                [evidence.client_baseline_value for _, evidence in rows], type=pa.float64()
            ),
            "peer_reference_value": pa.array(
                [evidence.peer_reference_value for _, evidence in rows], type=pa.float64()
            ),
            "self_strength": pa.array(
                [evidence.self_strength for _, evidence in rows], type=pa.float64()
            ),
            "peer_strength": pa.array(
                [evidence.peer_strength for _, evidence in rows], type=pa.float64()
            ),
            "metric_strength": pa.array(
                [evidence.metric_strength for _, evidence in rows], type=pa.float64()
            ),
            "support_count": pa.array(
                [evidence.support_count for _, evidence in rows], type=pa.uint64()
            ),
        }
    )


def _timestamps(values: list[Any]) -> pa.Array[Any]:
    return pa.array(values, type=pa.timestamp("us", tz="UTC"))


def _database_bytes(connection: duckdb.DuckDBPyConnection) -> int:
    row = connection.execute(
        "SELECT database_size, wal_size FROM pragma_database_size()"
    ).fetchone()
    if row is None:
        raise FeedStorageError("cannot measure DuckDB feed storage")
    return _size_bytes(str(row[0])) + _size_bytes(str(row[1]))


def _size_bytes(raw: str) -> int:
    match = _SIZE.fullmatch(raw)
    if match is None:
        raise FeedStorageError("DuckDB returned an unsupported storage size")
    scale = {"bytes": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    return int(float(match.group("value")) * scale[match.group("unit")])


def _uuid(value: object) -> UUID:
    return value if isinstance(value, UUID) else UUID(str(value))


def _utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TypeError("DuckDB returned an invalid complete-feed timestamp")
    return value.astimezone(UTC)


def _optional_float(value: Any) -> float | None:
    return float(value) if value is not None else None
