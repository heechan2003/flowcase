"""Typed, deterministic daily evidence-stream contract.

`daily-evidence-stream-v2`. See `PRODUCT_CONTRACT.md` Tier 4.

Differences from the frozen v1 contract in `legacy_v1.py`, and why:

- `priority_score` is gone. It was linear interpolation of rank position — 21 distinct values across
  3,100 episodes — so it carried no information beyond position while implying measurement.
- `daily_rank` is gone. A contiguous total order claimed a discrimination the evidence does not
  support: ~90% of adjacent within-tier pairs tie on every substantive key.
- `sequence` replaces it as file position only, so a consumer can verify nothing was dropped.
- `tie_group` is a dense rank over the real ordering key. Episodes sharing one are equivalent on
  the evidence, and this says so rather than hiding it behind consecutive ranks.
- `evidence_tier` (E1/E2/E3) replaces `priority_tier`. The top tier holds ~30% of the stream, so
  "priority" asserted more than the evidence supports.
- `service_domain` makes an episode resolvable. Emitted only where the service basis is a domain
  and that service affected the decision; never written to retained history.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
from math import isfinite
from typing import Any
from uuid import UUID

from network_behaviour.baselines.models import HistoryConfidence
from network_behaviour.detectors.models import DetectorEvidence, DetectorFamily
from network_behaviour.domain import EvidenceGroup, ReasonCode, code_mask
from network_behaviour.normalization.service import CANONICAL_DOMAIN, MAX_DOMAIN_LENGTH
from network_behaviour.ranking import (
    DataQualityConfidence,
    EvidenceTier,
    RankedEpisode,
    RankingBatch,
    SignalStatus,
)
from network_behaviour.time import UtcDay

STREAM_SCHEMA_VERSION = "daily-evidence-stream-v2"
STREAM_ENCODING_VERSION = "daily-evidence-stream-jsonl-v2"

_MACHINE_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}")
_VERSION = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}")
_FORBIDDEN_WORDING = re.compile(
    r"(?<![a-z])(?:threat|risk|scan(?:ning)?|exfiltrat(?:e|ion)|malware|"
    r"command(?:_|-| )and(?:_|-| )control|compromise(?:d)?|malicious(?:ness)?)(?![a-z])",
    re.IGNORECASE,
)
_TIER_ORDER = {EvidenceTier.E1: 0, EvidenceTier.E2: 1, EvidenceTier.E3: 2}
_EVIDENCE_MASK = code_mask(*tuple(EvidenceGroup))
_REASON_MASK = code_mask(*tuple(ReasonCode))


class StreamValidationError(ValueError):
    """Raised when a stream would violate the versioned product contract."""


@dataclass(frozen=True, slots=True)
class StreamBuildMetadata:
    run_id: UUID
    published_at: datetime
    detected_at: datetime
    source_detail_expires_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_uuid(self.run_id, "run ID")
        _require_utc(self.published_at, "publication timestamp")
        _require_utc(self.detected_at, "detection timestamp")
        if self.source_detail_expires_at is not None:
            _require_utc(self.source_detail_expires_at, "source-detail expiry")
            if self.source_detail_expires_at < self.detected_at:
                raise StreamValidationError("source-detail expiry cannot precede detection")


@dataclass(frozen=True, slots=True)
class StreamHeader:
    stream_schema_version: str
    day: str
    published_at: datetime
    run_id: UUID
    detector_version: str
    ordering_version: str
    episode_count: int

    def __post_init__(self) -> None:
        if self.stream_schema_version != STREAM_SCHEMA_VERSION:
            raise StreamValidationError("stream schema version is not the released contract")
        day = _require_day(self.day)
        _require_utc(self.published_at, "publication timestamp")
        if self.published_at < day.eligible_at:
            raise StreamValidationError("publication precedes completed-day eligibility")
        _require_uuid(self.run_id, "run ID")
        _require_version(self.detector_version, "detector version")
        _require_version(self.ordering_version, "ordering version")
        if not _is_int(self.episode_count) or self.episode_count < 0:
            raise StreamValidationError("episode count must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class StreamEvidence:
    evidence_group: EvidenceGroup
    metric_code: str
    observed_value: float
    client_baseline_value: float | None = None
    peer_reference_value: float | None = None
    self_strength: float | None = None
    peer_strength: float | None = None
    metric_strength: float | None = None
    support_count: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_group, EvidenceGroup):
            raise StreamValidationError("evidence group is not a versioned code")
        _require_machine_code(self.metric_code)
        numeric = (
            self.observed_value,
            self.client_baseline_value,
            self.peer_reference_value,
            self.self_strength,
            self.peer_strength,
            self.metric_strength,
        )
        if any(value is not None and not isfinite(value) for value in numeric):
            raise StreamValidationError("evidence values must be finite")
        for strength in (self.self_strength, self.peer_strength, self.metric_strength):
            if strength is not None and not 0 <= strength <= 100:
                raise StreamValidationError("evidence strength must be between zero and 100")
        if self.support_count is not None and (
            not _is_int(self.support_count) or self.support_count < 0
        ):
            raise StreamValidationError("evidence support cannot be negative")

    def payload(self) -> dict[str, object]:
        return {
            "evidence_group": int(self.evidence_group),
            "metric_code": self.metric_code,
            "observed_value": self.observed_value,
            "client_baseline_value": self.client_baseline_value,
            "peer_reference_value": self.peer_reference_value,
            "self_strength": self.self_strength,
            "peer_strength": self.peer_strength,
            "metric_strength": self.metric_strength,
            "support_count": self.support_count,
        }


@dataclass(frozen=True, slots=True)
class StreamEpisode:
    episode_id: UUID
    run_id: UUID
    day: str
    detected_at: datetime
    client_ip: str
    family: DetectorFamily
    episode_start: datetime
    episode_end: datetime
    service_id: str | None
    service_domain: str | None
    asn_id: int | None
    family_strength: float
    evidence_tier: EvidenceTier
    sequence: int
    tie_group: int
    evidence_group_mask: int
    history_confidence: HistoryConfidence
    data_quality_confidence: DataQualityConfidence
    reason_code_mask: int
    detector_version: str
    ordering_version: str
    source_detail_expires_at: datetime | None
    evidence: tuple[StreamEvidence, ...]

    def __post_init__(self) -> None:
        _require_uuid(self.episode_id, "episode ID")
        _require_uuid(self.run_id, "run ID")
        day = _require_day(self.day)
        _require_utc(self.detected_at, "detection timestamp")
        if self.detected_at < day.eligible_at:
            raise StreamValidationError("episode detection precedes completed-day eligibility")
        _require_utc(self.episode_start, "episode start")
        _require_utc(self.episode_end, "episode end")
        if not day.bounds.start <= self.episode_start <= self.episode_end <= day.bounds.end:
            raise StreamValidationError("episode is outside its UTC day")
        try:
            normalized_ip = str(ip_address(self.client_ip))
        except ValueError as exc:
            raise StreamValidationError("episode client IP is invalid") from exc
        if normalized_ip != self.client_ip:
            raise StreamValidationError("episode client IP is not canonical")
        if not isinstance(self.family, DetectorFamily):
            raise StreamValidationError("episode family is not a versioned code")
        _require_service_id(self.service_id)
        _require_service_domain(self.service_domain, self.service_id)
        if self.asn_id is not None and (not _is_int(self.asn_id) or self.asn_id < 0):
            raise StreamValidationError("episode ASN must be a non-negative integer")
        if not isfinite(self.family_strength) or not 0 <= self.family_strength <= 100:
            raise StreamValidationError("episode family strength must be between zero and 100")
        if (
            not isinstance(self.evidence_tier, EvidenceTier)
            or self.evidence_tier not in _TIER_ORDER
        ):
            raise StreamValidationError("diagnostic tier cannot enter the evidence stream")
        if not _is_int(self.sequence) or self.sequence <= 0:
            raise StreamValidationError("sequence must be one-based")
        if not _is_int(self.tie_group) or self.tie_group <= 0:
            raise StreamValidationError("tie group must be one-based")
        if (
            not _is_int(self.evidence_group_mask)
            or self.evidence_group_mask < 0
            or self.evidence_group_mask & ~_EVIDENCE_MASK
        ):
            raise StreamValidationError("episode evidence mask contains an unknown group")
        if (
            not _is_int(self.reason_code_mask)
            or self.reason_code_mask < 0
            or self.reason_code_mask & ~_REASON_MASK
        ):
            raise StreamValidationError("episode reason mask contains an unknown code")
        if not self.evidence:
            raise StreamValidationError("eligible episode evidence cannot be empty")
        groups = tuple(item.evidence_group for item in self.evidence)
        if len(groups) != len(set(groups)):
            raise StreamValidationError("episode evidence groups must be unique")
        if self.evidence_group_mask != code_mask(*groups):
            raise StreamValidationError("episode evidence does not match its group mask")
        if not isinstance(self.history_confidence, HistoryConfidence):
            raise StreamValidationError("history confidence is not a versioned code")
        if not isinstance(self.data_quality_confidence, DataQualityConfidence):
            raise StreamValidationError("data-quality confidence is not a versioned code")
        _require_version(self.detector_version, "detector version")
        _require_version(self.ordering_version, "ordering version")
        if self.source_detail_expires_at is not None:
            _require_utc(self.source_detail_expires_at, "source-detail expiry")
            if self.source_detail_expires_at < self.detected_at:
                raise StreamValidationError("source-detail expiry cannot precede detection")

    def payload(self) -> dict[str, object]:
        return {
            "episode_id": str(self.episode_id),
            "run_id": str(self.run_id),
            "day": self.day,
            "detected_at": self.detected_at.isoformat(),
            "client_ip": self.client_ip,
            "family": self.family.value,
            "episode_start": self.episode_start.isoformat(),
            "episode_end": self.episode_end.isoformat(),
            "service_id": self.service_id,
            "service_domain": self.service_domain,
            "asn_id": self.asn_id,
            "family_strength": self.family_strength,
            "evidence_tier": self.evidence_tier.value,
            "sequence": self.sequence,
            "tie_group": self.tie_group,
            "evidence_group_mask": self.evidence_group_mask,
            "history_confidence": self.history_confidence.value,
            "data_quality_confidence": self.data_quality_confidence.value,
            "reason_code_mask": self.reason_code_mask,
            "detector_version": self.detector_version,
            "ordering_version": self.ordering_version,
            "source_detail_expires_at": (
                self.source_detail_expires_at.isoformat()
                if self.source_detail_expires_at is not None
                else None
            ),
            "evidence": [item.payload() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class DailyEvidenceStream:
    header: StreamHeader
    episodes: tuple[StreamEpisode, ...]

    def __post_init__(self) -> None:
        if self.header.episode_count != len(self.episodes):
            raise StreamValidationError("episode count does not match the stream population")
        expected = tuple(range(1, len(self.episodes) + 1))
        if tuple(item.sequence for item in self.episodes) != expected:
            raise StreamValidationError("sequence must be complete and contiguous")
        episode_ids = tuple(item.episode_id for item in self.episodes)
        if len(episode_ids) != len(set(episode_ids)):
            raise StreamValidationError("episode IDs must be unique within a day")
        tier_order = tuple(_TIER_ORDER[item.evidence_tier] for item in self.episodes)
        if tier_order != tuple(sorted(tier_order)):
            raise StreamValidationError("stream must preserve E1-before-E2-before-E3 ordering")
        # Tie groups are dense and non-decreasing: equivalent episodes are adjacent by construction.
        groups = tuple(item.tie_group for item in self.episodes)
        if groups != tuple(sorted(groups)):
            raise StreamValidationError("tie groups must not decrease along the stream")
        if groups and sorted(set(groups)) != list(range(1, max(groups) + 1)):
            raise StreamValidationError("tie groups must be dense and one-based")
        for item in self.episodes:
            if item.day != self.header.day or item.run_id != self.header.run_id:
                raise StreamValidationError("episode day/run linkage conflicts with the header")
            if (
                item.detector_version != self.header.detector_version
                or item.ordering_version != self.header.ordering_version
            ):
                raise StreamValidationError("episode versions conflict with the header")

    def payload(self) -> dict[str, Any]:
        return {
            "stream_schema_version": self.header.stream_schema_version,
            "day": self.header.day,
            "published_at": self.header.published_at.isoformat(),
            "run_id": str(self.header.run_id),
            "detector_version": self.header.detector_version,
            "ordering_version": self.header.ordering_version,
            "episode_count": self.header.episode_count,
            "episodes": [item.payload() for item in self.episodes],
        }

    def to_bytes(self) -> bytes:
        """Serialize the complete stream to deterministic ASCII JSON bytes."""

        return json.dumps(
            self.payload(),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")


def iter_daily_evidence_stream_jsonl(stream: DailyEvidenceStream) -> Iterator[bytes]:
    """Yield the versioned stream as a header-first, sequence-ordered JSONL stream."""

    yield _jsonl_record(
        {
            "record_type": "header",
            "stream_encoding_version": STREAM_ENCODING_VERSION,
            "stream_schema_version": stream.header.stream_schema_version,
            "day": stream.header.day,
            "published_at": stream.header.published_at.isoformat(),
            "run_id": str(stream.header.run_id),
            "detector_version": stream.header.detector_version,
            "ordering_version": stream.header.ordering_version,
            "episode_count": stream.header.episode_count,
        }
    )
    for episode in stream.episodes:
        yield _jsonl_record({"record_type": "episode", "episode": episode.payload()})


def build_daily_evidence_stream(
    ranking: RankingBatch,
    metadata: StreamBuildMetadata,
    service_domains: dict[str, str] | None = None,
) -> DailyEvidenceStream:
    """Map every canonical eligible episode exactly once into a versioned stream.

    `service_domains` maps a hex `service_id` to its registered domain, for services whose basis is
    a domain. It comes from current-day staging, never from retained history, which stays hashed.
    """

    day = _require_day(ranking.day)
    _require_version(ranking.detector_version, "detector version")
    _require_version(ranking.ordering_version, "ordering version")
    if metadata.published_at < day.eligible_at or metadata.detected_at < day.eligible_at:
        raise StreamValidationError("stream metadata precedes completed-day eligibility")
    eligible_ids = {item.episode_id for item in ranking.ranked_eligible}
    diagnostic_ids = {item.episode_id for item in ranking.diagnostics}
    if eligible_ids & diagnostic_ids:
        raise StreamValidationError("eligible and diagnostic populations overlap")
    episodes = tuple(
        _episode_from_ranked(episode, ranking, metadata, sequence, service_domains or {})
        for sequence, episode in enumerate(ranking.ranked_eligible, start=1)
    )
    header = StreamHeader(
        STREAM_SCHEMA_VERSION,
        ranking.day,
        metadata.published_at,
        metadata.run_id,
        ranking.detector_version,
        ranking.ordering_version,
        len(episodes),
    )
    return DailyEvidenceStream(header, episodes)


def _episode_from_ranked(
    episode: RankedEpisode,
    ranking: RankingBatch,
    metadata: StreamBuildMetadata,
    sequence: int,
    service_domains: dict[str, str],
) -> StreamEpisode:
    if episode.status is not SignalStatus.ELIGIBLE:
        raise StreamValidationError("non-eligible episode cannot enter the stream")
    if episode.evidence_tier is EvidenceTier.DIAGNOSTIC:
        raise StreamValidationError("diagnostic episode cannot enter the stream")
    if episode.day != ranking.day:
        raise StreamValidationError("ranked episode belongs to a different day")
    expected_behaviour_version = f"{ranking.detector_version}/{ranking.ordering_version}"
    if episode.detector_version != expected_behaviour_version:
        raise StreamValidationError("ranked episode versions conflict with its ranking batch")
    return StreamEpisode(
        episode.episode_id,
        metadata.run_id,
        episode.day,
        metadata.detected_at,
        episode.client_ip,
        episode.family,
        episode.episode_start,
        episode.episode_end,
        episode.service_id_hex,
        service_domains.get(episode.service_id_hex) if episode.service_id_hex else None,
        episode.asn_id,
        episode.family_strength,
        episode.evidence_tier,
        sequence,
        episode.tie_group,
        episode.evidence_group_mask,
        episode.history_confidence,
        episode.data_quality_confidence,
        episode.reason_code_mask,
        ranking.detector_version,
        ranking.ordering_version,
        metadata.source_detail_expires_at,
        tuple(
            _evidence_from_detector(item)
            for item in sorted(episode.evidence, key=lambda item: int(item.group))
        ),
    )


def _evidence_from_detector(item: DetectorEvidence) -> StreamEvidence:
    return StreamEvidence(
        item.group,
        item.metric_code,
        item.observed_value,
        item.client_baseline_value,
        item.peer_reference_value,
        item.self_strength,
        item.peer_strength,
        item.metric_strength,
        item.support_count,
    )


def _jsonl_record(payload: dict[str, object]) -> bytes:
    return (
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _require_day(raw: str) -> UtcDay:
    try:
        return UtcDay.parse(raw)
    except ValueError as exc:
        raise StreamValidationError("day must be an ISO UTC date") from exc


def _require_utc(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise StreamValidationError(f"{name} must be timezone-aware UTC")


def _require_uuid(value: UUID, name: str) -> None:
    if not isinstance(value, UUID):
        raise StreamValidationError(f"{name} must be a UUID")


def _require_version(value: str, name: str) -> None:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise StreamValidationError(f"{name} must be a versioned identifier")
    if _FORBIDDEN_WORDING.search(value):
        raise StreamValidationError(f"{name} contains prohibited wording")


def _require_machine_code(value: str) -> None:
    if not isinstance(value, str) or not _MACHINE_CODE.fullmatch(value):
        raise StreamValidationError("metric code must be a machine-readable identifier")
    if _FORBIDDEN_WORDING.search(value):
        raise StreamValidationError("metric code contains prohibited wording")


def _require_service_id(value: str | None) -> None:
    if value is None:
        return
    if not isinstance(value, str) or len(value) != 32:
        raise StreamValidationError("service ID must be a 128-bit hex fingerprint")
    try:
        int(value, 16)
    except ValueError as exc:
        raise StreamValidationError("service ID must be hexadecimal") from exc


def _require_service_domain(value: str | None, service_id: str | None) -> None:
    """A resolvable destination, permitted only where a hashed service exists to resolve.

    Deliberately not subject to `_FORBIDDEN_WORDING`. That guard governs strings this system
    authors — version identifiers and metric codes — because the evidence cannot support a
    scanning, malware or compromise claim. A registered domain is observed data, not a claim:
    `anti-malware.org` is the name of a destination, not an allegation about the client that
    reached it. Applying the guard here rejected ordinary domains on a word boundary
    (`malwarebytes.com` passed, `anti-malware.org` did not) and, because publication is
    fail-closed and whole-day, one such domain destroyed an entire day's stream.
    """
    if value is None:
        return
    if service_id is None:
        raise StreamValidationError("service domain requires a service ID")
    # A resolvable destination is permitted on the stream and forbidden in retained history. The
    # stream is short-lived; the 365-day store is not, and only the first is authorized to carry
    # one. The shape itself is CANONICAL_DOMAIN, imported from normalization.service rather than
    # defined here a second time -- the two definitions drifting apart is exactly how a corrupted
    # domain from the source reached this validation in the first place. See registered_domain's
    # docstring.
    if (
        not isinstance(value, str)
        or len(value) > MAX_DOMAIN_LENGTH
        or not CANONICAL_DOMAIN.fullmatch(value)
    ):
        raise StreamValidationError("service domain is not a canonical registered domain")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
