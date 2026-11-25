"""FROZEN — the `daily-candidate-feed-v1` contract, retained for read-back only.

Published days are reconstructed from stored rows and verified against a stored SHA-256 digest,
byte count and evidence count. Days published under this schema must therefore serialize exactly as
they did when written, so nothing here may change: not a field, not a key order, not a validation
rule. Tier 0 immutability depends on it.

New days use `feed/domain.py` (`daily-evidence-stream-v2`). Nothing in this module is reachable
from the publication path.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from ipaddress import ip_address
from math import isfinite
from typing import Any
from uuid import UUID

from network_behaviour.baselines.models import HistoryConfidence
from network_behaviour.detectors.models import DetectorEvidence, DetectorFamily
from network_behaviour.domain import EvidenceGroup, ReasonCode, code_mask
from network_behaviour.ranking import DataQualityConfidence
from network_behaviour.time import UtcDay

LEGACY_FEED_SCHEMA_VERSION = "daily-candidate-feed-v1"
LEGACY_FEED_STREAM_ENCODING_VERSION = "daily-candidate-feed-jsonl-v1"


class LegacyPriorityTier(StrEnum):
    """Frozen v1 tier codes. Superseded by `EvidenceTier` for new days."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


_MACHINE_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}")
_VERSION = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}")
_FORBIDDEN_WORDING = re.compile(
    r"(?<![a-z])(?:threat|risk|scan(?:ning)?|exfiltrat(?:e|ion)|malware|"
    r"command(?:_|-| )and(?:_|-| )control|compromise(?:d)?|malicious(?:ness)?)(?![a-z])",
    re.IGNORECASE,
)
_TIER_ORDER = {LegacyPriorityTier.P1: 0, LegacyPriorityTier.P2: 1, LegacyPriorityTier.P3: 2}
_SCORE_RANGES = {
    LegacyPriorityTier.P1: range(80, 101),
    LegacyPriorityTier.P2: range(55, 80),
    LegacyPriorityTier.P3: range(30, 55),
}
_EVIDENCE_MASK = code_mask(*tuple(EvidenceGroup))
_REASON_MASK = code_mask(*tuple(ReasonCode))


class FeedValidationError(ValueError):
    """Raised when a feed would violate the versioned product contract."""


@dataclass(frozen=True, slots=True)
class FeedBuildMetadata:
    """Operational values that cannot affect ranking or feed inclusion."""

    run_id: UUID
    published_at: datetime
    detected_at: datetime
    source_detail_expires_at: datetime | None

    def __post_init__(self) -> None:
        _require_uuid(self.run_id, "run ID")
        _require_utc(self.published_at, "publication timestamp")
        _require_utc(self.detected_at, "detection timestamp")
        if self.detected_at > self.published_at:
            raise FeedValidationError("detection timestamp cannot follow publication")
        if self.source_detail_expires_at is not None:
            _require_utc(self.source_detail_expires_at, "source-detail expiry")
            if self.source_detail_expires_at < self.published_at:
                raise FeedValidationError("source-detail expiry cannot precede publication")


@dataclass(frozen=True, slots=True)
class DailyFeedHeader:
    feed_schema_version: str
    day: str
    published_at: datetime
    run_id: UUID
    detector_version: str
    ranking_version: str
    candidate_count: int

    def __post_init__(self) -> None:
        if self.feed_schema_version != LEGACY_FEED_SCHEMA_VERSION:
            raise FeedValidationError("feed schema version is unsupported")
        day = _require_day(self.day)
        _require_utc(self.published_at, "publication timestamp")
        if self.published_at < day.eligible_at:
            raise FeedValidationError("feed publication precedes completed-day eligibility")
        _require_uuid(self.run_id, "run ID")
        _require_version(self.detector_version, "detector version")
        _require_version(self.ranking_version, "ranking version")
        if not _is_int(self.candidate_count) or self.candidate_count < 0:
            raise FeedValidationError("candidate count cannot be negative")


@dataclass(frozen=True, slots=True)
class DailyFeedEvidence:
    evidence_group: EvidenceGroup
    metric_code: str
    observed_value: float
    client_baseline_value: float | None
    peer_reference_value: float | None
    self_strength: float | None
    peer_strength: float | None
    metric_strength: float | None
    support_count: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_group, EvidenceGroup):
            raise FeedValidationError("evidence group is not a versioned code")
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
            raise FeedValidationError("feed evidence values must be finite")
        for strength in (self.self_strength, self.peer_strength, self.metric_strength):
            if strength is not None and not 0 <= strength <= 100:
                raise FeedValidationError("feed evidence strength must be between zero and 100")
        if self.support_count is not None and (
            not _is_int(self.support_count) or self.support_count < 0
        ):
            raise FeedValidationError("feed evidence support must be a non-negative integer")

    @classmethod
    def from_detector(cls, evidence: DetectorEvidence) -> DailyFeedEvidence:
        return cls(
            evidence.group,
            evidence.metric_code,
            evidence.observed_value,
            evidence.client_baseline_value,
            evidence.peer_reference_value,
            evidence.self_strength,
            evidence.peer_strength,
            evidence.metric_strength,
            evidence.support_count,
        )

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
class DailyFeedCandidate:
    candidate_id: UUID
    run_id: UUID
    day: str
    detected_at: datetime
    client_ip: str
    family: DetectorFamily
    episode_start: datetime
    episode_end: datetime
    service_id: str | None
    asn_id: int | None
    family_strength: float
    priority_tier: LegacyPriorityTier
    daily_rank: int
    priority_score: int
    evidence_group_mask: int
    history_confidence: HistoryConfidence
    data_quality_confidence: DataQualityConfidence
    reason_code_mask: int
    detector_version: str
    ranking_version: str
    source_detail_expires_at: datetime | None
    evidence: tuple[DailyFeedEvidence, ...]

    def __post_init__(self) -> None:
        _require_uuid(self.candidate_id, "candidate ID")
        _require_uuid(self.run_id, "run ID")
        day = _require_day(self.day)
        _require_utc(self.detected_at, "detection timestamp")
        if self.detected_at < day.eligible_at:
            raise FeedValidationError("candidate detection precedes completed-day eligibility")
        _require_utc(self.episode_start, "episode start")
        _require_utc(self.episode_end, "episode end")
        if not day.bounds.start <= self.episode_start <= self.episode_end <= day.bounds.end:
            raise FeedValidationError("candidate episode is outside its UTC day")
        try:
            normalized_ip = str(ip_address(self.client_ip))
        except ValueError as exc:
            raise FeedValidationError("candidate client IP is invalid") from exc
        if normalized_ip != self.client_ip:
            raise FeedValidationError("candidate client IP is not canonical")
        if not isinstance(self.family, DetectorFamily):
            raise FeedValidationError("candidate family is not a versioned code")
        _require_service_id(self.service_id)
        if self.asn_id is not None and (not _is_int(self.asn_id) or self.asn_id < 0):
            raise FeedValidationError("candidate ASN must be a non-negative integer")
        if not isfinite(self.family_strength) or not 0 <= self.family_strength <= 100:
            raise FeedValidationError("candidate family strength must be between zero and 100")
        if (
            not isinstance(self.priority_tier, LegacyPriorityTier)
            or self.priority_tier not in _TIER_ORDER
        ):
            raise FeedValidationError("diagnostic priority cannot enter the daily feed")
        if not _is_int(self.daily_rank) or self.daily_rank <= 0:
            raise FeedValidationError("daily rank must be one-based")
        if (
            not _is_int(self.priority_score)
            or self.priority_score not in _SCORE_RANGES[self.priority_tier]
        ):
            raise FeedValidationError("priority score is outside its tier range")
        if (
            not _is_int(self.evidence_group_mask)
            or self.evidence_group_mask < 0
            or self.evidence_group_mask & ~_EVIDENCE_MASK
        ):
            raise FeedValidationError("candidate evidence mask contains an unknown group")
        if (
            not _is_int(self.reason_code_mask)
            or self.reason_code_mask < 0
            or self.reason_code_mask & ~_REASON_MASK
        ):
            raise FeedValidationError("candidate reason mask contains an unknown code")
        if not self.evidence:
            raise FeedValidationError("eligible candidate evidence cannot be empty")
        groups = tuple(item.evidence_group for item in self.evidence)
        if len(groups) != len(set(groups)):
            raise FeedValidationError("candidate evidence groups must be unique")
        if self.evidence_group_mask != code_mask(*groups):
            raise FeedValidationError("candidate evidence does not match its group mask")
        if not isinstance(self.history_confidence, HistoryConfidence):
            raise FeedValidationError("history confidence is not a versioned code")
        if not isinstance(self.data_quality_confidence, DataQualityConfidence):
            raise FeedValidationError("data-quality confidence is not a versioned code")
        _require_version(self.detector_version, "detector version")
        _require_version(self.ranking_version, "ranking version")
        if self.source_detail_expires_at is not None:
            _require_utc(self.source_detail_expires_at, "source-detail expiry")
            if self.source_detail_expires_at < self.detected_at:
                raise FeedValidationError("source-detail expiry cannot precede detection")

    def payload(self) -> dict[str, object]:
        return {
            "candidate_id": str(self.candidate_id),
            "run_id": str(self.run_id),
            "day": self.day,
            "detected_at": self.detected_at.isoformat(),
            "client_ip": self.client_ip,
            "family": self.family.value,
            "episode_start": self.episode_start.isoformat(),
            "episode_end": self.episode_end.isoformat(),
            "service_id": self.service_id,
            "asn_id": self.asn_id,
            "family_strength": self.family_strength,
            "priority_tier": self.priority_tier.value,
            "daily_rank": self.daily_rank,
            "priority_score": self.priority_score,
            "evidence_group_mask": self.evidence_group_mask,
            "history_confidence": self.history_confidence.value,
            "data_quality_confidence": self.data_quality_confidence.value,
            "reason_code_mask": self.reason_code_mask,
            "detector_version": self.detector_version,
            "ranking_version": self.ranking_version,
            "source_detail_expires_at": (
                self.source_detail_expires_at.isoformat()
                if self.source_detail_expires_at is not None
                else None
            ),
            "evidence": [item.payload() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class DailyCandidateFeed:
    header: DailyFeedHeader
    candidates: tuple[DailyFeedCandidate, ...]

    def __post_init__(self) -> None:
        if self.header.candidate_count != len(self.candidates):
            raise FeedValidationError("candidate count does not match the feed population")
        expected_ranks = tuple(range(1, len(self.candidates) + 1))
        if tuple(item.daily_rank for item in self.candidates) != expected_ranks:
            raise FeedValidationError("daily ranks must be complete and contiguous")
        candidate_ids = tuple(item.candidate_id for item in self.candidates)
        if len(candidate_ids) != len(set(candidate_ids)):
            raise FeedValidationError("candidate IDs must be unique within a daily feed")
        tier_order = tuple(_TIER_ORDER[item.priority_tier] for item in self.candidates)
        if tier_order != tuple(sorted(tier_order)):
            raise FeedValidationError("daily feed must preserve P1-before-P2-before-P3 ordering")
        for previous, current in zip(self.candidates, self.candidates[1:], strict=False):
            if (
                previous.priority_tier is current.priority_tier
                and previous.priority_score < current.priority_score
            ):
                raise FeedValidationError("within-tier priority scores must not increase")
        for item in self.candidates:
            if item.day != self.header.day or item.run_id != self.header.run_id:
                raise FeedValidationError(
                    "candidate day/run linkage conflicts with the feed header"
                )
            if (
                item.detector_version != self.header.detector_version
                or item.ranking_version != self.header.ranking_version
            ):
                raise FeedValidationError("candidate versions conflict with the feed header")

    def payload(self) -> dict[str, Any]:
        return {
            "feed_schema_version": self.header.feed_schema_version,
            "day": self.header.day,
            "published_at": self.header.published_at.isoformat(),
            "run_id": str(self.header.run_id),
            "detector_version": self.header.detector_version,
            "ranking_version": self.header.ranking_version,
            "candidate_count": self.header.candidate_count,
            "candidates": [item.payload() for item in self.candidates],
        }

    def to_bytes(self) -> bytes:
        """Serialize the complete feed to deterministic UTF-8 JSON bytes."""

        return json.dumps(
            self.payload(),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")


def iter_daily_candidate_feed_jsonl(feed: DailyCandidateFeed) -> Iterator[bytes]:
    """Yield the versioned feed as a header-first, rank-ordered JSONL stream."""

    yield _jsonl_record(
        {
            "record_type": "header",
            "feed_encoding_version": LEGACY_FEED_STREAM_ENCODING_VERSION,
            "feed_schema_version": feed.header.feed_schema_version,
            "day": feed.header.day,
            "published_at": feed.header.published_at.isoformat(),
            "run_id": str(feed.header.run_id),
            "detector_version": feed.header.detector_version,
            "ranking_version": feed.header.ranking_version,
            "candidate_count": feed.header.candidate_count,
        }
    )
    for candidate in feed.candidates:
        yield _jsonl_record({"record_type": "candidate", "candidate": candidate.payload()})


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
    if not isinstance(raw, str):
        raise FeedValidationError("feed day must use YYYY-MM-DD")
    try:
        day = UtcDay.parse(raw)
    except ValueError as exc:
        raise FeedValidationError("feed day must use YYYY-MM-DD") from exc
    if str(day) != raw:
        raise FeedValidationError("feed day is not canonical")
    return day


def _require_utc(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise FeedValidationError(f"{name} must be timezone-aware UTC")


def _require_uuid(value: UUID, name: str) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise FeedValidationError(f"{name} must be a non-zero UUID")


def _require_version(value: str, name: str) -> None:
    if (
        not isinstance(value, str)
        or not _VERSION.fullmatch(value)
        or _FORBIDDEN_WORDING.search(value)
    ):
        raise FeedValidationError(f"{name} is not a valid machine-readable value")


def _require_machine_code(value: str) -> None:
    if not isinstance(value, str) or not _MACHINE_CODE.fullmatch(value):
        raise FeedValidationError("evidence metric code must be machine-readable")
    if _FORBIDDEN_WORDING.search(value):
        raise FeedValidationError("evidence metric code contains prohibited wording")


def _require_service_id(value: str | None) -> None:
    if value is None:
        return
    try:
        encoded = bytes.fromhex(value)
    except ValueError as exc:
        raise FeedValidationError("service ID must be canonical 128-bit hexadecimal") from exc
    if len(encoded) != 16 or encoded.hex() != value:
        raise FeedValidationError("service ID must be canonical 128-bit hexadecimal")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
