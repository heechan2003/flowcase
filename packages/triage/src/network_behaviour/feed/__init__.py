"""Versioned all-eligible daily evidence-stream domain.

`domain` is the live contract (`daily-evidence-stream-v2`). `legacy_v1` is frozen and reachable
only from the storage read-back path, so days published under the v1 schema still reconstruct to
the exact bytes their stored digest was taken over.
"""

from network_behaviour.feed.domain import (
    STREAM_ENCODING_VERSION,
    STREAM_SCHEMA_VERSION,
    DailyEvidenceStream,
    StreamBuildMetadata,
    StreamEpisode,
    StreamEvidence,
    StreamHeader,
    StreamValidationError,
    build_daily_evidence_stream,
    iter_daily_evidence_stream_jsonl,
)

__all__ = [
    "STREAM_ENCODING_VERSION",
    "STREAM_SCHEMA_VERSION",
    "DailyEvidenceStream",
    "StreamBuildMetadata",
    "StreamEpisode",
    "StreamEvidence",
    "StreamHeader",
    "StreamValidationError",
    "build_daily_evidence_stream",
    "iter_daily_evidence_stream_jsonl",
]
