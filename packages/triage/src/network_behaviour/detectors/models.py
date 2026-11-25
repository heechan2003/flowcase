"""Typed detector policy, evidence, and output envelopes."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from math import isfinite

from network_behaviour.baselines.models import HistoryConfidence, ServiceConfidence
from network_behaviour.domain import EvidenceGroup, ReasonCode, code_mask
from network_behaviour.population import CURRENT_SUPPORT_DEFINITION, SupportDefinition

DETECTOR_VERSION = "primary-detectors-v9"

# What a large flow must be to count as independent corroboration: more extreme than this share
# of the large flows the same host has already made, on size or on duration. Declared once and
# read by both policies, here and in the ranking engine, because the detector records
# whether a unit qualified (docs/EVALUATION.md §5) and the ranking engine acts on it (the tier
# ladder). Two copies of the number would let the instrumentation describe a decision the engine
# no longer takes; `tests/unit/test_policy_thresholds.py` pins them equal.
CORROBORATION_STRENGTH = 97.5

# What a new DNS resolver must carry on day D before its novelty is worth reporting, in sessions
# on that resolver alone. Fitted in `primary-detectors-v7` on 2026-08-10..30, when most of what
# `dns_pairs` called clients were addresses that sent no query at all (804 of 1,057 on 2026-08-30;
# `CASE_STUDY.md`, superseded values). Re-measured 2026-10-23 on the clients that query, without the
# DNS servers: a queried (client, resolver) pair carries a median of 12-15 sessions a day and a p75
# of 24-26, so at 10 a new resolver still has to be used about as heavily as an ordinary one
# (`CASE_STUDY` §9). Not held at `dns_min_sessions`, which counts a whole client-day.
DNS_NEW_RESOLVER_MIN_SESSIONS = 10

# A client-day that sent queries to this many distinct resolvers is a DNS server — a campus
# recursive resolver asking authoritative servers — not a client choosing a resolver. Measured
# 2026-10-23 over 2026-07-01..10-22: client-days with a query sit at p50 3 and p90 4 resolvers,
# 556 fall in [10, 100), 10 in [100, 1,000) and 421 at 1,000 or more, on 7 addresses. Those
# addresses carried 129 of 335 published DNS episodes (2026-09-01..10-18), one on 43 of 45 days,
# because every new authoritative server read as a new resolver (`CASE_STUDY` §9).
DNS_SERVER_MIN_RESOLVERS = 100


class DetectorFamily(StrEnum):
    TRANSFER = "transfer"
    RELATIONSHIP = "relationship"
    FANOUT = "fanout"
    DNS = "dns"
    PERSISTENCE = "persistence"


FAMILY_ORDER = {
    DetectorFamily.TRANSFER: 0,
    DetectorFamily.RELATIONSHIP: 1,
    DetectorFamily.FANOUT: 2,
    DetectorFamily.DNS: 3,
    DetectorFamily.PERSISTENCE: 4,
}


class DecisionStatus(StrEnum):
    INELIGIBLE = "ineligible"
    DIAGNOSTIC = "diagnostic"


@dataclass(frozen=True, slots=True)
class DetectorPolicy:
    moderate_strength: float = 97.5
    strong_strength: float = 99.0
    audit_floor_strength: float = 95.0
    corroboration_strength: float = CORROBORATION_STRENGTH
    # Which addresses have a behavioural day at all. One object rather than two loose integers,
    # because it is the denominator of every rarity strength and the membership of every peer
    # band — see network_behaviour.population.
    support: SupportDefinition = field(default_factory=lambda: CURRENT_SUPPORT_DEFINITION)
    # There is no second gate. `relationship_min_active_buckets = 2` and `relationship_min_flows =
    # 5` were a service-level support gate, removed in `primary-detectors-v4`: they excluded 32.61%
    # of service-days on 2026-08-09, and among what they excluded were 32 transfers of 100 MiB or
    # more, the largest 2.32 GB, dropped for having one active bucket and no recorded long flow.
    dns_min_packets: int = 100
    dns_min_sessions: int = 50
    # Applies to each new resolver on its own, not to the client-day denominator the two gates
    # above use. See DNS_NEW_RESOLVER_MIN_SESSIONS.
    dns_new_resolver_min_sessions: int = DNS_NEW_RESOLVER_MIN_SESSIONS
    # A client-day at or above this many queried resolvers is a DNS server and is out of the DNS
    # family. See DNS_SERVER_MIN_RESOLVERS.
    dns_server_min_resolvers: int = DNS_SERVER_MIN_RESOLVERS
    persistence_min_prior_days: int = 4
    persistence_lookback_days: int = 30
    version: str = DETECTOR_VERSION

    def __post_init__(self) -> None:
        if (
            not 0
            <= self.audit_floor_strength
            <= self.moderate_strength
            <= self.strong_strength
            <= 100
        ):
            raise ValueError("detector strength thresholds are inconsistent")
        if not 0 <= self.corroboration_strength <= 100:
            raise ValueError("corroboration strength must be a tail probability in [0, 100]")
        counts = (
            self.dns_min_packets,
            self.dns_min_sessions,
            self.dns_new_resolver_min_sessions,
            self.dns_server_min_resolvers,
            self.persistence_min_prior_days,
            self.persistence_lookback_days,
        )
        if any(value <= 0 for value in counts):
            raise ValueError("detector support thresholds must be positive")
        if self.persistence_lookback_days < self.persistence_min_prior_days:
            raise ValueError("persistence lookback is shorter than its support gate")


@dataclass(frozen=True, slots=True)
class DetectorEvidence:
    group: EvidenceGroup
    metric_code: str
    observed_value: float
    client_baseline_value: float | None = None
    peer_reference_value: float | None = None
    self_strength: float | None = None
    peer_strength: float | None = None
    metric_strength: float | None = None
    support_count: int | None = None

    def __post_init__(self) -> None:
        numeric = (
            self.observed_value,
            self.client_baseline_value,
            self.peer_reference_value,
            self.self_strength,
            self.peer_strength,
            self.metric_strength,
        )
        if any(value is not None and not isfinite(value) for value in numeric):
            raise ValueError("detector evidence values must be finite")
        for strength in (self.self_strength, self.peer_strength, self.metric_strength):
            if strength is not None and not 0 <= strength <= 100:
                raise ValueError("detector evidence strength must be between zero and 100")
        if self.support_count is not None and self.support_count < 0:
            raise ValueError("detector evidence support cannot be negative")


@dataclass(frozen=True, slots=True)
class DetectorSignal:
    client_ip: str
    family: DetectorFamily
    label: str
    family_strength: float
    history_confidence: HistoryConfidence
    evidence: tuple[DetectorEvidence, ...]
    reason_codes: tuple[ReasonCode, ...]
    service_id_hex: str | None = None
    asn_id: int | None = None
    service_confidence: ServiceConfidence | None = None

    @property
    def evidence_group_mask(self) -> int:
        return code_mask(*(item.group for item in self.evidence))

    @property
    def reason_code_mask(self) -> int:
        return code_mask(*self.reason_codes)


@dataclass(frozen=True, slots=True)
class DetectorDiagnostic:
    client_ip: str
    family: DetectorFamily
    status: DecisionStatus
    reason_codes: tuple[ReasonCode, ...]
    service_id_hex: str | None = None
    asn_id: int | None = None
    near_threshold_signal: DetectorSignal | None = None


@dataclass(frozen=True, slots=True)
class DetectionBatch:
    day: str
    version: str
    signals: tuple[DetectorSignal, ...]
    diagnostics: tuple[DetectorDiagnostic, ...]

    def to_bytes(self) -> bytes:
        return json.dumps(
            asdict(self),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
