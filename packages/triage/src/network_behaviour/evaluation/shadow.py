"""One shadow-mode behavioural profile, named for its shape, scored outside the publisher.

The shape is a scheduled low-volume channel. Measured at the source's raw one-minute grain on
2026-08-18, it collapsed 173,707 candidate (client, server) pairs to 8. This module scores that
shape at the grain the rest of this system actually uses: `ClientServiceDayRow.active_5m_bitmap`,
the same 288-bucket-per-day bitmap the persistence detector already reads. Thresholds were
re-fitted at that grain rather than rescaled — a single active minute fills a whole five-minute
bucket, so occupancy does not scale linearly (`CASE_STUDY` §13). The sensitivity envelope in
`injection.py` runs against this profile in `measure_beacon_sensitivity` below.

**§2's permutation null does not apply here, and that is a finding, not a gap left for later.**
`permutation.py` relabels the host on a `StagedDay` and asks whether a condition's pass rate moves
— informative exactly where a condition compares a host against *its own history or population
membership*, which is every publisher detector. `beacon_candidates` compares a relationship
against nothing but itself: every stage reads only `active_5m_bitmap`, `up_bytes`, `down_bytes`
and `service_id` off the one row in front of it, and campus fan-in is grouped by `service_id`, not
`client_ip`. Relabelling clients on a `StagedDay` and rescoring is therefore a bijection on labels
with no effect on any stage — verified empirically on 2026-08-09: identical funnel counts at every
stage and an identical candidate set up to which label each row carries (`CASE_STUDY` §13,
`tests/unit/evaluation/test_shadow.py::test_a_client_label_permutation_is_a_structural_no_op`). A
null worth running here would have to perturb something the shape actually reads — which minutes
a host's existing volume occupied, holding its count and total bytes fixed — and that is a
different, unbuilt piece of work, not a rerun of the existing tooling.

**This is evaluation-harness code, nothing else.** It never touches `StagedDay` before scoring
starts, is never called from `operations/pipeline.py` or `run-day`, and writes nothing to
`data/network_behaviour.duckdb`. A host matching this shape today is not flagged, queued or
published by anything upstream of `scripts/evaluate.py shadow`.

**The bucket-grain thresholds below are a recalibration, not a rescaling.** Minute-level occupancy
and bucket-level occupancy are not related by a fixed factor — a single active minute makes a whole
five-minute bucket count as active, so naive division by five overstates how sparse a bucket-grain
schedule looks. Every threshold here was measured directly against `history.client_service_day` on
2026-08-09 (`CASE_STUDY` §13) rather than derived arithmetically from the review's minute-grain
numbers. Two exceptions carry the same value across grains because the quantity itself does not
change scale: `min_span_hours` (a span is a span) and `max_cv` (a coefficient of variation is
already unitless).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise
from random import Random

from network_behaviour.aggregation import ClientServiceDayRow, DayAggregator
from network_behaviour.evaluation.injection import (
    ImplantProfile,
    InjectionError,
    synthesise_activity,
)
from network_behaviour.normalization.bitmap import BUCKET_COUNT, ActivityBitmap
from network_behaviour.time import UtcDay

BEACON_PROFILE_VERSION = "shadow-beacon-v1"


class ShadowProfileError(ValueError):
    """Raised when a shadow-profile input or policy is malformed."""


@dataclass(frozen=True, slots=True)
class BeaconPolicy:
    """Every constant the beacon shape is judged against. Fitted 2026-09-08, `CASE_STUDY` §13."""

    min_active_buckets: int = 6
    max_active_buckets: int = 80
    max_cv: float = 0.15
    min_mean_gap_buckets: float = 2.0
    min_span_hours: float = 6.0
    max_bytes_per_active_bucket: float = 250_000.0
    max_campus_fanin: int = 5
    version: str = BEACON_PROFILE_VERSION

    def __post_init__(self) -> None:
        if not 0 < self.min_active_buckets <= self.max_active_buckets <= BUCKET_COUNT:
            raise ShadowProfileError("beacon active-bucket range is inconsistent")
        if not self.max_cv > 0:
            raise ShadowProfileError("beacon max_cv must be positive")
        if self.min_mean_gap_buckets < 1:
            raise ShadowProfileError("a mean gap below one bucket cannot exclude contiguity")
        if self.min_span_hours <= 0:
            raise ShadowProfileError("beacon min_span_hours must be positive")
        if self.max_bytes_per_active_bucket <= 0:
            raise ShadowProfileError("beacon max_bytes_per_active_bucket must be positive")
        if self.max_campus_fanin < 1:
            raise ShadowProfileError("beacon max_campus_fanin must admit at least one client")


@dataclass(frozen=True, slots=True)
class BeaconCandidate:
    """One relationship that cleared every stage of the funnel.

    `service_basis` and `asn_id` are carried through for the structural characterisation
    `CASE_STUDY` §13 reports — which evidence basis a destination resolved on, not what it is.
    No domain, SNI or endpoint string reaches this module: `ClientServiceDayRow` never carries
    one, by the same rule that keeps retained history hashed.
    """

    client_ip: str
    service_id_hex: str
    service_basis: str
    asn_id: int
    active_buckets: int
    mean_gap_minutes: float
    coefficient_of_variation: float
    span_hours: float
    bytes_per_active_bucket: float
    campus_fanin: int


@dataclass(frozen=True, slots=True)
class BeaconFunnel:
    """The stage-by-stage count this shape's selectivity is measured by.

    Each stage name is the condition just applied, and its count is what survived every condition
    up to and including it.
    """

    day: str
    policy: BeaconPolicy
    evaluated: int
    after_contact_count: int
    after_regularity: int
    after_span: int
    after_volume: int
    candidates: tuple[BeaconCandidate, ...]

    @property
    def after_rarity(self) -> int:
        return len(self.candidates)

    def render(self) -> str:
        lines = [
            f"day {self.day}  policy {self.policy.version}",
            "",
            f"evaluated                                    {self.evaluated:>8,}",
            f"+ plausible contact count "
            f"({self.policy.min_active_buckets}-{self.policy.max_active_buckets} buckets)  "
            f"{self.after_contact_count:>8,}",
            f"+ low timing variation "
            f"(cv < {self.policy.max_cv}, mean gap >= {self.policy.min_mean_gap_buckets} buckets)"
            f"  {self.after_regularity:>8,}",
            f"+ sustained across the day (span >= {self.policy.min_span_hours}h)"
            f"           {self.after_span:>8,}",
            f"+ low volume per active bucket (< {self.policy.max_bytes_per_active_bucket:,.0f} B)"
            f"     {self.after_volume:>8,}",
            f"+ destination almost nobody else uses (fan-in <= {self.policy.max_campus_fanin})"
            f"      {self.after_rarity:>8,}",
        ]
        if self.candidates:
            lines += ["", "candidates (client, service, basis, period):"]
            lines.extend(
                f"  {item.client_ip}  {item.service_id_hex[:12]}  {item.service_basis:<8}  "
                f"{item.mean_gap_minutes:.0f} min  cv={item.coefficient_of_variation:.3f}  "
                f"fanin={item.campus_fanin}"
                for item in self.candidates
            )
            basis_counts = Counter(item.service_basis for item in self.candidates)
            lines += [
                "",
                "service basis: "
                + ", ".join(f"{basis} {count}" for basis, count in sorted(basis_counts.items())),
            ]
        return "\n".join(lines)


def beacon_candidates(
    day: UtcDay,
    service_rows: Sequence[ClientServiceDayRow],
    policy: BeaconPolicy | None = None,
) -> BeaconFunnel:
    """Score one day's relationships against the beacon shape. Pure: reads only its arguments.

    Campus fan-in is computed from `service_rows` itself — the same day's population, not a
    separate query — so this function is self-contained and callable on a synthetic or injected
    day exactly as it is on a retained one.
    """
    policy = policy or BeaconPolicy()
    fanin: dict[bytes, int] = defaultdict(int)
    for row in service_rows:
        fanin[row.service_id] += 1

    after_contact_count = 0
    after_regularity = 0
    after_span = 0
    after_volume = 0
    candidates: list[BeaconCandidate] = []
    for row in service_rows:
        buckets = ActivityBitmap(row.active_5m_bitmap).active_buckets()
        count = len(buckets)
        if not policy.min_active_buckets <= count <= policy.max_active_buckets:
            continue
        after_contact_count += 1

        gaps = tuple(right - left for left, right in pairwise(buckets))
        mean_gap = sum(gaps) / len(gaps)
        if mean_gap == 0:
            continue
        variance = sum((gap - mean_gap) ** 2 for gap in gaps) / len(gaps)
        cv = (variance**0.5) / mean_gap
        if not (cv < policy.max_cv and mean_gap >= policy.min_mean_gap_buckets):
            continue
        after_regularity += 1

        span_hours = (buckets[-1] - buckets[0]) * 5 / 60
        if span_hours < policy.min_span_hours:
            continue
        after_span += 1

        bytes_per_bucket = (row.up_bytes + row.down_bytes) / count
        if bytes_per_bucket >= policy.max_bytes_per_active_bucket:
            continue
        after_volume += 1

        campus_fanin = fanin[row.service_id]
        if campus_fanin > policy.max_campus_fanin:
            continue
        candidates.append(
            BeaconCandidate(
                row.client_ip,
                row.service_id.hex(),
                row.service_basis,
                row.asn_id,
                count,
                mean_gap * 5,
                cv,
                span_hours,
                bytes_per_bucket,
                campus_fanin,
            )
        )

    return BeaconFunnel(
        day.value.isoformat(),
        policy,
        len(service_rows),
        after_contact_count,
        after_regularity,
        after_span,
        after_volume,
        tuple(sorted(candidates, key=lambda item: (item.client_ip, item.service_id_hex))),
    )


@dataclass(frozen=True, slots=True)
class BeaconSurfacing:
    """One injected host under one profile, scored against the beacon funnel alone."""

    client_ip: str
    profile_name: str
    surfaced: bool


@dataclass(frozen=True, slots=True)
class BeaconEnvelopeCell:
    period_minutes: int
    jitter_minutes: int
    injections: int
    surfaced: int

    @property
    def surfaced_rate(self) -> float:
        return self.surfaced / self.injections if self.injections else 0.0


def measure_beacon_sensitivity(
    day: UtcDay,
    hosts: Sequence[str],
    periods_minutes: Sequence[int],
    *,
    occurrences: int = 10,
    up_bytes_per_contact: int = 2_000,
    jitter_minutes_grid: Sequence[int] = (0, 5),
    policy: BeaconPolicy | None = None,
    seed: int = 20260908,
) -> tuple[BeaconEnvelopeCell, ...]:
    """§1 for one shape: synthesise a beacon at each (period, jitter), check it against the funnel.

    Reuses `injection.py`'s synthesis verbatim — the same source-grain implant §1 already requires
    — but scores each implant alone rather than merged into the full day. That is not an
    approximation here: `ImplantProfile.for_host` gives every host a distinct synthetic
    destination (a private-use ASN nothing else can share), so the rarity stage's fan-in is
    always exactly 1 regardless of which real relationships surround it, and every other stage is
    a property of the implant's own bitmap. Scoring against the real population would answer a
    different, real question — whether the implant's *presence* changes which real relationships
    also surface — which this function does not measure.
    """
    if not hosts or not periods_minutes:
        raise ShadowProfileError("a sensitivity sweep needs at least one host and one period")
    cells: list[BeaconEnvelopeCell] = []
    for period in periods_minutes:
        for jitter in jitter_minutes_grid:
            surfaced_count = 0
            for index, client_ip in enumerate(hosts):
                profile = ImplantProfile(
                    f"beacon-{period}m",
                    period_minutes=period,
                    occurrences=occurrences,
                    up_bytes_per_contact=up_bytes_per_contact,
                    jitter_minutes=jitter,
                ).for_host(index)
                rng = Random(seed + index)
                try:
                    observations, _contacts = synthesise_activity(day, client_ip, profile, rng)
                except InjectionError:
                    continue
                implant = DayAggregator().aggregate(day, observations, (), ())
                funnel = beacon_candidates(day, implant.service_rows, policy)
                if funnel.candidates:
                    surfaced_count += 1
            cells.append(BeaconEnvelopeCell(period, jitter, len(hosts), surfaced_count))
    return tuple(cells)
