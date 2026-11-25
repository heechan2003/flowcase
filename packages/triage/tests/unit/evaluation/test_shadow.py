from random import Random

import pytest

from network_behaviour.aggregation import ClientDayRow, ClientServiceDayRow, StagedDay
from network_behaviour.evaluation.permutation import apply_labels, label_mapping
from network_behaviour.evaluation.shadow import (
    BeaconFunnel,
    BeaconPolicy,
    ShadowProfileError,
    beacon_candidates,
    measure_beacon_sensitivity,
)
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.time import UtcDay

DAY = UtcDay.parse("2026-07-10")
SERVICE_A = bytes.fromhex("01" * 16)
SERVICE_B = bytes.fromhex("02" * 16)
POLICY = BeaconPolicy()


def _row(
    client_ip: str,
    service_id: bytes,
    buckets: tuple[int, ...],
    *,
    up_bytes: int = 1_000,
    down_bytes: int = 0,
    asn_id: int = 64500,
) -> ClientServiceDayRow:
    return ClientServiceDayRow(
        DAY.value,
        client_ip,
        service_id,
        "domain",
        asn_id,
        1,
        6,
        443,
        ActivityBitmap.from_buckets(buckets).value,
        up_bytes,
        down_bytes,
        len(buckets),
        1,
        0,
        0,
        0,
        0.0,
    )


# Eight contacts, 12 buckets (60 minutes) apart: matches the review's dominant real-data period
# and clears every stage at the module's fitted defaults.
_BEACON_BUCKETS = (0, 12, 24, 36, 48, 60, 72, 84)


def test_a_clean_beacon_clears_every_stage() -> None:
    rows = (_row("10.20.1.1", SERVICE_A, _BEACON_BUCKETS, up_bytes=8_000),)

    funnel = beacon_candidates(DAY, rows, POLICY)

    assert funnel.evaluated == 1
    assert funnel.after_contact_count == 1
    assert funnel.after_regularity == 1
    assert funnel.after_span == 1
    assert funnel.after_volume == 1
    assert funnel.after_rarity == 1
    candidate = funnel.candidates[0]
    assert candidate.client_ip == "10.20.1.1"
    assert candidate.mean_gap_minutes == 60.0
    assert candidate.coefficient_of_variation == 0.0
    assert candidate.campus_fanin == 1


def test_a_contiguous_session_fails_the_regularity_stage() -> None:
    """A held-open connection occupies every consecutive bucket: gap 1, cv 0 — the beacon shape's
    `min_mean_gap_buckets` floor exists precisely to reject this, the same trap `CASE_STUDY` §10
    already documents for the raw source grain."""
    rows = (_row("10.20.1.1", SERVICE_A, tuple(range(20))),)

    funnel = beacon_candidates(DAY, rows, POLICY)

    assert funnel.after_contact_count == 1
    assert funnel.after_regularity == 0
    assert funnel.candidates == ()


def test_a_widely_used_destination_fails_the_rarity_stage() -> None:
    rows = tuple(
        _row(f"10.20.1.{index}", SERVICE_A, _BEACON_BUCKETS, up_bytes=8_000)
        for index in range(1, POLICY.max_campus_fanin + 3)
    )

    funnel = beacon_candidates(DAY, rows, POLICY)

    assert funnel.after_volume == len(rows)
    assert funnel.after_rarity == 0
    assert funnel.candidates == ()


def test_a_high_volume_relationship_fails_the_volume_stage() -> None:
    rows = (
        _row(
            "10.20.1.1",
            SERVICE_A,
            _BEACON_BUCKETS,
            up_bytes=int(POLICY.max_bytes_per_active_bucket) * len(_BEACON_BUCKETS),
        ),
    )

    funnel = beacon_candidates(DAY, rows, POLICY)

    assert funnel.after_span == 1
    assert funnel.after_volume == 0


def test_a_short_span_fails_before_volume_is_checked() -> None:
    # Six regularly-spaced contacts (enough to clear the contact-count floor) packed into 2h,
    # short of the 6h span floor.
    rows = (_row("10.20.1.1", SERVICE_A, (0, 5, 10, 15, 20, 25), up_bytes=1_000),)

    funnel = beacon_candidates(DAY, rows, POLICY)

    assert funnel.after_regularity == 1
    assert funnel.after_span == 0


def test_two_relationships_share_no_state() -> None:
    rows = (
        _row("10.20.1.1", SERVICE_A, _BEACON_BUCKETS, up_bytes=8_000),
        _row("10.20.1.1", SERVICE_B, tuple(range(20))),
    )

    funnel = beacon_candidates(DAY, rows, POLICY)

    assert funnel.evaluated == 2
    assert funnel.after_rarity == 1
    assert funnel.candidates[0].service_id_hex == SERVICE_A.hex()


def test_policy_rejects_arithmetically_inconsistent_thresholds() -> None:
    with pytest.raises(ShadowProfileError, match="inconsistent"):
        BeaconPolicy(min_active_buckets=80, max_active_buckets=6)
    with pytest.raises(ShadowProfileError, match="one bucket"):
        BeaconPolicy(min_mean_gap_buckets=0.5)


def test_sensitivity_recovers_a_matching_beacon() -> None:
    """§1 for this shape: a synthesised 60-minute beacon, scored alone, should surface reliably.

    `measure_beacon_sensitivity` scores each implant on its own rather than merged into a real
    population — exact here because `ImplantProfile.for_host` gives every host a distinct
    synthetic destination, so the rarity stage's fan-in is always 1 by construction.
    """
    hosts = tuple(f"10.20.1.{index}" for index in range(1, 6))

    cells = measure_beacon_sensitivity(
        DAY,
        hosts,
        periods_minutes=(60,),
        occurrences=8,
        up_bytes_per_contact=1_000,
        jitter_minutes_grid=(0,),
        policy=POLICY,
    )

    assert len(cells) == 1
    cell = cells[0]
    assert cell.period_minutes == 60
    assert cell.injections == len(hosts)
    assert cell.surfaced == len(hosts)
    assert cell.surfaced_rate == 1.0


def test_sensitivity_rejects_a_period_too_short_to_leave_a_gap() -> None:
    """A 5-minute period occupies every consecutive bucket — the same contiguity trap as a
    held-open session — and should not surface, same failure as the regularity-stage test above."""
    hosts = tuple(f"10.20.1.{index}" for index in range(1, 4))

    cells = measure_beacon_sensitivity(
        DAY,
        hosts,
        periods_minutes=(5,),
        occurrences=20,
        up_bytes_per_contact=1_000,
        jitter_minutes_grid=(0,),
        policy=POLICY,
    )

    assert cells[0].surfaced == 0


def _client_row(client_ip: str) -> ClientDayRow:
    """Minimal enough for `build_strata`: only `client_ip` and `day` are read from it.

    `stratum_key` computes occupancy from `staged.service_rows`, not from this row.
    """
    return ClientDayRow(
        day=DAY.value,
        client_ip=client_ip,
        up_bytes=0,
        down_bytes=0,
        up_packets=0,
        down_packets=0,
        flow_count=0,
        active_minutes=0,
        active_5m_buckets=0,
        unique_servers=1,
        unique_services=1,
        unique_routes=1,
        unique_asns=1,
        unique_port_groups=1,
        top_service_up_bytes=0,
        top_service_total_bytes=0,
        opaque_bytes=0,
        p95_5m_up_bytes=0.0,
        max_5m_up_bytes=0,
        p95_5m_unique_servers=0.0,
        max_5m_unique_servers=0,
        p95_5m_unique_services=0.0,
        max_5m_unique_services=0,
        p95_5m_unique_port_groups=0.0,
        max_5m_unique_port_groups=0,
        p95_bucket_up_rate_p95_bps=0.0,
        max_bucket_up_rate_p95_bps=0.0,
        large_flow_count=0,
        large_flow_up_bytes=0,
        max_large_flow_bytes=0,
        max_large_flow_duration_sec=0.0,
    )


def test_a_client_label_permutation_is_a_structural_no_op() -> None:
    """§2's permutation null cannot be informative for this profile, and this is why.

    Every stage in `beacon_candidates` reads only a row's own `active_5m_bitmap`, `up_bytes`,
    `down_bytes` and `service_id` — never `client_ip` except to report it — and campus fan-in
    groups by `service_id`, not by client. Relabelling clients is therefore a rename with no
    effect on which rows pass. See `network_behaviour.evaluation.shadow`'s module docstring.
    """
    rows = (
        _row("10.20.1.1", SERVICE_A, _BEACON_BUCKETS, up_bytes=8_000),
        _row("10.20.1.1", SERVICE_B, tuple(range(20))),
        _row("10.20.1.2", SERVICE_A, _BEACON_BUCKETS, up_bytes=8_000, asn_id=64501),
        _row("10.20.1.3", SERVICE_B, (0, 5, 10, 15, 20, 25)),
    )
    staged = StagedDay(
        DAY,
        tuple(_client_row(ip) for ip in ("10.20.1.1", "10.20.1.2", "10.20.1.3")),
        rows,
    )
    observed = beacon_candidates(DAY, staged.service_rows, POLICY)

    mapping = label_mapping(staged, Random(7))
    permuted = apply_labels(staged, mapping)
    result = beacon_candidates(DAY, permuted.service_rows, POLICY)

    assert (
        observed.evaluated,
        observed.after_contact_count,
        observed.after_regularity,
        observed.after_span,
        observed.after_volume,
        observed.after_rarity,
    ) == (
        result.evaluated,
        result.after_contact_count,
        result.after_regularity,
        result.after_span,
        result.after_volume,
        result.after_rarity,
    )

    def label_free(funnel: BeaconFunnel) -> list[tuple[str, int, int]]:
        return sorted(
            (item.service_id_hex, item.active_buckets, item.campus_fanin)
            for item in funnel.candidates
        )

    assert label_free(observed) == label_free(result)
