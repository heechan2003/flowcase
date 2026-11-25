from dataclasses import replace
from datetime import date, timedelta

from network_behaviour.aggregation import ClientDayRow, ClientServiceDayRow
from network_behaviour.baselines.models import (
    BASELINE_VERSION,
    CLIENT_METRICS,
    BaselineBatch,
    ClientBaselineContext,
    HistoryConfidence,
    MetricCalibration,
    RelationshipBaselineContext,
    ServiceConfidence,
    SourceQualityContext,
)
from network_behaviour.detectors import (
    DetectionBatch,
    DetectorEngine,
    DetectorFamily,
    DetectorPolicy,
    DnsDailyObservation,
)
from network_behaviour.detectors.dns import calibrate_dns_metrics, dns_population_by_day
from network_behaviour.detectors.models import DetectorEvidence, DetectorSignal
from network_behaviour.detectors.persistence import RelationshipBitmapDay
from network_behaviour.domain import EvidenceGroup, ReasonCode
from network_behaviour.instrumentation import Combinator, ConditionLog
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.operations.scoring import build_ranking_inputs
from network_behaviour.population import RETIRED_SUPPORT_DEFINITION_V2
from network_behaviour.ranking import TemporalPrecision
from network_behaviour.time import UtcDay

DAY = UtcDay.parse("2026-07-10")
SERVICE = bytes.fromhex("01" * 16)


def _client(client_ip: str, **updates: int | float) -> ClientDayRow:
    values: dict[str, object] = {
        "day": DAY.value,
        "client_ip": client_ip,
        "up_bytes": 1_000,
        "down_bytes": 500,
        "up_packets": 100,
        "down_packets": 50,
        "flow_count": 100,
        "active_minutes": 60,
        "active_5m_buckets": 10,
        "unique_servers": 5,
        "unique_services": 3,
        "unique_routes": 3,
        "unique_asns": 2,
        "unique_port_groups": 2,
        "top_service_up_bytes": 500,
        "top_service_total_bytes": 700,
        "opaque_bytes": 0,
        "p95_5m_up_bytes": 100.0,
        "max_5m_up_bytes": 200,
        "p95_5m_unique_servers": 2.0,
        "max_5m_unique_servers": 3,
        "p95_5m_unique_services": 1.0,
        "max_5m_unique_services": 2,
        "p95_5m_unique_port_groups": 1.0,
        "max_5m_unique_port_groups": 2,
        "p95_bucket_up_rate_p95_bps": 100.0,
        "max_bucket_up_rate_p95_bps": 200.0,
        "large_flow_count": 0,
        "large_flow_up_bytes": 0,
        "max_large_flow_bytes": 0,
        "max_large_flow_duration_sec": 0.0,
    }
    values.update(updates)
    return ClientDayRow(**values)  # type: ignore[arg-type]


def _service(
    client_ip: str,
    *,
    bitmap: ActivityBitmap | None = None,
    flow_count: int = 5,
    large_flow_count: int = 0,
) -> ClientServiceDayRow:
    return ClientServiceDayRow(
        DAY.value,
        client_ip,
        SERVICE,
        "domain",
        64500,
        1,
        6,
        443,
        (bitmap or ActivityBitmap.from_buckets((10, 11))).value,
        1_000,
        500,
        flow_count,
        1,
        large_flow_count,
        1_000_000 if large_flow_count else 0,
        1_500_000 if large_flow_count else 0,
        60.0 if large_flow_count else 0.0,
    )


def _client_context(
    client: ClientDayRow,
    strengths: dict[str, float] | None = None,
    *,
    confidence: HistoryConfidence = HistoryConfidence.NORMAL,
    quality: SourceQualityContext | None = None,
    large_flow_strength: float = 0.0,
) -> ClientBaselineContext:
    strengths = strengths or {}
    metrics = tuple(
        MetricCalibration(
            name=name,
            current_value=float(getattr(client, name)),
            recent=None,
            long=None,
            same_weekday=None,
            current_residual=(1.0 if name in strengths else None),
            self_percentile=(strengths[name] / 100 if name in strengths else None),
            peer_percentile=(strengths[name] / 100 if name in strengths else None),
            metric_strength=strengths.get(name),
        )
        for name in CLIENT_METRICS
    )
    return ClientBaselineContext(
        client.client_ip,
        20,
        confidence,
        "bytes0-minutes1-destinations1",
        True,
        metrics,
        quality or SourceQualityContext(True, True, True, True, True, False, 0.0),
        large_flow_size_strength=large_flow_strength,
        large_flow_duration_strength=0.0,
        large_flow_strength=large_flow_strength,
    )


def _relationship_context(
    client_ip: str,
    *,
    prior_days: int = 0,
    new_service: bool = True,
    new_route: bool = True,
    historical_prevalence: float = 0.0,
    current_prevalence: float = 0.01,
    joint_strength: float = 99.5,
    novelty_strength: float = 96.0,
    rarity_strength: float = 99.5,
    large_flow_strength: float = 0.0,
) -> RelationshipBaselineContext:
    """One calibrated relationship unit.

    The three strengths are set here rather than derived, because they are properties of a
    population and not of one unit: `BaselineEngine._calibrate_relationships` ranks every unit of
    the day against every other, so a single hand-built context has no calibrated strength at all
    — on its own it is at the midpoint of a population of one. These tests are about what the
    detector does with a strength; `tests/unit/baselines/test_relationship_calibration.py` is
    about where the strength comes from.
    """
    return RelationshipBaselineContext(
        client_ip,
        SERVICE.hex(),
        64500,
        ServiceConfidence.HIGH,
        prior_days,
        None if new_service else 1,
        new_service,
        prior_days,
        None if new_route else 1,
        new_route,
        historical_prevalence,
        historical_prevalence,
        current_prevalence,
        current_prevalence,
        novelty_strength,
        rarity_strength,
        joint_strength,
        large_flow_size_strength=large_flow_strength,
        large_flow_duration_strength=0.0,
        large_flow_strength=large_flow_strength,
    )


def _baselines(
    clients: tuple[ClientBaselineContext, ...],
    relationships: tuple[RelationshipBaselineContext, ...] = (),
) -> BaselineBatch:
    return BaselineBatch(DAY.value.isoformat(), BASELINE_VERSION, clients, relationships)


def test_transfer_injection_triggers_only_transfer_and_context_cannot_create_it() -> None:
    current = _client("10.20.1.1", large_flow_count=2, large_flow_up_bytes=2_000_000)
    context = _client_context(
        current,
        {"up_bytes": 99.0, "max_bucket_up_rate_p95_bps": 100.0},
    )

    batch = DetectorEngine().detect(DAY, (current,), (), _baselines((context,)))
    transfer_only = DetectorEngine().detect(
        DAY,
        (current,),
        (),
        _baselines((context,)),
        families=frozenset({DetectorFamily.TRANSFER}),
    )

    assert [signal.family for signal in batch.signals] == [DetectorFamily.TRANSFER]
    assert transfer_only == DetectionBatch(
        transfer_only.day,
        transfer_only.version,
        batch.signals,
        tuple(item for item in batch.diagnostics if item.family is DetectorFamily.TRANSFER),
    )
    signal = batch.signals[0]
    # Correlated magnitude/rate alternatives contribute only their strongest group.
    assert [item.group for item in signal.evidence] == [
        EvidenceGroup.TRANSFER_BURST,
        EvidenceGroup.LARGE_FLOW_CONTEXT,
    ]
    assert signal.family_strength == 100.0

    without_large_flow = replace(
        current,
        large_flow_count=0,
        large_flow_up_bytes=0,
    )
    without_context = DetectorEngine().detect(
        DAY, (without_large_flow,), (), _baselines((context,))
    )
    assert without_context.signals[0].family_strength == signal.family_strength

    no_primary = _client_context(current, {})
    without = DetectorEngine().detect(DAY, (current,), (), _baselines((no_primary,)))
    assert not without.signals


def test_transfer_threshold_downstream_exclusion_and_missing_optional_context() -> None:
    current = _client("10.20.1.1")
    below = _client_context(current, {"up_bytes": 98.999, "down_bytes": 100.0})
    missing = SourceQualityContext(True, True, False, True, False, False, 0.0)
    exact = _client_context(current, {"up_bytes": 99.0}, quality=missing)

    assert not DetectorEngine().detect(DAY, (current,), (), _baselines((below,))).signals
    below_batch = DetectorEngine().detect(DAY, (current,), (), _baselines((below,)))
    near = next(
        item.near_threshold_signal
        for item in below_batch.diagnostics
        if item.family is DetectorFamily.TRANSFER
    )
    assert near is not None
    assert near.family_strength == 98.999
    assert ReasonCode.INSUFFICIENT_SUPPORT in near.reason_codes
    signal = DetectorEngine().detect(DAY, (current,), (), _baselines((exact,))).signals[0]
    assert signal.family is DetectorFamily.TRANSFER
    assert ReasonCode.MISSING_OPTIONAL_CONTEXT in signal.reason_codes


def test_below_threshold_audit_floor_is_exact_and_does_not_create_candidates() -> None:
    current = _client("10.20.1.1")
    exact = _client_context(current, {"up_bytes": 95.0})
    below = _client_context(current, {"up_bytes": 94.999})

    exact_batch = DetectorEngine().detect(DAY, (current,), (), _baselines((exact,)))
    below_batch = DetectorEngine().detect(DAY, (current,), (), _baselines((below,)))

    assert not exact_batch.signals and not below_batch.signals
    assert any(item.near_threshold_signal is not None for item in exact_batch.diagnostics)
    assert all(item.near_threshold_signal is None for item in below_batch.diagnostics)


def test_relationship_eligibility_is_the_calibrated_joint_tail() -> None:
    """`primary-detectors-v5`: one threshold against one calibrated strength.

    Under v4 this asserted `family_strength == 97.5` — a rung of the retired novelty ladder,
    reached by 82.5% of relationship candidates. The strength is now the joint tail probability
    `BaselineEngine` calibrated, and it is the only quantity the eligibility branch reads.
    """
    client = _client("10.20.1.1")
    service = _service(
        client.client_ip,
        bitmap=ActivityBitmap.from_buckets((10, 11, 30)),
    )
    client_context = _client_context(client)
    rare = _relationship_context(client.client_ip, current_prevalence=0.025)

    batch = DetectorEngine().detect(
        DAY,
        (client,),
        (service,),
        _baselines((client_context,), (rare,)),
    )

    assert [signal.family for signal in batch.signals] == [DetectorFamily.RELATIONSHIP]
    assert batch.signals[0].family_strength == rare.joint_strength
    assert batch.signals[0].service_confidence is ServiceConfidence.HIGH
    assert {item.group for item in batch.signals[0].evidence} == {
        EvidenceGroup.RELATIONSHIP_NOVELTY,
        EvidenceGroup.POPULATION_RARITY,
    }
    strengths = {item.group: item.metric_strength for item in batch.signals[0].evidence}
    assert strengths[EvidenceGroup.RELATIONSHIP_NOVELTY] == rare.novelty_strength
    assert strengths[EvidenceGroup.POPULATION_RARITY] == rare.rarity_strength
    relationship_episodes = build_ranking_inputs(DAY, batch.signals, (service,))
    assert len(relationship_episodes) == 2
    assert all(
        item.temporal_precision is TemporalPrecision.FIVE_MINUTE for item in relationship_episodes
    )

    # Prevalence no longer decides anything on its own: it is an input to the calibration, and
    # the calibration is what the detector reads. Moving it without moving the strength changes
    # the reported observed value and nothing else.
    broad_prevalence = replace(rare, current_service_prevalence=0.5, current_route_prevalence=0.5)
    assert (
        DetectorEngine()
        .detect(DAY, (client,), (service,), _baselines((client_context,), (broad_prevalence,)))
        .signals
    )

    # Below the threshold, the weaker axis names the reason. Rarity weaker: widely used.
    broad = replace(rare, joint_strength=60.0, novelty_strength=96.0, rarity_strength=40.0)
    suppressed = DetectorEngine().detect(
        DAY, (client,), (service,), _baselines((client_context,), (broad,))
    )
    assert not suppressed.signals
    assert any(
        ReasonCode.BROAD_EVENT_SUPPRESSED in item.reason_codes
        for item in suppressed.diagnostics
        if item.family is DetectorFamily.RELATIONSHIP
    )

    # Novelty weaker: a destination this host already knows well.
    familiar = replace(rare, joint_strength=60.0, novelty_strength=20.0, rarity_strength=99.5)
    unsupported = DetectorEngine().detect(
        DAY, (client,), (service,), _baselines((client_context,), (familiar,))
    )
    assert not unsupported.signals
    assert any(
        ReasonCode.INSUFFICIENT_SUPPORT in item.reason_codes
        for item in unsupported.diagnostics
        if item.family is DetectorFamily.RELATIONSHIP
    )

    low_confidence = replace(rare, service_confidence=ServiceConfidence.LOW)
    low = DetectorEngine().detect(
        DAY,
        (client,),
        (service,),
        _baselines((client_context,), (low_confidence,)),
    )
    assert low.signals[0].service_confidence is ServiceConfidence.LOW


def test_a_quiet_bulk_transfer_is_no_longer_dropped_for_looking_idle() -> None:
    """`primary-detectors-v4` removed the service-level support gate. This is what it hid.

    The retired predicate was `active_buckets >= 2 or flow_count >= 5 or large_flow_count > 0`. A
    single-bucket, single-flow service-day with no *recorded* long flow failed all three arms and
    was ineligible before any strength was computed — and on 2026-08-09 that shape covered 32
    service-days moving 100 MiB or more across 23 addresses, the largest 2.32 GB. The long-flow
    source recording nothing is exactly the case `CLAUDE.md` says must never cost strength.

    No test ever referenced the gate while it was in force, which is why removing it broke nothing.
    """

    client = _client("10.20.1.1")
    quiet = _service(
        client.client_ip,
        bitmap=ActivityBitmap.from_buckets((10,)),
        flow_count=1,
        large_flow_count=0,
    )
    rare = _relationship_context(client.client_ip, current_prevalence=0.025)

    batch = DetectorEngine().detect(
        DAY, (client,), (quiet,), _baselines((_client_context(client),), (rare,))
    )

    assert [signal.family for signal in batch.signals] == [DetectorFamily.RELATIONSHIP]
    assert not any(
        ReasonCode.INSUFFICIENT_SUPPORT in item.reason_codes
        for item in batch.diagnostics
        if item.family is DetectorFamily.RELATIONSHIP
    )


def test_fanout_injection_triggers_only_approved_behavioural_label() -> None:
    current = _client("10.20.1.1", max_5m_unique_servers=500)
    context = _client_context(current, {"max_5m_unique_servers": 99.0})

    batch = DetectorEngine().detect(DAY, (current,), (), _baselines((context,)))

    assert [signal.family for signal in batch.signals] == [DetectorFamily.FANOUT]
    assert batch.signals[0].label == "external fanout change"
    assert batch.signals[0].evidence[0].group is EvidenceGroup.FANOUT


def test_dns_injection_uses_one_strong_supported_change_and_missing_dns_is_local() -> None:
    target = _client("10.20.1.1")
    peers = tuple(_client(f"10.20.2.{index}") for index in range(1, 100))
    clients = (target, *peers)
    contexts = tuple(_client_context(client) for client in clients)
    observations = (
        _dns(target.client_ip, "shared-resolver", query_packets=1_000, complete_sessions=500),
        *(
            _dns(peer.client_ip, "shared-resolver", query_packets=100, complete_sessions=50)
            for peer in peers
        ),
    )

    batch = DetectorEngine().detect(
        DAY,
        clients,
        (),
        _baselines(contexts),
        dns_observations=observations,
    )

    assert [(item.client_ip, item.family) for item in batch.signals] == [
        (target.client_ip, DetectorFamily.DNS)
    ]
    assert batch.signals[0].evidence[0].support_count is not None

    unavailable = replace(
        contexts[0],
        source_quality=replace(contexts[0].source_quality, dns_context_available=False),
    )
    missing = DetectorEngine().detect(
        DAY, (target,), (), _baselines((unavailable,)), dns_observations=()
    )
    assert not missing.signals
    assert any(
        item.family is DetectorFamily.DNS
        and ReasonCode.MISSING_OPTIONAL_CONTEXT in item.reason_codes
        for item in missing.diagnostics
    )


def test_an_address_with_no_service_row_is_out_of_the_activity_families_but_not_dns() -> None:
    """`behavioural-support-v3`: transfer and fanout score only addresses with a service row.

    An address carrying only unaddressed rows — no server, port or domain (`CASE_STUDY` §3) —
    has nothing "external" to measure, however extreme its bytes look. DNS is different:
    `activity_1m` has no DNS rows, so a DNS-only address has no service row and is still
    a DNS client (`CASE_STUDY` §9).
    """
    unaddressed = _client(
        "10.20.1.1", unique_services=0, unique_routes=0, max_5m_unique_servers=500
    )
    context = _client_context(unaddressed, {"up_bytes": 99.9, "max_5m_unique_servers": 99.9})
    activity = DetectorEngine().detect(DAY, (unaddressed,), (), _baselines((context,)))
    assert not activity.signals
    assert {
        item.family
        for item in activity.diagnostics
        if ReasonCode.INSUFFICIENT_SUPPORT in item.reason_codes
    } >= {DetectorFamily.TRANSFER, DetectorFamily.FANOUT}

    ungated = DetectorEngine(DetectorPolicy(support=RETIRED_SUPPORT_DEFINITION_V2)).detect(
        DAY, (unaddressed,), (), _baselines((context,))
    )
    assert {signal.family for signal in ungated.signals} == {
        DetectorFamily.TRANSFER,
        DetectorFamily.FANOUT,
    }

    peers = tuple(_client(f"10.20.2.{index}") for index in range(1, 100))
    clients = (unaddressed, *peers)
    observations = (
        _dns(unaddressed.client_ip, "shared-resolver", query_packets=1_000, complete_sessions=500),
        *(
            _dns(peer.client_ip, "shared-resolver", query_packets=100, complete_sessions=50)
            for peer in peers
        ),
    )
    dns = DetectorEngine().detect(
        DAY,
        clients,
        (),
        _baselines(tuple(_client_context(client) for client in clients)),
        dns_observations=observations,
        families=frozenset({DetectorFamily.DNS}),
    )
    assert [(item.client_ip, item.family) for item in dns.signals] == [
        (unaddressed.client_ip, DetectorFamily.DNS)
    ]


def test_dns_requires_two_independent_moderate_concepts_when_none_is_strong() -> None:
    target = _client("10.20.1.1")
    peers = tuple(_client(f"10.20.2.{index}") for index in range(1, 100))
    clients = (target, *peers)
    contexts = tuple(_client_context(client) for client in clients)
    base = (
        _dns(target.client_ip, "shared-resolver", query_packets=1_000, complete_sessions=500),
        *(
            _dns(peer.client_ip, "shared-resolver", query_packets=100, complete_sessions=50)
            for peer in peers
        ),
    )
    target_unsolicited = replace(base[0], unsolicited_sessions=25, unsolicited_response_packets=50)
    policy = DetectorPolicy(
        audit_floor_strength=85.0, moderate_strength=90.0, strong_strength=100.0
    )

    one_concept = DetectorEngine(policy).detect(
        DAY, clients, (), _baselines(contexts), dns_observations=base
    )
    two_concepts = DetectorEngine(policy).detect(
        DAY,
        clients,
        (),
        _baselines(contexts),
        dns_observations=(target_unsolicited, *base[1:]),
    )

    assert not any(
        item.client_ip == target.client_ip and item.family is DetectorFamily.DNS
        for item in one_concept.signals
    )
    signal = next(
        item
        for item in two_concepts.signals
        if item.client_ip == target.client_ip and item.family is DetectorFamily.DNS
    )
    assert len(signal.evidence) == 2
    assert len({item.group for item in signal.evidence}) == 2


def test_dns_service_time_is_shared_context_and_cannot_carry_a_signal() -> None:
    """`primary-detectors-v7`: mean service time is the resolver's, not the client's.

    56.5% of the variance in per-(client, resolver) mean service time sat between resolvers
    rather than within them on 2026-08-30 (`CASE_STUDY.md`, superseded values), so a resolver
    slowing down deviates every client behind it on the same day. It is still reported — an analyst
    reading an episode should see it — but it establishes nothing on its own.
    """
    target = _client("10.20.1.1")
    peers = tuple(_client(f"10.20.2.{index}") for index in range(1, 100))
    clients = (target, *peers)
    contexts = tuple(_client_context(client) for client in clients)
    flat = tuple(
        _dns(client.client_ip, "shared-resolver", query_packets=100, complete_sessions=50)
        for client in clients
    )
    slow_only = (replace(flat[0], weighted_service_nanos=5_000_000.0), *flat[1:])
    busy_and_slow = (
        replace(
            flat[0],
            query_packets=1_000,
            complete_sessions=500,
            weighted_service_nanos=50_000_000.0,
            weighted_service_sessions=500,
            response_packets=1_000,
        ),
        *flat[1:],
    )

    alone = DetectorEngine().detect(
        DAY, clients, (), _baselines(contexts), dns_observations=slow_only
    )
    beside = DetectorEngine().detect(
        DAY, clients, (), _baselines(contexts), dns_observations=busy_and_slow
    )

    assert not any(
        item.client_ip == target.client_ip and item.family is DetectorFamily.DNS
        for item in alone.signals
    )
    signal = next(
        item
        for item in beside.signals
        if item.client_ip == target.client_ip and item.family is DetectorFamily.DNS
    )
    assert EvidenceGroup.DNS_SERVICE_TIME in {item.group for item in signal.evidence}
    deciding = [
        item.metric_strength
        for item in signal.evidence
        if item.group is not EvidenceGroup.DNS_SERVICE_TIME
    ]
    assert signal.family_strength == max(value for value in deciding if value is not None)


def test_new_resolver_requires_prior_dns_history_and_its_own_volume() -> None:
    """`primary-detectors-v7`: two ways a resolver was "new" without the client doing anything.

    A client with no prior DNS day has an empty prior set, so every resolver it used is new by
    construction. And a single packet to one unseen address scored a novelty near 99.9 with no
    volume behind it at all. Most of the addresses that showed it on 2026-08-30 had sent no query
    at all, which `primary-detectors-v8` now removes first (`CASE_STUDY.md`, superseded values).
    """
    policy = DetectorPolicy()
    known = _client("10.20.1.1")
    fresh = _client("10.20.1.2")
    contexts = {
        known.client_ip: _client_context(known),
        fresh.client_ip: _client_context(fresh),
    }
    prior_day = DAY.value - timedelta(days=1)
    history = (
        _dns(
            known.client_ip, "established", query_packets=200, complete_sessions=100, day=prior_day
        ),
    )
    stray = _dns(known.client_ip, "unseen", query_packets=2, complete_sessions=1)
    used = _dns(known.client_ip, "unseen", query_packets=200, complete_sessions=100)
    first_appearance = _dns(fresh.client_ip, "unseen", query_packets=200, complete_sessions=100)

    def names(observations: tuple[DnsDailyObservation, ...], client_ip: str) -> set[str]:
        metrics = calibrate_dns_metrics(DAY, observations, contexts, policy).metrics.get(
            client_ip, ()
        )
        return {metric.name for metric in metrics}

    assert "new_resolver" not in names((*history, stray, first_appearance), known.client_ip)
    assert "new_resolver" not in names((*history, used, first_appearance), fresh.client_ip)
    qualified = calibrate_dns_metrics(
        DAY, (*history, used, first_appearance), contexts, policy
    ).metrics[known.client_ip]
    novelty = next(metric for metric in qualified if metric.name == "new_resolver")
    assert novelty.observed_value == 1.0
    assert novelty.support_count == 100


def test_an_address_that_sent_no_query_is_not_a_dns_client() -> None:
    """`primary-detectors-v8`: one unsolicited response is not a DNS day.

    `dns_pairs` carries addresses that asked nothing and received one unsolicited response —
    804 of the 1,057 "clients" on 2026-08-30 (`CASE_STUDY` §9). They must not enter novelty's
    denominator, and a stray one in history must not become a prior DNS day.
    """
    policy = DetectorPolicy()
    client = _client("10.20.1.1")
    contexts = {client.client_ip: _client_context(client)}
    prior_day = DAY.value - timedelta(days=1)
    backscatter = replace(
        _dns(client.client_ip, "unasked", query_packets=0, complete_sessions=0, day=prior_day),
        unsolicited_sessions=1,
        response_packets=1,
        unsolicited_response_packets=1,
    )
    real = _dns(client.client_ip, "chosen", query_packets=200, complete_sessions=100)
    noise = tuple(
        replace(
            _dns(f"10.20.3.{index}", "unasked", query_packets=0, complete_sessions=0),
            unsolicited_sessions=1,
        )
        for index in range(1, 50)
    )

    calibration = calibrate_dns_metrics(DAY, (backscatter, real, *noise), contexts, policy)

    # The stray response gave no prior DNS day, so the real resolver is not "new".
    names = {metric.name for metric in calibration.metrics[client.client_ip]}
    assert "new_resolver" not in names
    populations = dns_population_by_day((backscatter, real, *noise), policy)
    assert populations[DAY.value].clients == frozenset({client.client_ip})
    assert prior_day not in populations


def test_a_resolver_the_client_never_asked_is_not_one_of_its_resolvers() -> None:
    policy = DetectorPolicy()
    client = _client("10.20.1.1")
    contexts = {client.client_ip: _client_context(client)}
    prior_day = DAY.value - timedelta(days=1)
    history = (
        _dns(
            client.client_ip, "established", query_packets=200, complete_sessions=100, day=prior_day
        ),
    )
    unasked = replace(
        _dns(client.client_ip, "unasked", query_packets=0, complete_sessions=0),
        unsolicited_sessions=40,
    )
    today = _dns(client.client_ip, "established", query_packets=200, complete_sessions=100)

    calibration = calibrate_dns_metrics(DAY, (*history, unasked, today), contexts, policy)

    assert "new_resolver" not in {m.name for m in calibration.metrics[client.client_ip]}


def test_a_dns_server_is_out_of_the_dns_family() -> None:
    """A campus resolver asks thousands of authoritative servers; each would read as new.

    On 7 addresses that shape carried 129 of 335 published DNS episodes, one on 43 of 45 days.
    """
    policy = DetectorPolicy(dns_server_min_resolvers=5)
    server = _client("10.20.1.1")
    stub = _client("10.20.1.2")
    contexts = (_client_context(server), _client_context(stub))
    prior_day = DAY.value - timedelta(days=1)
    observations = (
        *(
            _dns(server.client_ip, f"auth-{index}", query_packets=200, complete_sessions=100)
            for index in range(10)
        ),
        _dns(server.client_ip, "auth-old", query_packets=200, complete_sessions=100, day=prior_day),
        _dns(stub.client_ip, "shared", query_packets=100, complete_sessions=50),
    )

    calibration = calibrate_dns_metrics(
        DAY, observations, {item.client_ip: item for item in contexts}, policy
    )
    assert calibration.servers == frozenset({server.client_ip})
    assert server.client_ip not in calibration.metrics

    batch = DetectorEngine(policy).detect(
        DAY, (server, stub), (), _baselines(contexts), dns_observations=observations
    )
    assert not [item for item in batch.signals if item.client_ip == server.client_ip]
    assert any(
        item.client_ip == server.client_ip
        and item.family is DetectorFamily.DNS
        and ReasonCode.INSUFFICIENT_SUPPORT in item.reason_codes
        for item in batch.diagnostics
    )


def test_dns_ratio_metrics_require_authoritative_denominators() -> None:
    target = _client("10.20.1.1")
    peer = _client("10.20.1.2")
    contexts = {
        target.client_ip: _client_context(target),
        peer.client_ip: _client_context(peer),
    }
    target_dns = replace(
        _dns(target.client_ip, "shared", query_packets=99, complete_sessions=25),
        unanswered_sessions=24,
        unanswered_query_packets=50,
        response_packets=99,
        unsolicited_sessions=24,
        unsolicited_response_packets=50,
    )
    peer_dns = _dns(peer.client_ip, "shared", query_packets=99, complete_sessions=25)

    metrics = calibrate_dns_metrics(
        DAY, (target_dns, peer_dns), contexts, DetectorPolicy()
    ).metrics[target.client_ip]

    assert not {
        "unanswered_session_ratio",
        "unanswered_query_ratio",
        "unsolicited_session_ratio",
        "unsolicited_response_ratio",
    } & {metric.name for metric in metrics}


def test_persistence_requires_rare_relationship_and_multiple_comparable_days() -> None:
    client = _client("10.20.1.1")
    bitmap = ActivityBitmap.from_buckets((10, 11, 30))
    service = _service(client.client_ip, bitmap=bitmap)
    client_context = _client_context(client)
    relationship = _relationship_context(
        client.client_ip,
        prior_days=10,
        new_service=False,
        new_route=False,
        historical_prevalence=0.01,
        current_prevalence=0.01,
        # Below the moderate threshold, so the relationship family declines and this test is
        # about persistence alone. Persistence does not read the calibrated strengths: it still
        # conjoins the uncalibrated `100 * (1 - prevalence)` with a recurrence figure that is
        # also not a percentile. `primary-detectors-v5` deliberately left that pair alone.
        joint_strength=50.0,
    )
    history = tuple(
        RelationshipBitmapDay(
            DAY.value - timedelta(days=offset),
            client.client_ip,
            SERVICE,
            64500,
            ActivityBitmap.from_buckets((10, 12, 30)),
        )
        for offset in range(1, 5)
    )

    batch = DetectorEngine().detect(
        DAY,
        (client,),
        (service,),
        _baselines((client_context,), (relationship,)),
        persistence_history=history,
    )

    assert [signal.family for signal in batch.signals] == [DetectorFamily.PERSISTENCE]
    assert batch.signals[0].family_strength == 99.0
    assert {item.group for item in batch.signals[0].evidence} == {
        EvidenceGroup.RELATIONSHIP_RARITY,
        EvidenceGroup.RECURRENCE,
    }
    signal = batch.signals[0]
    episodes = build_ranking_inputs(DAY, batch.signals, (service,))
    assert len(episodes) == 1
    assert episodes[0].signal is signal
    assert episodes[0].episode_start == DAY.bounds.start
    assert episodes[0].episode_end == DAY.bounds.end
    assert episodes[0].temporal_precision is TemporalPrecision.DAY
    assert episodes[0].signal.service_id_hex == SERVICE.hex()
    assert episodes[0].signal.asn_id == 64500
    assert episodes[0].signal.evidence == signal.evidence
    assert episodes[0].signal.family_strength == signal.family_strength
    assert episodes[0].signal.reason_codes == signal.reason_codes
    assert episodes[0].signal.history_confidence == signal.history_confidence

    too_short = DetectorEngine().detect(
        DAY,
        (client,),
        (service,),
        _baselines((client_context,), (relationship,)),
        persistence_history=history[:3],
    )
    assert not any(item.family is DetectorFamily.PERSISTENCE for item in too_short.signals)


def test_cold_history_uses_peer_only_strength_and_preserves_confidence_reason() -> None:
    current = _client("10.20.1.1")
    context = _client_context(current, confidence=HistoryConfidence.COLD)
    metrics = tuple(
        replace(
            metric,
            peer_percentile=0.995 if metric.name == "up_bytes" else None,
            metric_strength=None,
        )
        for metric in context.metrics
    )
    context = replace(context, prior_active_days=0, metrics=metrics)

    batch = DetectorEngine().detect(DAY, (current,), (), _baselines((context,)))

    signal = next(item for item in batch.signals if item.family is DetectorFamily.TRANSFER)
    assert signal.family_strength == 99.5
    assert ReasonCode.COLD_HISTORY in signal.reason_codes


def test_detection_envelope_is_stable_under_current_row_reordering() -> None:
    first = _client("10.20.1.1")
    second = _client("10.20.1.2")
    first_context = _client_context(first, {"up_bytes": 99.0})
    second_context = _client_context(second, {"max_5m_unique_servers": 99.0})
    engine = DetectorEngine()

    ordered = engine.detect(
        DAY,
        (first, second),
        (),
        _baselines((first_context, second_context)),
    )
    reversed_rows = engine.detect(
        DAY,
        (second, first),
        (),
        _baselines((second_context, first_context)),
    )

    assert ordered.to_bytes() == reversed_rows.to_bytes()


def test_degraded_quality_blocks_publication_and_output_wording_is_bounded() -> None:
    current = _client("10.20.1.1")
    quality = SourceQualityContext(False, False, True, True, True, False, 0.0)
    context = _client_context(current, {"up_bytes": 100.0}, quality=quality)

    blocked = DetectorEngine().detect(DAY, (current,), (), _baselines((context,)))

    assert not blocked.signals
    assert all(item.status.value == "diagnostic" for item in blocked.diagnostics[:3])

    allowed = _client_context(current, {"up_bytes": 100.0})
    encoded = DetectorEngine().detect(DAY, (current,), (), _baselines((allowed,))).to_bytes()
    lowered = encoded.decode("ascii").lower()
    for forbidden in (
        "scanning",
        "exfiltration",
        "malware",
        "command and control",
        "compromise",
        "threat",
    ):
        assert forbidden not in lowered


def _dns(
    client_ip: str,
    resolver_id: str,
    *,
    query_packets: int,
    complete_sessions: int,
    day: date | None = None,
) -> DnsDailyObservation:
    return DnsDailyObservation(
        day=DAY.value if day is None else day,
        client_ip=client_ip,
        resolver_id=resolver_id,
        complete_sessions=complete_sessions,
        unanswered_sessions=0,
        unsolicited_sessions=0,
        query_packets=query_packets,
        response_packets=query_packets,
        unanswered_query_packets=0,
        unsolicited_response_packets=0,
        weighted_service_nanos=float(complete_sessions * 1_000),
        weighted_service_sessions=complete_sessions,
    )


def _large_flow_evidence(signal: DetectorSignal) -> DetectorEvidence:
    return next(item for item in signal.evidence if item.group is EvidenceGroup.LARGE_FLOW_CONTEXT)


def test_large_flow_context_is_reported_whether_or_not_it_corroborates() -> None:
    """The flow stays on the episode; its strength decides whether it promotes a tier.

    Dropping unqualified context would take a real transfer out of the stream to express a
    tiering decision. It is emitted either way, carrying how unusual it is for this host, and
    `RankingPolicy.corroboration_strength` is what reads that.
    """
    policy = DetectorPolicy()
    current = _client("10.20.1.1")
    service = _service("10.20.1.1", large_flow_count=2)
    qualified = _relationship_context("10.20.1.1", large_flow_strength=99.9)
    ordinary = _relationship_context(
        "10.20.1.1", large_flow_strength=policy.corroboration_strength - 0.1
    )

    for context, expected in ((qualified, 99.9), (ordinary, policy.corroboration_strength - 0.1)):
        batch = DetectorEngine().detect(
            DAY,
            (current,),
            (service,),
            _baselines((_client_context(current),), (context,)),
            families=frozenset({DetectorFamily.RELATIONSHIP}),
        )
        evidence = _large_flow_evidence(batch.signals[0])
        assert evidence.metric_strength == expected
        assert evidence.support_count == 2


def test_corroboration_instrumentation_records_the_decision_the_tier_ladder_takes() -> None:
    """§5 must see the qualification, and each axis separately for §2.

    `large_flow_qualified` is recorded against `DetectorPolicy.corroboration_strength`, the same
    threshold `RankingPolicy` acts on, so what the bundle reports is the decision the engine
    takes rather than a second implementation of it.
    """
    current = _client("10.20.1.1")
    service = _service("10.20.1.1", large_flow_count=2)
    context = _relationship_context("10.20.1.1", large_flow_strength=0.0)
    context = replace(
        context,
        large_flow_size_strength=99.9,
        large_flow_duration_strength=10.0,
        large_flow_strength=99.9,
    )
    log = ConditionLog()

    DetectorEngine().detect(
        DAY,
        (current,),
        (service,),
        _baselines((_client_context(current),), (context,)),
        families=frozenset({DetectorFamily.RELATIONSHIP}),
        recorder=log,
    )

    assert (
        log.observations[
            (
                "relationship_corroboration",
                Combinator.ALL,
                (
                    ("long_flow_context", True),
                    ("large_flow_present", True),
                    ("large_flow_qualified", True),
                ),
            )
        ]
        == 1
    )
    assert (
        log.observations[
            (
                "relationship_large_flow_axes",
                Combinator.ANY,
                (("size_unusual", True), ("duration_unusual", False)),
            )
        ]
        == 1
    )
