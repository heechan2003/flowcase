"""Each bundle section, run end to end against a real scoring path."""

from __future__ import annotations

from datetime import date, timedelta
from random import Random

import pytest
from day_fixture import Fixture

from network_behaviour.detectors.dns import DnsDailyObservation
from network_behaviour.evaluation.harness import DayEvaluator
from network_behaviour.evaluation.injection import (
    ImplantProfile,
    InjectionError,
    inject,
    synthesise_activity,
)
from network_behaviour.evaluation.permutation import (
    build_strata,
    label_mapping,
    measure_permutation_null,
    permute_labels,
    relabel_dns,
    stratum_key,
    verify_marginals,
)
from network_behaviour.evaluation.redundancy import measure_redundancy
from network_behaviour.evaluation.sensitivity import measure_sensitivity
from network_behaviour.evaluation.stability import (
    build_report,
    perturb_parameters,
    resample_hosts,
)


@pytest.fixture
def evaluator(fixture: Fixture) -> DayEvaluator:
    return DayEvaluator(fixture.connection, fixture.day, fixture.staged)


# ------------------------------------------------------------------ §1 sensitivity


def test_an_implant_is_synthesised_at_the_source_grain(fixture: Fixture) -> None:
    """Occupied minute buckets with volumes, which is what the source records."""

    profile = ImplantProfile("hourly", period_minutes=60, occurrences=8, up_bytes_per_contact=5_000)
    observations, contacts = synthesise_activity(fixture.day, "10.20.1.1", profile, Random(1))

    assert len(contacts) == 8
    assert all(observation.minute_offsets for observation in observations)
    assert all(
        0 <= offset < 5 for observation in observations for offset in observation.minute_offsets
    )
    assert sum(observation.up_bytes for observation in observations) == profile.total_up_bytes


def test_jitter_moves_the_schedule_and_is_reproducible_from_the_seed(fixture: Fixture) -> None:
    steady = ImplantProfile("steady", period_minutes=60, occurrences=8, up_bytes_per_contact=1_000)
    jittered = ImplantProfile(
        "jittered",
        period_minutes=60,
        occurrences=8,
        up_bytes_per_contact=1_000,
        jitter_minutes=7,
    )

    _, regular = synthesise_activity(fixture.day, "10.20.1.1", steady, Random(5))
    _, first = synthesise_activity(fixture.day, "10.20.1.1", jittered, Random(5))
    _, again = synthesise_activity(fixture.day, "10.20.1.1", jittered, Random(5))

    assert regular != first
    assert first == again


def test_injection_adds_one_service_and_leaves_every_other_host_untouched(
    fixture: Fixture,
) -> None:
    profile = ImplantProfile("hourly", period_minutes=60, occurrences=8, up_bytes_per_contact=5_000)
    result = inject(fixture.staged, "10.20.1.1", profile, Random(3))

    assert len(result.staged.service_rows) == len(fixture.staged.service_rows) + 1
    assert len(result.staged.client_rows) == len(fixture.staged.client_rows)
    untouched = {
        row.client_ip: row for row in fixture.staged.client_rows if row.client_ip != "10.20.1.1"
    }
    for row in result.staged.client_rows:
        if row.client_ip != "10.20.1.1":
            assert row == untouched[row.client_ip]


def test_injection_is_additive_where_it_claims_to_be_exact(fixture: Fixture) -> None:
    profile = ImplantProfile("hourly", period_minutes=60, occurrences=8, up_bytes_per_contact=5_000)
    before = next(row for row in fixture.staged.client_rows if row.client_ip == "10.20.1.1")
    result = inject(fixture.staged, "10.20.1.1", profile, Random(3))
    after = next(row for row in result.staged.client_rows if row.client_ip == "10.20.1.1")

    assert after.up_bytes == before.up_bytes + profile.total_up_bytes
    assert after.unique_services == before.unique_services + 1
    assert after.p95_5m_up_bytes == before.p95_5m_up_bytes
    assert result.fidelity.host_was_present
    assert "p95_5m_up_bytes" in result.fidelity.unchanged


def test_injecting_a_destination_the_host_already_has_is_refused(fixture: Fixture) -> None:
    profile = ImplantProfile("hourly", period_minutes=60, occurrences=8, up_bytes_per_contact=1_000)
    once = inject(fixture.staged, "10.20.1.1", profile, Random(3))

    with pytest.raises(InjectionError, match="already a service"):
        inject(once.staged, "10.20.1.1", profile, Random(3))


def test_each_host_in_a_sweep_gets_its_own_synthetic_service(fixture: Fixture) -> None:
    profile = ImplantProfile("hourly", period_minutes=60, occurrences=8, up_bytes_per_contact=1_000)
    ids = {
        inject(fixture.staged, host, profile.for_host(index), Random(1)).service_id_hex
        for index, host in enumerate(("10.20.1.1", "10.20.1.2", "10.20.1.3"))
    }

    assert len(ids) == 3


def test_a_sweep_reports_one_cell_per_grid_point(evaluator: DayEvaluator) -> None:
    profiles = (
        ImplantProfile("a", period_minutes=60, occurrences=4, up_bytes_per_contact=1_000),
        ImplantProfile("b", period_minutes=60, occurrences=40, up_bytes_per_contact=10_000_000),
    )
    envelope = measure_sensitivity(evaluator, ("10.20.1.4", "10.20.1.5"), profiles, seed=11)

    assert len(envelope.cells) == 2
    assert all(cell.injections == 2 for cell in envelope.cells)
    assert all(0.0 <= cell.surfaced_rate <= 1.0 for cell in envelope.cells)
    assert envelope.baseline_episodes > 0
    assert "merge fidelity" in envelope.render()


def test_a_surfaced_implant_is_attributed_to_its_own_service(evaluator: DayEvaluator) -> None:
    """Surfacing means an episode on the implant's service, not that the host moved."""

    profile = ImplantProfile(
        "scheduled", period_minutes=60, occurrences=20, up_bytes_per_contact=5_000_000
    )
    envelope = measure_sensitivity(evaluator, ("10.20.1.7",), (profile,), seed=11)

    assert envelope.cells[0].surfaced_rate == 1.0


# ------------------------------------------------------------------ §2 permutation


def test_strata_block_on_weekday_and_occupancy(fixture: Fixture) -> None:
    key = stratum_key(fixture.staged, "10.20.1.1")

    assert key.startswith("fri:")
    assert len(build_strata(fixture.staged)) >= 2


def test_permutation_preserves_every_marginal(fixture: Fixture) -> None:
    permuted, _moved = permute_labels(fixture.staged, Random(7))

    verify_marginals(fixture.staged, permuted)
    assert sorted(row.client_ip for row in permuted.client_rows) == sorted(
        row.client_ip for row in fixture.staged.client_rows
    )


def test_permutation_moves_day_d_dns_with_the_host_and_leaves_its_history(
    fixture: Fixture,
) -> None:
    """DNS arrives as one tuple carrying both day D and its own history.

    Relabelling day D alone breaks the same pairing the staged permutation breaks: today's
    behaviour is judged against a history that is no longer its own. Without it the DNS
    conditions were scored on unpermuted input, so §2 could report nothing about them.
    """
    mapping = label_mapping(fixture.staged, Random(7))
    source, target = next((left, right) for left, right in mapping.items() if left != right)
    prior = fixture.day.value - timedelta(days=1)
    observations = (
        _dns_observation(fixture.day.value, source, "today"),
        _dns_observation(prior, source, "yesterday"),
    )

    relabelled = relabel_dns(observations, mapping, fixture.day)

    assert [row.client_ip for row in relabelled] == [target, source]
    assert [row.query_packets for row in relabelled] == [20, 20]


def _dns_observation(day: date, client_ip: str, resolver_id: str) -> DnsDailyObservation:
    return DnsDailyObservation(
        day=day,
        client_ip=client_ip,
        resolver_id=resolver_id,
        complete_sessions=10,
        unanswered_sessions=0,
        unsolicited_sessions=0,
        query_packets=20,
        response_packets=20,
        unanswered_query_packets=0,
        unsolicited_response_packets=0,
        weighted_service_nanos=10_000.0,
        weighted_service_sessions=10,
    )


def test_permutation_moves_labels_only_inside_a_stratum(fixture: Fixture) -> None:
    strata = {
        host: key for key, members in build_strata(fixture.staged).items() for host in members
    }
    permuted, _moved = permute_labels(fixture.staged, Random(7))
    original = {row.values()[2:]: row.client_ip for row in fixture.staged.client_rows}

    for row in permuted.client_rows:
        assert strata[original[row.values()[2:]]] == strata[row.client_ip]


def test_the_null_reports_conditions_not_a_ratio_of_totals(evaluator: DayEvaluator) -> None:
    """§2 yields a per-condition comparison. It must not resurrect the discredited bound.

    Dividing permuted episodes by observed ones produced 792% on real data, because a
    history-relative detector must fire more once the host-to-history pairing is broken. The
    render carries the totals, names no quotient of them, and names no rate of anything real.
    """

    null = measure_permutation_null(evaluator, seed=13, replicates=2)
    rendered = null.render()

    assert null.replicates == 2
    assert "per condition" in rendered
    assert "carries no host-specific information" in rendered
    assert "upper bound" not in rendered.casefold()
    assert "false positive" not in rendered.casefold()


# ------------------------------------------------------------------ §3 stability


def test_resampling_and_parameter_perturbation_are_comparable_to_the_baseline(
    evaluator: DayEvaluator,
) -> None:
    variants = (
        *resample_hosts(evaluator, seed=17, replicates=2, keep_fraction=0.75),
        *perturb_parameters(evaluator, deltas=(-0.5,)),
    )
    report = build_report(evaluator, variants, seed=17)

    assert len(report.comparisons) == len(variants)
    assert report.group("resample")
    assert report.group("parameter")
    assert "not ordered at all" in report.render()


def test_the_tied_episode_share_is_reported_with_every_correlation(
    evaluator: DayEvaluator,
) -> None:
    report = build_report(evaluator, resample_hosts(evaluator, seed=17, replicates=1), seed=17)

    assert 0.0 <= report.baseline_tied_episode_share <= 1.0
    assert all(0.0 <= item.tied_episode_share <= 1.0 for item in report.comparisons)


# ------------------------------------------------------------------ §5 redundancy


def test_redundancy_reports_marginals_and_the_realised_joint(evaluator: DayEvaluator) -> None:
    """§5 still measures every rule that conjoins conditions. Relationship is no longer one.

    `primary-detectors-v5` combines novelty and rarity into a calibrated joint tail *before*
    thresholding, so `relationship_eligibility` presents one condition and there is no
    conjunction on it left to be redundant. The section is unchanged and still measures the
    rules that do conjoin — persistence, corroboration, the tier gates. This pins that the rule
    reports itself honestly as single-condition rather than reporting a vacuous joint.
    """
    report = measure_redundancy(str(evaluator.day), evaluator.baseline().conditions)
    relationship = next(rule for rule in report.rules if rule.rule == "relationship_eligibility")

    assert [item.name for item in relationship.marginals] == ["joint_moderate"]
    assert 0.0 <= relationship.realised <= 1.0
    assert relationship.evaluated > 0

    # The two axes are still observed beside the decision, so §2 can still ask whether each
    # responds to the host label. Rarity is a property of the service and must not; a first
    # contact is defined against the host's own history and must.
    axes = next(rule for rule in report.rules if rule.rule == "relationship_axes")
    assert [item.name for item in axes.marginals] == ["first_contact", "rarity_moderate"]
    assert axes.evaluated == relationship.evaluated

    persistence = next(rule for rule in report.rules if rule.rule == "persistence_eligibility")
    assert len(persistence.marginals) == 2
    assert "product of marginals" in report.render()
    assert "not a proof of independence" in report.render()


def test_a_coarse_grid_reports_itself_as_a_pilot_not_an_envelope(
    evaluator: DayEvaluator,
) -> None:
    """A two-point axis describes a line. §1 asks for a region, so the report refuses the word."""

    profiles = (
        ImplantProfile("a", period_minutes=60, occurrences=4, up_bytes_per_contact=1_000),
        ImplantProfile("b", period_minutes=60, occurrences=40, up_bytes_per_contact=1_000),
    )
    envelope = measure_sensitivity(evaluator, ("10.20.1.4",), profiles, seed=11)

    assert not envelope.is_envelope
    assert envelope.axes == (("period", 1), ("occurrences", 2), ("amplitude", 1))
    assert "PILOT, NOT AN ENVELOPE" in envelope.render()
    assert envelope.seconds > 0
