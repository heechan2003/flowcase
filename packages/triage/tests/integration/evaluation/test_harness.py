"""The harness runs the real scoring path, and observing it cannot change it."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from day_fixture import Fixture

from network_behaviour.evaluation.harness import DayEvaluator, restrict_to_clients
from network_behaviour.operations.scoring import score_day
from network_behaviour.time import UtcDay


def test_recording_a_run_leaves_the_scored_output_byte_identical(fixture: Fixture) -> None:
    """The safety property behind leaving a recorder in the production path."""

    without = score_day(fixture.connection, fixture.day, fixture.staged)
    evaluator = DayEvaluator(fixture.connection, fixture.day, fixture.staged)
    with_recorder = evaluator.baseline()

    assert with_recorder.scored.detections.to_bytes() == without.detections.to_bytes()
    assert with_recorder.scored.ranking.to_bytes() == without.ranking.to_bytes()
    assert with_recorder.scored.baselines.to_bytes() == without.baselines.to_bytes()


def test_the_fixture_day_actually_produces_a_ranked_population(fixture: Fixture) -> None:
    """A guard on the fixture itself: an empty day would make every section vacuously pass."""

    outcome = DayEvaluator(fixture.connection, fixture.day, fixture.staged).baseline()

    assert outcome.episode_count > 0
    assert outcome.host_count > 0
    assert len({episode.evidence_tier.value for episode in outcome.episodes}) >= 2


def test_a_run_produces_a_condition_log_for_every_family_rule(fixture: Fixture) -> None:
    evaluator = DayEvaluator(fixture.connection, fixture.day, fixture.staged)
    rules = set(evaluator.baseline().conditions.rules())

    assert {
        "transfer_eligibility",
        "relationship_eligibility",
        "fanout_eligibility",
        "persistence_eligibility",
    } <= rules


def test_the_harness_never_writes_to_the_history_it_scores_against(fixture: Fixture) -> None:
    before = fixture.connection.execute(
        "SELECT count(*), count(*) FROM history.client_day"
    ).fetchone()
    evaluator = DayEvaluator(fixture.connection, fixture.day, fixture.staged)
    evaluator.baseline()
    evaluator.run("restricted", transform=restrict_to_clients(frozenset({"10.20.1.1"})))
    after = fixture.connection.execute(
        "SELECT count(*), count(*) FROM history.client_day"
    ).fetchone()

    assert before == after


def test_restricting_the_population_scores_only_the_kept_hosts(fixture: Fixture) -> None:
    evaluator = DayEvaluator(fixture.connection, fixture.day, fixture.staged)
    kept = frozenset({"10.20.1.1", "10.20.1.2", "10.20.1.3"})
    outcome = evaluator.run("kept", transform=restrict_to_clients(kept))

    assert outcome.client_rows == len(kept)
    assert {episode.client_ip for episode in outcome.episodes} <= kept


def test_a_transform_that_changes_the_day_is_refused(fixture: Fixture) -> None:
    evaluator = DayEvaluator(fixture.connection, fixture.day, fixture.staged)
    other = replace(fixture.staged, day=UtcDay(fixture.day.value - timedelta(days=1)))

    with pytest.raises(ValueError, match="UTC day"):
        evaluator.run("wrong-day", transform=lambda _staged: other)
