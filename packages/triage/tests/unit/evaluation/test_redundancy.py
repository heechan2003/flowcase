from __future__ import annotations

import pytest

from network_behaviour.evaluation.redundancy import measure_redundancy
from network_behaviour.instrumentation import Combinator, ConditionLog


def _log() -> ConditionLog:
    log = ConditionLog()
    # 100 units: 80 pass novelty, 80 pass rarity, and 78 pass both. Near-redundant on purpose —
    # this is the shape docs/EVALUATION.md §5 exists to expose.
    for _ in range(78):
        log.record("relationship_eligibility", Combinator.ALL, novelty=True, rarity=True)
    for _ in range(2):
        log.record("relationship_eligibility", Combinator.ALL, novelty=True, rarity=False)
    for _ in range(2):
        log.record("relationship_eligibility", Combinator.ALL, novelty=False, rarity=True)
    for _ in range(18):
        log.record("relationship_eligibility", Combinator.ALL, novelty=False, rarity=False)
    return log


def test_marginals_and_the_realised_joint_come_from_the_recorded_vectors() -> None:
    rule = measure_redundancy("2026-07-10", _log()).rules[0]

    assert rule.evaluated == 100
    assert [item.rate for item in rule.marginals] == [0.8, 0.8]
    assert rule.realised == pytest.approx(0.78)
    assert rule.independent == pytest.approx(0.64)


def test_a_near_redundant_conjunction_shows_a_lift_above_one() -> None:
    rule = measure_redundancy("2026-07-10", _log()).rules[0]

    assert rule.lift is not None and rule.lift > 1.2
    # The second condition removed 2 of the 80 the first admitted, and that is the number
    # that says the conjunction is buying almost nothing.
    assert rule.removed_by_conjunction == pytest.approx(0.025)


def test_units_excluded_before_the_rule_stay_out_of_every_rate() -> None:
    log = _log()
    for _ in range(500):
        log.exclude("relationship_eligibility", "insufficient_support")
    rule = measure_redundancy("2026-07-10", log).rules[0]

    assert rule.evaluated == 100
    assert rule.excluded == 500
    assert rule.realised == pytest.approx(0.78)
    assert rule.exclusion_reasons == (("insufficient_support", 500),)


def test_a_disjunction_is_compared_against_the_union_of_its_marginals() -> None:
    log = ConditionLog()
    for _ in range(50):
        log.record("dns_eligibility", Combinator.ANY, strong=True, two_moderate=False)
    for _ in range(50):
        log.record("dns_eligibility", Combinator.ANY, strong=False, two_moderate=False)
    rule = measure_redundancy("2026-07-10", log).rules[0]

    assert rule.realised == pytest.approx(0.5)
    assert rule.independent == pytest.approx(0.5)
    assert rule.removed_by_conjunction is None
