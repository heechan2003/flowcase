"""The recorder must be able to observe a decision without being able to change one."""

from __future__ import annotations

from network_behaviour.instrumentation import Combinator, ConditionLog


def test_log_counts_condition_vectors_without_retaining_identifiers() -> None:
    log = ConditionLog()
    log.record("relationship_eligibility", Combinator.ALL, novelty=True, rarity=True)
    log.record("relationship_eligibility", Combinator.ALL, novelty=True, rarity=True)
    log.record("relationship_eligibility", Combinator.ALL, novelty=True, rarity=False)

    assert log.evaluated("relationship_eligibility") == 3
    assert len(log.observations) == 2
    # Nothing in the key is an address, digest or domain: the key is the condition vector.
    for rule, combinator, vector in log.observations:
        assert rule == "relationship_eligibility"
        assert combinator is Combinator.ALL
        assert {name for name, _ in vector} == {"novelty", "rarity"}


def test_condition_order_is_the_call_order() -> None:
    log = ConditionLog()
    log.record("rule", Combinator.ALL, first=True, second=False)
    (key,) = log.observations
    assert [name for name, _ in key[2]] == ["first", "second"]


def test_exclusions_are_counted_separately_from_evaluations() -> None:
    log = ConditionLog()
    log.record("rule", Combinator.ALL, condition=True)
    log.exclude("rule", "insufficient_support")
    log.exclude("rule", "insufficient_support")

    assert log.evaluated("rule") == 1
    assert log.excluded("rule") == 2
    assert log.rules() == ("rule",)
