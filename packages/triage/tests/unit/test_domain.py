import pytest

from network_behaviour.domain import (
    RETIRED_EVIDENCE_GROUP_CODES,
    EvidenceGroup,
    ReasonCode,
    code_mask,
)


def test_code_masks_are_deterministic_and_order_independent() -> None:
    left = code_mask(EvidenceGroup.FANOUT, EvidenceGroup.TRANSFER_BURST)
    right = code_mask(EvidenceGroup.TRANSFER_BURST, EvidenceGroup.FANOUT)

    assert left == right
    assert left == (1 << EvidenceGroup.FANOUT) | (1 << EvidenceGroup.TRANSFER_BURST)
    assert code_mask(ReasonCode.COLD_HISTORY) == 1 << ReasonCode.COLD_HISTORY


def test_controlled_code_values_are_unique_and_fit_storage_masks() -> None:
    for enum_type in (EvidenceGroup, ReasonCode):
        values = [int(member) for member in enum_type]
        assert len(values) == len(set(values))
        assert max(values) < 64


def test_evidence_group_codes_are_a_frozen_wire_format() -> None:
    """Codes are stored in published feeds and packed into evidence_group_mask.

    Renumbering a survivor would silently reinterpret every published day, so the mapping is
    pinned here rather than left to the enum's declaration order.
    """
    assert {member.name: int(member) for member in EvidenceGroup} == {
        "TRANSFER_MAGNITUDE": 0,
        "TRANSFER_BURST": 1,
        "RELATIONSHIP_NOVELTY": 2,
        "POPULATION_RARITY": 3,
        "FANOUT": 4,
        "RELATIONSHIP_RARITY": 5,
        "RECURRENCE": 6,
        "DNS_CHANGE": 7,
        "LARGE_FLOW_CONTEXT": 9,
        "DNS_RESOLVER": 13,
        "DNS_VOLUME": 14,
        "DNS_UNANSWERED": 15,
        "DNS_UNSOLICITED": 16,
        "DNS_SERVICE_TIME": 17,
    }


def test_retired_evidence_group_codes_are_never_reused() -> None:
    """8, 10, 11 and 12 were declared but never emitted, and were removed in domain-codes-v3.

    Reusing one would give an old published mask a new meaning.
    """
    assert {8, 10, 11, 12} == RETIRED_EVIDENCE_GROUP_CODES
    assert RETIRED_EVIDENCE_GROUP_CODES.isdisjoint({int(member) for member in EvidenceGroup})
    for code in sorted(RETIRED_EVIDENCE_GROUP_CODES):
        with pytest.raises(ValueError):
            EvidenceGroup(code)
