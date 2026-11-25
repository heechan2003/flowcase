"""Versioned evidence and reason codes shared by detection and storage."""

from __future__ import annotations

from enum import IntEnum

DOMAIN_CODE_VERSION = "domain-codes-v3"

# Codes 8, 10, 11 and 12 are retired and must never be reused.
#
# DIRECTION_CONCENTRATION (8), COMPOSITION_CONTEXT (10), SYNCHRONIZATION_CONTEXT (11) and
# SOURCE_QUALITY (12) were declared but never constructed by any detector, verified both by static
# analysis and against 47,692 published evidence rows in which none of the four ever appeared. They
# were removed in domain-codes-v3. Two of them were in the ranking engine's corroboration set, so
# they advertised routes to the top tier that did not exist.
#
# The surviving members keep their original values. These codes are a wire format: they are stored
# in feed.candidate_evidence, packed into evidence_group_mask by code_mask below, and decoded on
# read-back, so renumbering would silently reinterpret every published day. Gaps are correct here.
RETIRED_EVIDENCE_GROUP_CODES = frozenset({8, 10, 11, 12})


class EvidenceGroup(IntEnum):
    TRANSFER_MAGNITUDE = 0
    TRANSFER_BURST = 1
    RELATIONSHIP_NOVELTY = 2
    POPULATION_RARITY = 3
    FANOUT = 4
    RELATIONSHIP_RARITY = 5
    RECURRENCE = 6
    DNS_CHANGE = 7
    LARGE_FLOW_CONTEXT = 9
    DNS_RESOLVER = 13
    DNS_VOLUME = 14
    DNS_UNANSWERED = 15
    DNS_UNSOLICITED = 16
    DNS_SERVICE_TIME = 17


class ReasonCode(IntEnum):
    UNUSUAL_EXTERNAL_TRANSFER = 0
    RARE_EXTERNAL_RELATIONSHIP = 1
    EXTERNAL_FANOUT_CHANGE = 2
    DNS_BEHAVIOUR_CHANGE = 3
    PERSISTENT_RARE_RELATIONSHIP = 4
    COLD_HISTORY = 5
    LIMITED_HISTORY = 6
    MISSING_OPTIONAL_CONTEXT = 7
    BROAD_EVENT_SUPPRESSED = 8
    INSUFFICIENT_SUPPORT = 9
    DEGRADED_SOURCE_QUALITY = 10


def code_mask(*codes: IntEnum) -> int:
    mask = 0
    for code in codes:
        mask |= 1 << int(code)
    return mask
