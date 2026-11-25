"""The decision. Code alone decides whether a case is `explained` or left for `review`.

Every observed contact with a flagged address must be explained by one of the E rules, and none of
the K rules may hold. Missing data never explains anything. "Explained" is a statement about the
match, never about the host: it says the contact the indicator matched has an ordinary reason.

E rules (explain one contact):
  E1  UDP, and the family's C2 is TCP-only                         botnet_cc, cited profile
  E2  an ECH outer name (only browsers send ECH), native family      botnet_cc, cited profile
  E3  TLS to another, non-operator-controlled site; C2 has no TLS     botnet_cc, cited profile
      (not when the name was registered under NEW_NAME_DAYS before the match, from RDAP)
  E4  an established site (§15) served from its usual network, on a shared address: one carrying
      many names (§14), or one on a network that shares its addresses by design (cited)
  E5  a tunnelling service's own client port: the host runs the tunnel client
  E6  the host sent nothing: inbound traffic it did not answer
K rules (keep the case for review):
  K1  the host's traffic named the flagged domain (except a tunnel client, E5)
  K2  a tunnelling service reached on a port other than its client port: a visitor
  K3  the published triage stream has an episode on the flagged destination itself
  K4  a scheduled low-volume contact (§10, §13) not explained as an established site or tunnel
  K5  payload delivery: a long flow with the flagged address not explained as an established site
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ioc_report.contact import Contact, Evidence, FlowContact, asn_number, bitmap_timing
from ioc_report.feed import TRANSPORTS, Case, logical_service
from ioc_report.history import address_services, indicator_service, sni_service
from ioc_report.knowledge import (
    SHARED_NETWORKS,
    UDP,
    FamilyProfile,
    ServiceProfile,
    clean,
    family_profile,
    name_facts,
    service_for,
    tenant_domain,
    under,
)
from ioc_report.registration import NameAge

# ThreatFox threat types whose family profile describes the channel the indicator was seen on. A
# payload_delivery listing is a download server: its family says nothing about the protocol that
# served the file, so no protocol rule applies to it.
C2_THREAT_TYPES = frozenset({"botnet_cc"})

# CASE_STUDY §14 (2026-10-08 and 2026-10-14): 10 registered domains in a day is the 99th
# percentile per server address on both days; an address at or above it is in the top 1%.
SHARED_MIN_DOMAINS = 10

# CASE_STUDY §15 (90 days to 2026-10-05): a name the campus already used routinely before the
# first match. 7 addresses and 9 days are the 90th percentiles per domain-basis service (7 is also
# above §13's fan-in ceiling of 5); 8.7% of names pass, carrying 98.4% of service-day rows.
ESTABLISHED_MIN_ADDRESSES = 7
ESTABLISHED_MIN_DAYS = 9

# CASE_STUDY §16: a name registered under 32 days before the match is a newly registered domain
# (Unit 42's definition, the window in which such names are most abused). An operator can register
# one for the same infrastructure, so TLS to it is not evidence of another site. Ages come from
# RDAP; an unknown age leaves E3 as it was.
NEW_NAME_DAYS = 32

EXPLAINED = "explained"
REVIEW = "review"


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    text: str


@dataclass(frozen=True, slots=True)
class Gap:
    """One reason a rule could not explain an item. `kind` lets the report group items by reason;
    the decision never reads it."""

    kind: str
    text: str


# Gap kinds. Protocol: why E1-E3 could not apply. Name: why the name could not count as another
# site. Site: why E4 could not apply. Flow: why a long flow could not be explained.
NOT_C2_LISTING = "not-c2-listing"
OTHER_LISTING = "other-listing"
INBOUND_LISTING = "inbound-listing"
NO_PROFILE = "no-profile"
RECORDS_DISAGREE = "records-disagree"
NO_REGISTERED_DOMAIN = "no-registered-domain"
OWN_DOMAIN = "own-domain"
OPERATOR_NAME = "operator-name"
OTHER_INDICATOR = "other-indicator"
PLATFORM_TENANT = "platform-tenant"
NEW_NAME = "new-name"
NO_SNI = "no-sni"
ECH_HIDDEN = "ech"
NO_HISTORY = "no-history"
NOT_ESTABLISHED = "not-established"
UNKNOWN_NETWORK = "unknown-network"
NETWORK_NOT_SEEN = "network-not-seen"
NOT_SHARED = "not-shared"
FLOW_OVERLAPS_UNEXPLAINED = "flow-overlaps-unexplained"
FLOW_UNATTRIBUTED = "flow-unattributed"
NO_RULE = "no-rule"


@dataclass(frozen=True, slots=True)
class Judged:
    item: Contact | FlowContact
    explained_by: tuple[Finding, ...]
    gaps: tuple[Gap, ...] = ()
    """Why no rule explained it. Empty when explained."""

    @property
    def gap(self) -> str:
        if self.explained_by:
            return ""
        return "; ".join(dict.fromkeys(gap.text for gap in self.gaps)) or "no rule applies"

    @property
    def explained(self) -> bool:
        return bool(self.explained_by)

    @property
    def rules(self) -> tuple[str, ...]:
        return tuple(sorted({finding.rule for finding in self.explained_by}))


@dataclass(frozen=True, slots=True)
class Decision:
    disposition: str
    contacts: tuple[Judged, ...]
    flows: tuple[Judged, ...]
    kept_by: tuple[Finding, ...]
    family: FamilyProfile | None
    notes: tuple[str, ...] = ()

    @property
    def unexplained(self) -> tuple[Judged, ...]:
        return tuple(item for item in (*self.contacts, *self.flows) if not item.explained)

    @property
    def explaining_rules(self) -> tuple[str, ...]:
        return tuple(
            sorted({rule for item in (*self.contacts, *self.flows) for rule in item.rules})
        )

    @property
    def keeping_rules(self) -> tuple[str, ...]:
        return tuple(sorted({finding.rule for finding in self.kept_by}))

    @property
    def rules(self) -> tuple[str, ...]:
        if self.disposition == EXPLAINED:
            return self.explaining_rules
        return self.keeping_rules or ("unexplained",)


def decide(evidence: Evidence, flagged_domains: frozenset[str]) -> Decision:
    case = evidence.case
    claim = case.consistent_claim
    family = family_profile(claim.malware) if claim is not None else None
    channel = claim is not None and claim.threat_type in C2_THREAT_TYPES
    notes = []
    if claim is None:
        notes.append(
            f"The case's records disagree on {case.listing.source} family or threat type, so no "
            "family rule applies."
        )
    contacts = tuple(
        _judge_contact(contact, evidence, family if channel else None, flagged_domains)
        for contact in evidence.contacts
    )
    flows = tuple(
        _judge_flow(index, flow, evidence, contacts, family if channel else None)
        for index, flow in enumerate(evidence.flows)
    )
    kept = _keeps(evidence, contacts, flows, flagged_domains)
    if kept:
        disposition = REVIEW
    elif all(item.explained for item in (*contacts, *flows)):
        disposition = EXPLAINED
    else:
        disposition = REVIEW
    return Decision(disposition, contacts, flows, tuple(kept), family, tuple(notes))


def _judge_contact(
    contact: Contact,
    evidence: Evidence,
    family: FamilyProfile | None,
    flagged_domains: frozenset[str],
) -> Judged:
    case = evidence.case
    found: list[Finding] = []
    gaps: list[Gap] = []
    transport = TRANSPORTS.get(contact.transport, str(contact.transport))
    if contact.up_bytes == 0:
        found.append(
            Finding(
                "E6", "the host sent 0 bytes in these minutes: inbound traffic it did not answer"
            )
        )
    service = _service(contact, case)
    if service is not None and service.is_client_port(contact.port, contact.transport):
        found.append(
            Finding(
                "E5", f"{service.name} client port {contact.port}/{transport}: {service.exposes}"
            )
        )
    if family is not None:
        if family.c2_udp is False and contact.transport == UDP:
            found.append(Finding("E1", f"UDP contact; {family.family}'s C2 channel is TCP only"))
        if family.client == "native" and contact.ech:
            found.append(
                Finding(
                    "E2",
                    f"ECH outer name {contact.sni}: only browsers send ECH, and {family.family} "
                    "is a native program",
                )
            )
        if family.c2_tls is False and contact.sni and not contact.ech:
            problem = _name_problem(contact.sni, case, flagged_domains, tenants_allowed=True)
            age = registration(contact.sni, evidence)
            days = age.days_before(case.first) if age is not None else None
            if problem is None and days is not None and days < NEW_NAME_DAYS:
                assert age is not None and age.registered is not None
                problem = Gap(
                    NEW_NAME,
                    f"{age.domain} was registered {age.registered:%Y-%m-%d}, {days:.0f} day(s) "
                    "before the first match; a name that new may be the operator's "
                    "(CASE_STUDY §16)",
                )
            if problem is None:
                registered = (
                    f"; {age.domain} registered {age.registered:%Y-%m-%d}"
                    if age is not None and age.registered is not None and days is not None
                    else ""
                )
                found.append(
                    Finding(
                        "E3",
                        f"TLS to {contact.sni}; {family.family}'s C2 channel carries no TLS"
                        + registered,
                    )
                )
            else:
                gaps.append(Gap(problem.kind, f"not a protocol mismatch: {problem.text}"))
    elif contact.transport == UDP or contact.sni:
        gaps.append(_no_profile(case))
    established, reason = _established(contact, evidence, flagged_domains)
    if established is not None:
        found.append(established)
    elif reason is not None:
        gaps.append(reason)
    if found:
        return Judged(contact, tuple(found))
    return Judged(contact, (), tuple(gaps) or (Gap(NO_RULE, "no rule applies"),))


def _judge_flow(
    index: int,
    flow: FlowContact,
    evidence: Evidence,
    contacts: Sequence[Judged],
    family: FamilyProfile | None,
) -> Judged:
    overlapped = [contacts[position] for position in evidence.flow_attribution.get(index, ())]
    if overlapped and all(item.explained for item in overlapped):
        rules = sorted({rule for item in overlapped for rule in item.rules})
        return Judged(
            flow,
            tuple(
                Finding(rule, f"overlaps {len(overlapped)} contact(s) explained by {rule}")
                for rule in rules
            ),
        )
    if overlapped:
        return Judged(
            flow,
            (),
            (Gap(FLOW_OVERLAPS_UNEXPLAINED, "it overlaps a contact that no rule explains"),),
        )
    found = []
    if family is not None and family.c2_udp is False and flow.transport == UDP:
        found.append(Finding("E1", f"UDP flow; {family.family}'s C2 channel is TCP only"))
    service = service_for(evidence.case.indicator) if evidence.case.is_domain else None
    if service is not None and service.is_client_port(flow.port, flow.transport):
        found.append(Finding("E5", f"{service.name} client port {flow.port}: {service.exposes}"))
    if found:
        return Judged(flow, tuple(found))
    return Judged(
        flow,
        (),
        (Gap(FLOW_UNATTRIBUTED, "no minute contact overlaps it, so it cannot be attributed"),),
    )


def _keeps(
    evidence: Evidence,
    contacts: Sequence[Judged],
    flows: Sequence[Judged],
    flagged_domains: frozenset[str],
) -> list[Finding]:
    case = evidence.case
    kept: list[Finding] = []
    for judged in contacts:
        contact = judged.item
        assert isinstance(contact, Contact)
        if any(case.names_flagged(name) for name in contact.names) and "E5" not in judged.rules:
            visit = (
                "a visit to a flagged lure or payload site cannot be cleared from flow records"
                if case.listing.threat_type == "payload_delivery"
                else "flow records cannot show such a contact was harmless"
            )
            kept.append(
                Finding("K1", f"the host named the flagged domain ({contact.label}); {visit}")
            )
        service = _service(contact, case)
        if service is not None and not service.is_client_port(contact.port, contact.transport):
            kept.append(
                Finding(
                    "K2",
                    f"{service.name} reached on {contact.port}/"
                    f"{TRANSPORTS.get(contact.transport, contact.transport)}, not its client "
                    "port: the host was a visitor to something published through it",
                )
            )

    flagged = {key.service_id_hex: key.label for key in address_services(case)}
    if (own := indicator_service(case)) is not None:
        flagged[own.service_id_hex] = own.label
    for episode in evidence.history.episodes:
        if episode.service_id_hex in flagged:
            kept.append(
                Finding(
                    "K3",
                    f"the published triage stream has a {episode.family} {episode.tier} episode "
                    f"on {flagged[episode.service_id_hex]} itself on {episode.day}",
                )
            )

    for day in evidence.pair_days:
        if not day.scheduled:
            continue
        involved = [
            judged
            for judged in contacts
            if isinstance(judged.item, Contact)
            and judged.item.server_ip == day.server_ip
            and day.day in judged.item.days
        ]
        if not all({"E4", "E5"} & set(judged.rules) for judged in involved):
            kept.append(
                Finding(
                    "K4",
                    f"scheduled low-volume contact with {day.server_ip} on {day.day}: "
                    f"{day.minutes} minutes, mean gap {day.mean_gap_minutes or 0:.1f} min, "
                    f"CV {day.cv or 0:.2f}, over {day.span_hours:.1f} h (CASE_STUDY §10)",
                )
            )
    by_service = _contacts_by_service(contacts, case)
    for retained in evidence.history.services:
        for row in retained.match_rows:
            timing = bitmap_timing(row)
            if not timing.beacon:
                continue
            involved = by_service.get(retained.service_id_hex, [])
            if involved and all({"E4", "E5"} & set(judged.rules) for judged in involved):
                continue
            kept.append(
                Finding(
                    "K4",
                    f"retained 5-minute activity with {retained.domain} on {timing.day} has the "
                    f"beacon shape: {timing.active_buckets} buckets, mean gap "
                    f"{timing.mean_gap_minutes or 0:.0f} min, CV {timing.cv or 0:.2f}, over "
                    f"{timing.span_hours:.1f} h, {timing.fanin} campus row(s) (CASE_STUDY §13)",
                )
            )

    if case.listing.threat_type == "payload_delivery":
        heavy = [
            index
            for index, judged in enumerate(flows)
            if not ("E4" in judged.rules and judged.explained)
        ]
        if heavy or evidence.other_flows:
            # Count the traffic once: a feed flow the live re-query returned again is counted
            # through its live copy (contact.Evidence.flow_duplicates). The decision is unchanged.
            counted = [
                flows[index].item
                for index in heavy
                if evidence.flow_duplicates.get(index) not in heavy
            ]
            counted += [
                flow
                for other, flow in enumerate(evidence.other_flows)
                if evidence.other_flow_duplicates.get(other) not in heavy
            ]
            count = sum(flow.flows for flow in counted if isinstance(flow, FlowContact))
            total = sum(flow.down_bytes for flow in counted if isinstance(flow, FlowContact))
            kept.append(
                Finding(
                    "K5",
                    f"{count} transfer(s) of 1 MB or more with the flagged address "
                    f"({total:,} bytes received) on a payload-delivery indicator, not explained "
                    "as an established site" + _untied_transfers(evidence, counted),
                )
            )
    return list(dict.fromkeys(kept))


def _untied_transfers(evidence: Evidence, counted: Sequence[Contact | FlowContact]) -> str:
    """Bytes on an address its network shares by design cannot be pinned on the flagged site without
    a TLS name. The transfer still keeps the case: this only says how far it can be attributed."""
    untied: dict[str, int] = {}
    for flow in counted:
        if not isinstance(flow, FlowContact):
            continue
        sharing = evidence.addresses.get(flow.server_ip)
        network = sharing.shared_by_design if sharing is not None else None
        if network is None or _tied_by_name(flow, evidence):
            continue
        untied[network.name] = untied.get(network.name, 0) + flow.flows
    return "".join(
        f"; {count} of them on {name}'s network, whose addresses many sites share, with no TLS "
        "name to tie them to the flagged site"
        for name, count in sorted(untied.items())
    )


def _tied_by_name(flow: FlowContact, evidence: Evidence) -> bool:
    """Whether a contact the flow overlaps carries a TLS name. An ECH outer name hides the site."""
    if flow not in evidence.flows:
        return False
    positions = evidence.flow_attribution.get(evidence.flows.index(flow), ())
    return any(
        evidence.contacts[position].sni and not evidence.contacts[position].ech
        for position in positions
    )


def _contacts_by_service(contacts: Sequence[Judged], case: Case) -> dict[str, list[Judged]]:
    found: dict[str, list[Judged]] = {}
    address = {key.label: key.service_id_hex for key in address_services(case)}
    for judged in contacts:
        contact = judged.item
        assert isinstance(contact, Contact)
        keys = set()
        service = logical_service(contact.server_ip, contact.root_domain, contact.sni, contact.dns)
        if service is not None:
            keys.add(service.service_id.hex())
        if (key := sni_service(contact.server_ip, contact.sni)) is not None:
            keys.add(key.service_id_hex)
        if not contact.names and contact.server_ip in address:
            keys.add(address[contact.server_ip])
        for key_hex in keys:
            found.setdefault(key_hex, []).append(judged)
    return found


def _established(
    contact: Contact, evidence: Evidence, flagged_domains: frozenset[str]
) -> tuple[Finding | None, Gap | None]:
    """E4: an established site, served from its usual network, on a shared address. On a list of
    addresses that connect in, the name is the host's own site and says nothing of the address."""
    if evidence.case.listing.inbound:
        return None, Gap(
            INBOUND_LISTING,
            "this list names addresses that connect in, so the TLS name is likely this host's own "
            "site and says nothing about the address",
        )
    if not contact.sni:
        return None, Gap(NO_SNI, "no SNI: the contact cannot be attributed to a site")
    if contact.ech:
        return None, Gap(ECH_HIDDEN, "ECH hides which site it was")
    case = evidence.case
    problem = _name_problem(contact.sni, case, flagged_domains, tenants_allowed=False)
    if problem is not None:
        return None, problem
    key = sni_service(contact.server_ip, contact.sni)
    service = evidence.history.service(key.service_id_hex) if key is not None else None
    prior = service.prior if service is not None else None
    if prior is None or prior.retained_days == 0:
        return None, Gap(
            NO_HISTORY,
            f"no retained history before the first match to show {contact.sni} is common",
        )
    name = key.label if key is not None else contact.sni
    if prior.addresses < ESTABLISHED_MIN_ADDRESSES or prior.days < ESTABLISHED_MIN_DAYS:
        return None, Gap(
            NOT_ESTABLISHED,
            f"{name} was used by {prior.addresses} campus address(es) on {prior.days} of "
            f"{prior.retained_days} retained days before the first match; an established site "
            f"needs {ESTABLISHED_MIN_ADDRESSES} on {ESTABLISHED_MIN_DAYS} (CASE_STUDY §15)",
        )
    asn = asn_number(contact.asn)
    if asn == 0:
        return None, Gap(UNKNOWN_NETWORK, f"the network serving {contact.server_ip} is unknown")
    if asn not in prior.asn_ids:
        return None, Gap(
            NETWORK_NOT_SEEN,
            f"campus history never saw {name} served from AS{asn}, the network of "
            f"{contact.server_ip}",
        )
    sharing = evidence.addresses.get(contact.server_ip)
    domains = sharing.most_domains if sharing is not None else 0
    network = SHARED_NETWORKS.get(asn)
    if domains >= SHARED_MIN_DOMAINS:
        shared = f"{contact.server_ip} carried {domains} registered domains"
    elif network is not None:
        shared = f"{contact.server_ip} is on {network.name}'s network, shared by design"
    else:
        return None, Gap(
            NOT_SHARED,
            f"{contact.server_ip} carried at most {domains} registered domain(s); shared hosting "
            f"needs {SHARED_MIN_DOMAINS} (CASE_STUDY §14)",
        )
    return (
        Finding(
            "E4",
            f"{name}: {prior.addresses} campus addresses on {prior.days} days before the first "
            f"match, served from AS{asn}; {shared}",
        ),
        None,
    )


def _name_problem(
    name: str, case: Case, flagged_domains: frozenset[str], *, tenants_allowed: bool
) -> Gap | None:
    facts = name_facts(name)
    if facts.registered is None:
        return Gap(NO_REGISTERED_DOMAIN, f"{name} has no registered domain")
    if case.is_domain and (
        under(name, case.indicator)
        or (facts.tenant is not None and facts.tenant == tenant_domain(case.indicator))
    ):
        return Gap(OWN_DOMAIN, f"{name} is under the indicator's own domain")
    if facts.operator_controlled:
        return Gap(OPERATOR_NAME, f"{name} is a {facts.category} name, chosen by whoever runs it")
    for other in flagged_domains:
        if other == clean(case.indicator):
            continue
        if under(name, other) or (
            facts.tenant is not None and facts.tenant == tenant_domain(other)
        ):
            return Gap(OTHER_INDICATOR, f"{name} is another indicator in this feed")
    if not tenants_allowed and (facts.platform_tenant or facts.category == "free hosting"):
        return Gap(
            PLATFORM_TENANT,
            f"{name} is one tenant of a shared platform, so the platform's popularity says "
            "nothing about it",
        )
    return None


def registration(name: str, evidence: Evidence) -> NameAge | None:
    """The RDAP registration record of the name's registered domain, when the run looked it up."""
    registered = name_facts(name).registered
    if evidence.registrations is None or registered is None:
        return None
    return evidence.registrations.get(registered)


def _service(contact: Contact, case: Case) -> ServiceProfile | None:
    for name in contact.names:
        if (service := service_for(name)) is not None:
            return service
    if case.is_domain:
        return service_for(case.indicator)
    return None


def _no_profile(case: Case) -> Gap:
    claim = case.consistent_claim
    if claim is None:
        return Gap(
            RECORDS_DISAGREE,
            f"the records disagree on the {case.listing.source} family, so protocol cannot "
            "explain it",
        )
    if claim.threat_type not in C2_THREAT_TYPES and claim.threat_type != "payload_delivery":
        return Gap(
            OTHER_LISTING,
            f"this {claim.threat_type} listing names no malware channel, so the family's protocol "
            "cannot explain it",
        )
    if claim.threat_type not in C2_THREAT_TYPES:
        return Gap(
            NOT_C2_LISTING,
            f"a {claim.threat_type} listing names a download server, so the family's protocol "
            "cannot explain it",
        )
    return Gap(
        NO_PROFILE, f"{claim.malware} has no cited C2 profile, so protocol cannot explain it"
    )
