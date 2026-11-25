"""Pure deterministic implementation of the five candidate-producing families."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from statistics import median

from network_behaviour.aggregation import ClientDayRow, ClientServiceDayRow
from network_behaviour.baselines.models import (
    BaselineBatch,
    ClientBaselineContext,
    HistoryConfidence,
    MetricCalibration,
    RelationshipBaselineContext,
)
from network_behaviour.detectors.dns import (
    DNS_SHARED_CONTEXT_METRICS,
    DnsDailyObservation,
    DnsMetric,
    calibrate_dns_metrics,
)
from network_behaviour.detectors.models import (
    FAMILY_ORDER,
    DecisionStatus,
    DetectionBatch,
    DetectorDiagnostic,
    DetectorEvidence,
    DetectorFamily,
    DetectorPolicy,
    DetectorSignal,
)
from network_behaviour.detectors.persistence import RelationshipBitmapDay
from network_behaviour.domain import EvidenceGroup, ReasonCode
from network_behaviour.instrumentation import Combinator, ConditionRecorder
from network_behaviour.normalization.bitmap import ActivityBitmap
from network_behaviour.time import UtcDay

_LABELS = {
    DetectorFamily.TRANSFER: "unusual external transfer",
    DetectorFamily.RELATIONSHIP: "rare or new external relationship",
    DetectorFamily.FANOUT: "external fanout change",
    DetectorFamily.DNS: "DNS behaviour change",
    # Not "persistent or regularly recurring". What the evidence establishes is that the
    # relationship was present on prior days with a comparable time shape — with a 30-day
    # lookback and a moderate threshold of 97.5, on every one of them. "Persistent" claims a
    # durability the 30 days do not reach, and "regularly recurring" claims an interval the
    # bitmap cannot establish, which `PRODUCT_CONTRACT.md` Tier 5 already forbids.
    DetectorFamily.PERSISTENCE: "repeated rare external relationship",
}

# Rules observed for docs/EVALUATION.md §5. A unit leaving a family before its rule is evaluated
# belongs in no marginal, so it is excluded by name rather than silently dropped from the
# denominator. Write-only: see network_behaviour.instrumentation.
_TRANSFER_RULES = (
    "transfer_eligibility",
    "transfer_corroboration",
    "transfer_large_flow_axes",
)
_RELATIONSHIP_RULES = (
    "relationship_eligibility",
    "relationship_axes",
    "relationship_corroboration",
    "relationship_large_flow_axes",
)
_FANOUT_RULES = ("fanout_eligibility",)
_DNS_RULES = ("dns_eligibility",)
_PERSISTENCE_RULES = ("persistence_eligibility",)


def _exclude(recorder: ConditionRecorder | None, rules: tuple[str, ...], reason: str) -> None:
    if recorder is None:
        return
    for rule in rules:
        recorder.exclude(rule, reason)


@dataclass(slots=True)
class _CurrentRelationship:
    client_ip: str
    service_id: bytes
    asn_id: int
    bitmap: ActivityBitmap
    flow_count: int = 0
    up_bytes: int = 0
    down_bytes: int = 0
    large_flow_count: int = 0
    large_flow_up_bytes: int = 0
    max_large_flow_bytes: int = 0
    max_large_flow_duration_sec: float = 0.0

    @property
    def active_buckets(self) -> int:
        return self.bitmap.count


class DetectorEngine:
    """Evaluate primary families without episode fusion, tiers, or queue ordering."""

    def __init__(self, policy: DetectorPolicy | None = None) -> None:
        self._policy = policy or DetectorPolicy()

    def detect(
        self,
        day: UtcDay,
        current_clients: tuple[ClientDayRow, ...],
        current_services: tuple[ClientServiceDayRow, ...],
        baselines: BaselineBatch,
        *,
        dns_observations: tuple[DnsDailyObservation, ...] = (),
        persistence_history: tuple[RelationshipBitmapDay, ...] = (),
        families: frozenset[DetectorFamily] | None = None,
        recorder: ConditionRecorder | None = None,
    ) -> DetectionBatch:
        selected_families = frozenset(DetectorFamily) if families is None else families
        if not selected_families:
            raise ValueError("detector family selection cannot be empty")
        if baselines.day != day.value.isoformat():
            raise ValueError("baseline batch must belong to day D")
        clients = {row.client_ip: row for row in current_clients}
        if len(clients) != len(current_clients):
            raise ValueError("current client rows must be unique")
        if any(row.day != day.value for row in current_clients + current_services):
            raise ValueError("current detector rows must belong to day D")
        contexts = {row.client_ip: row for row in baselines.clients}
        if set(clients) != set(contexts):
            raise ValueError("current clients and baseline contexts must match")
        relationships = _current_relationships(current_services)
        relationship_contexts = {
            (row.client_ip, bytes.fromhex(row.service_id_hex), row.asn_id): row
            for row in baselines.relationships
        }
        if set(relationships) != set(relationship_contexts):
            raise ValueError("current relationships and baseline contexts must match")

        signals: list[DetectorSignal] = []
        diagnostics: list[DetectorDiagnostic] = []
        if DetectorFamily.TRANSFER in selected_families:
            for client_ip in sorted(clients):
                context = contexts[client_ip]
                signal, diagnostic = self._transfer(clients[client_ip], context, recorder)
                _collect(signal, diagnostic, signals, diagnostics)
        if DetectorFamily.RELATIONSHIP in selected_families:
            for key in sorted(relationships, key=lambda item: (item[0], item[1], item[2])):
                signal, diagnostic = self._relationship(
                    relationships[key], relationship_contexts[key], contexts[key[0]], recorder
                )
                _collect(signal, diagnostic, signals, diagnostics)
        if DetectorFamily.FANOUT in selected_families:
            for client_ip in sorted(clients):
                signal, diagnostic = self._fanout(clients[client_ip], contexts[client_ip], recorder)
                _collect(signal, diagnostic, signals, diagnostics)

        if DetectorFamily.DNS in selected_families:
            calibration = (
                calibrate_dns_metrics(day, dns_observations, contexts, self._policy)
                if dns_observations
                else None
            )
            dns_metrics = calibration.metrics if calibration is not None else {}
            dns_servers = calibration.servers if calibration is not None else frozenset()
            for client_ip in sorted(clients):
                signal, diagnostic = self._dns(
                    contexts[client_ip],
                    dns_metrics.get(client_ip, ()),
                    recorder,
                    dns_server=client_ip in dns_servers,
                )
                _collect(signal, diagnostic, signals, diagnostics)

        if DetectorFamily.PERSISTENCE in selected_families:
            persistence_by_key: dict[tuple[str, bytes, int], list[RelationshipBitmapDay]] = (
                defaultdict(list)
            )
            for row in persistence_history:
                if row.day >= day.value:
                    raise ValueError("persistence history must enforce day < D")
                persistence_by_key[(row.client_ip, row.service_id, row.asn_id)].append(row)
            for key in sorted(relationships, key=lambda item: (item[0], item[1], item[2])):
                signal, diagnostic = self._persistence(
                    day,
                    relationships[key],
                    relationship_contexts[key],
                    contexts[key[0]],
                    tuple(sorted(persistence_by_key.get(key, ()), key=lambda item: item.day)),
                    recorder,
                )
                _collect(signal, diagnostic, signals, diagnostics)

        signals.sort(key=_signal_sort_key)
        diagnostics.sort(key=_diagnostic_sort_key)
        return DetectionBatch(
            day.value.isoformat(), self._policy.version, tuple(signals), tuple(diagnostics)
        )

    def _large_flow_qualified(self, strength: float) -> bool:
        """Whether this large flow is unusual enough for the host to corroborate an episode.

        The threshold is `DetectorPolicy.corroboration_strength`, the same value the ranking
        engine acts on, so what §5 records is the decision the tier ladder actually takes.
        """
        return strength >= self._policy.corroboration_strength

    def _transfer(
        self,
        current: ClientDayRow,
        context: ClientBaselineContext,
        recorder: ConditionRecorder | None = None,
    ) -> tuple[DetectorSignal | None, DetectorDiagnostic | None]:
        family = DetectorFamily.TRANSFER
        blocked = _principal_quality_diagnostic(context, family)
        if blocked is not None:
            _exclude(recorder, _TRANSFER_RULES, "principal_quality")
            return None, blocked
        if not _client_supported(current, self._policy):
            _exclude(recorder, _TRANSFER_RULES, "insufficient_support")
            return None, _diagnostic(context.client_ip, family, ReasonCode.INSUFFICIENT_SUPPORT)
        metrics = {metric.name: metric for metric in context.metrics}
        magnitude = _best_metric(metrics, ("up_bytes",), context.history_confidence)
        burst_names = ["p95_5m_up_bytes", "max_5m_up_bytes"]
        if context.source_quality.rate_context_available:
            burst_names.extend(("p95_bucket_up_rate_p95_bps", "max_bucket_up_rate_p95_bps"))
        burst = _best_metric(metrics, tuple(burst_names), context.history_confidence)
        primary = _strongest_alternative(
            (magnitude, EvidenceGroup.TRANSFER_MAGNITUDE),
            (burst, EvidenceGroup.TRANSFER_BURST),
        )
        if primary is None:
            _exclude(recorder, _TRANSFER_RULES, "no_calibrated_metric")
            return None, _diagnostic(context.client_ip, family, ReasonCode.INSUFFICIENT_SUPPORT)
        strength, metric, group = primary
        if recorder is not None:
            strong = strength >= self._policy.strong_strength
            recorder.record("transfer_eligibility", Combinator.ALL, strong_strength=strong)
            recorder.record(
                "transfer_corroboration",
                Combinator.ALL,
                strong_strength=strong,
                long_flow_context=context.source_quality.long_flow_context_available,
                large_flow_present=current.large_flow_count > 0,
                large_flow_qualified=self._large_flow_qualified(context.large_flow_strength),
            )
            # Recorded beside the decision, not as one: the decision takes either axis, which is
            # an ANY inside an ALL and so cannot be one recorded vector. Same shape as
            # `relationship_axes`, and for the same reason — §2 and §5 still need each axis.
            recorder.record(
                "transfer_large_flow_axes",
                Combinator.ANY,
                size_unusual=self._large_flow_qualified(context.large_flow_size_strength),
                duration_unusual=self._large_flow_qualified(context.large_flow_duration_strength),
            )
        evidence = [_metric_evidence(metric, group, strength)]
        if (
            strength >= self._policy.strong_strength
            and context.source_quality.long_flow_context_available
            and current.large_flow_count > 0
        ):
            evidence.append(
                DetectorEvidence(
                    EvidenceGroup.LARGE_FLOW_CONTEXT,
                    "filtered_large_flow_count",
                    float(current.large_flow_count),
                    metric_strength=context.large_flow_strength,
                    support_count=current.large_flow_count,
                )
            )
        reasons = _signal_reasons(
            context,
            ReasonCode.UNUSUAL_EXTERNAL_TRANSFER,
            missing_optional=(
                not context.source_quality.rate_context_available
                or not context.source_quality.long_flow_context_available
            ),
        )
        signal = DetectorSignal(
            context.client_ip,
            family,
            _LABELS[family],
            strength,
            context.history_confidence,
            tuple(evidence),
            reasons,
        )
        if strength < self._policy.strong_strength:
            audit_signal = (
                _as_near_threshold(signal)
                if strength >= self._policy.audit_floor_strength
                else None
            )
            return None, _diagnostic(
                context.client_ip,
                family,
                ReasonCode.INSUFFICIENT_SUPPORT,
                near_threshold_signal=audit_signal,
            )
        return (
            signal,
            None,
        )

    def _relationship(
        self,
        current: _CurrentRelationship,
        baseline: RelationshipBaselineContext,
        client: ClientBaselineContext,
        recorder: ConditionRecorder | None = None,
    ) -> tuple[DetectorSignal | None, DetectorDiagnostic | None]:
        family = DetectorFamily.RELATIONSHIP
        quality = _relationship_quality_diagnostic(client, current, family)
        if quality is not None:
            _exclude(recorder, _RELATIONSHIP_RULES, "relationship_quality")
            return None, quality
        novelty = baseline.novelty_strength
        rarity = baseline.rarity_strength
        strength = baseline.joint_strength
        if recorder is not None:
            # `relationship_eligibility` is now one condition, because the two axes are combined
            # into the joint tail before it is thresholded rather than thresholded separately.
            # `docs/EVALUATION.md` §5 therefore has no conjunction to measure on this rule; the
            # bundle states that rather than leaving the section to report a vacuous one.
            recorder.record(
                "relationship_eligibility",
                Combinator.ALL,
                joint_moderate=strength >= self._policy.moderate_strength,
            )
            # Recorded beside the decision, not as one. §2 classifies a condition by whether its
            # pass rate survives permuting the host labels, and both of these stay answerable:
            # rarity is a property of the service, so it must not move — which is how §2 checks
            # itself — while a first contact is defined against this host's own history, so it
            # must. Both are reachable predicates. Thresholding novelty at moderate_strength
            # would not be: 7.45% of units were first contacts on 2026-08-09, so that axis tops
            # out near 96.3 and the condition would be pinned at zero and read as structural.
            recorder.record(
                "relationship_axes",
                Combinator.ANY,
                first_contact=baseline.new_service,
                rarity_moderate=rarity >= self._policy.moderate_strength,
            )
        evidence = [
            DetectorEvidence(
                EvidenceGroup.RELATIONSHIP_NOVELTY,
                "client_relationship_novelty",
                float(baseline.prior_service_active_days),
                client_baseline_value=(
                    float(baseline.service_days_since_seen)
                    if baseline.service_days_since_seen is not None
                    else None
                ),
                metric_strength=novelty,
                support_count=current.active_buckets,
            ),
            DetectorEvidence(
                EvidenceGroup.POPULATION_RARITY,
                "service_or_route_prevalence",
                min(
                    baseline.current_service_prevalence,
                    baseline.current_route_prevalence
                    if baseline.current_route_prevalence is not None
                    else baseline.current_service_prevalence,
                ),
                client_baseline_value=min(
                    baseline.historical_service_prevalence,
                    baseline.historical_route_prevalence
                    if baseline.historical_route_prevalence is not None
                    else baseline.historical_service_prevalence,
                ),
                metric_strength=rarity,
            ),
        ]
        if strength < self._policy.moderate_strength:
            # Which axis is the weaker one names the reason. Comparing each marginal to the
            # moderate threshold would not: novelty is a tail probability over a population in
            # which 7.45% of units are first contacts (2026-08-09), so its ceiling is about 96.3
            # and no unit can clear 97.5 on it. That test would have retired
            # BROAD_EVENT_SUPPRESSED silently, which is the class of drift this repository is
            # recovering from.
            reason = (
                ReasonCode.BROAD_EVENT_SUPPRESSED
                if rarity <= novelty
                else ReasonCode.INSUFFICIENT_SUPPORT
            )
            status = (
                DecisionStatus.DIAGNOSTIC
                if reason is ReasonCode.BROAD_EVENT_SUPPRESSED
                else DecisionStatus.INELIGIBLE
            )
            audit_signal = (
                DetectorSignal(
                    current.client_ip,
                    family,
                    _LABELS[family],
                    strength,
                    client.history_confidence,
                    tuple(evidence),
                    _audit_reasons(client, ReasonCode.RARE_EXTERNAL_RELATIONSHIP),
                    current.service_id.hex(),
                    current.asn_id,
                    baseline.service_confidence,
                )
                if status is DecisionStatus.INELIGIBLE
                and strength >= self._policy.audit_floor_strength
                else None
            )
            if recorder is not None:
                recorder.exclude("relationship_corroboration", "not_eligible")
            return None, _relationship_diagnostic(
                current,
                family,
                status,
                reason,
                near_threshold_signal=audit_signal,
            )
        if recorder is not None:
            recorder.record(
                "relationship_corroboration",
                Combinator.ALL,
                long_flow_context=client.source_quality.long_flow_context_available,
                large_flow_present=current.large_flow_count > 0,
                large_flow_qualified=self._large_flow_qualified(baseline.large_flow_strength),
            )
            recorder.record(
                "relationship_large_flow_axes",
                Combinator.ANY,
                size_unusual=self._large_flow_qualified(baseline.large_flow_size_strength),
                duration_unusual=self._large_flow_qualified(baseline.large_flow_duration_strength),
            )
        if client.source_quality.long_flow_context_available and current.large_flow_count > 0:
            evidence.append(_relationship_large_flow(current, baseline.large_flow_strength))
        reasons = _signal_reasons(
            client,
            ReasonCode.RARE_EXTERNAL_RELATIONSHIP,
            missing_optional=not client.source_quality.long_flow_context_available,
        )
        return (
            DetectorSignal(
                current.client_ip,
                family,
                _LABELS[family],
                strength,
                client.history_confidence,
                tuple(evidence),
                reasons,
                current.service_id.hex(),
                current.asn_id,
                baseline.service_confidence,
            ),
            None,
        )

    def _fanout(
        self,
        current: ClientDayRow,
        context: ClientBaselineContext,
        recorder: ConditionRecorder | None = None,
    ) -> tuple[DetectorSignal | None, DetectorDiagnostic | None]:
        family = DetectorFamily.FANOUT
        blocked = _principal_quality_diagnostic(context, family)
        if blocked is not None:
            _exclude(recorder, _FANOUT_RULES, "principal_quality")
            return None, blocked
        if not _client_supported(current, self._policy):
            _exclude(recorder, _FANOUT_RULES, "insufficient_support")
            return None, _diagnostic(context.client_ip, family, ReasonCode.INSUFFICIENT_SUPPORT)
        metrics = {metric.name: metric for metric in context.metrics}
        best = _best_metric(
            metrics,
            (
                "p95_5m_unique_servers",
                "max_5m_unique_servers",
                "p95_5m_unique_services",
                "max_5m_unique_services",
                "p95_5m_unique_port_groups",
                "max_5m_unique_port_groups",
                "unique_servers",
                "unique_services",
                "unique_routes",
                "unique_asns",
                "unique_port_groups",
            ),
            context.history_confidence,
        )
        if best is None:
            _exclude(recorder, _FANOUT_RULES, "no_calibrated_metric")
            return None, _diagnostic(context.client_ip, family, ReasonCode.INSUFFICIENT_SUPPORT)
        strength, metric = best
        if context.source_quality.classifier_context_degraded and metric.name not in {
            "p95_5m_unique_servers",
            "max_5m_unique_servers",
            "unique_servers",
        }:
            _exclude(recorder, _FANOUT_RULES, "classifier_context_degraded")
            return None, _diagnostic(
                context.client_ip,
                family,
                ReasonCode.DEGRADED_SOURCE_QUALITY,
                status=DecisionStatus.DIAGNOSTIC,
            )
        if recorder is not None:
            recorder.record(
                "fanout_eligibility",
                Combinator.ALL,
                strong_strength=strength >= self._policy.strong_strength,
            )
        signal = DetectorSignal(
            context.client_ip,
            family,
            _LABELS[family],
            strength,
            context.history_confidence,
            (_metric_evidence(metric, EvidenceGroup.FANOUT, strength),),
            _signal_reasons(context, ReasonCode.EXTERNAL_FANOUT_CHANGE),
        )
        if strength < self._policy.strong_strength:
            audit_signal = (
                _as_near_threshold(signal)
                if strength >= self._policy.audit_floor_strength
                else None
            )
            return None, _diagnostic(
                context.client_ip,
                family,
                ReasonCode.INSUFFICIENT_SUPPORT,
                near_threshold_signal=audit_signal,
            )
        return (
            signal,
            None,
        )

    def _dns(
        self,
        context: ClientBaselineContext,
        metrics: tuple[DnsMetric, ...],
        recorder: ConditionRecorder | None = None,
        *,
        dns_server: bool = False,
    ) -> tuple[DetectorSignal | None, DetectorDiagnostic | None]:
        family = DetectorFamily.DNS
        blocked = _principal_quality_diagnostic(context, family)
        if blocked is not None:
            _exclude(recorder, _DNS_RULES, "principal_quality")
            return None, blocked
        if dns_server:
            # A campus DNS server asks thousands of authoritative servers a day, every new one of
            # which would read as a new resolver. Its DNS day is not a client's, so the family
            # has nothing to say about it (`DetectorPolicy.dns_server_min_resolvers`).
            _exclude(recorder, _DNS_RULES, "dns_server_role")
            return None, _diagnostic(context.client_ip, family, ReasonCode.INSUFFICIENT_SUPPORT)
        if not context.source_quality.dns_context_available or not metrics:
            _exclude(recorder, _DNS_RULES, "missing_dns_context")
            return None, _diagnostic(context.client_ip, family, ReasonCode.MISSING_OPTIONAL_CONTEXT)
        concepts: dict[str, DnsMetric] = {}
        for metric in metrics:
            if metric.strength is None:
                continue
            concept = _dns_concept(metric.name)
            previous = concepts.get(concept)
            if previous is None or (metric.strength, metric.name) > (
                previous.strength or -1,
                previous.name,
            ):
                concepts[concept] = metric
        supported = sorted(concepts.values(), key=lambda item: (-(item.strength or -1), item.name))
        # Resolver service time rides along as evidence and decides nothing. See
        # DNS_SHARED_CONTEXT_METRICS: it is a property of the resolver, so a resolver slowing
        # down would otherwise deviate every client behind it on the same day and arrive as a
        # burst of DNS candidates attributed to hosts.
        deciding = [metric for metric in supported if metric.name not in DNS_SHARED_CONTEXT_METRICS]
        shared = [metric for metric in supported if metric.name in DNS_SHARED_CONTEXT_METRICS]
        strong = any(
            metric.strength is not None and metric.strength >= self._policy.strong_strength
            for metric in deciding
        )
        moderate = [
            metric
            for metric in deciding
            if metric.strength is not None and metric.strength >= self._policy.moderate_strength
        ]
        if recorder is not None:
            recorder.record(
                "dns_eligibility",
                Combinator.ANY,
                strong_metric=strong,
                two_moderate_concepts=len(moderate) >= 2,
            )
            recorder.record(
                "dns_shared_context",
                Combinator.ANY,
                service_time_strong=any(
                    metric.strength is not None and metric.strength >= self._policy.strong_strength
                    for metric in shared
                ),
                service_time_moderate=any(
                    metric.strength is not None
                    and metric.strength >= self._policy.moderate_strength
                    for metric in shared
                ),
            )
        if not strong and len(moderate) < 2:
            audit_metrics = tuple(
                metric
                for metric in deciding
                if metric.strength is not None
                and metric.strength >= self._policy.audit_floor_strength
            )
            audit_signal = (
                DetectorSignal(
                    context.client_ip,
                    family,
                    _LABELS[family],
                    max(metric.strength or 0.0 for metric in audit_metrics),
                    context.history_confidence,
                    tuple(
                        DetectorEvidence(
                            _dns_evidence_group(metric.name),
                            metric.name,
                            metric.observed_value,
                            client_baseline_value=metric.baseline_value,
                            self_strength=metric.self_strength,
                            peer_strength=metric.peer_strength,
                            metric_strength=metric.strength,
                            support_count=metric.support_count,
                        )
                        for metric in audit_metrics
                    ),
                    _audit_reasons(context, ReasonCode.DNS_BEHAVIOUR_CHANGE),
                )
                if audit_metrics
                else None
            )
            return None, _diagnostic(
                context.client_ip,
                family,
                ReasonCode.INSUFFICIENT_SUPPORT,
                near_threshold_signal=audit_signal,
            )
        # Family strength comes from the deciding metrics; the shared-context ones are reported
        # beside them at the same evidence threshold and never set it.
        evidence_metrics = tuple(
            metric
            for metric in deciding
            if metric.strength is not None and metric.strength >= self._policy.moderate_strength
        )
        context_metrics = tuple(
            metric
            for metric in shared
            if metric.strength is not None and metric.strength >= self._policy.moderate_strength
        )
        evidence = tuple(
            DetectorEvidence(
                _dns_evidence_group(metric.name),
                metric.name,
                metric.observed_value,
                client_baseline_value=metric.baseline_value,
                self_strength=metric.self_strength,
                peer_strength=metric.peer_strength,
                metric_strength=metric.strength,
                support_count=metric.support_count,
            )
            for metric in (*evidence_metrics, *context_metrics)
        )
        return (
            DetectorSignal(
                context.client_ip,
                family,
                _LABELS[family],
                max(metric.strength or 0.0 for metric in evidence_metrics),
                context.history_confidence,
                evidence,
                _signal_reasons(context, ReasonCode.DNS_BEHAVIOUR_CHANGE),
            ),
            None,
        )

    def _persistence(
        self,
        day: UtcDay,
        current: _CurrentRelationship,
        baseline: RelationshipBaselineContext,
        client: ClientBaselineContext,
        history: tuple[RelationshipBitmapDay, ...],
        recorder: ConditionRecorder | None = None,
    ) -> tuple[DetectorSignal | None, DetectorDiagnostic | None]:
        family = DetectorFamily.PERSISTENCE
        quality = _relationship_quality_diagnostic(client, current, family)
        if quality is not None:
            _exclude(recorder, _PERSISTENCE_RULES, "relationship_quality")
            return None, quality
        rarity = _rarity_strength(baseline)
        if len(history) < self._policy.persistence_min_prior_days:
            _exclude(recorder, _PERSISTENCE_RULES, "insufficient_prior_days")
            return None, _relationship_diagnostic(
                current, family, DecisionStatus.INELIGIBLE, ReasonCode.INSUFFICIENT_SUPPORT
            )
        comparable = sum(_comparable_time_shape(current.bitmap, row.bitmap) for row in history)
        recurrence = 100.0 * comparable / len(history)
        active_counts = [row.bitmap.count for row in history]
        evidence = (
            DetectorEvidence(
                EvidenceGroup.RELATIONSHIP_RARITY,
                "relationship_population_prevalence",
                min(
                    baseline.current_service_prevalence,
                    baseline.current_route_prevalence
                    if baseline.current_route_prevalence is not None
                    else baseline.current_service_prevalence,
                ),
                metric_strength=rarity,
            ),
            DetectorEvidence(
                EvidenceGroup.RECURRENCE,
                "comparable_time_run_gap_recurrence",
                comparable / len(history),
                client_baseline_value=float(median(active_counts)),
                peer_reference_value=float(current.bitmap.run_count),
                metric_strength=recurrence,
                support_count=comparable,
            ),
        )
        if recorder is not None:
            recorder.record(
                "persistence_eligibility",
                Combinator.ALL,
                rarity_moderate=rarity >= self._policy.moderate_strength,
                recurrence_moderate=recurrence >= self._policy.moderate_strength,
            )
        if rarity < self._policy.moderate_strength or recurrence < self._policy.moderate_strength:
            strength = min(rarity, recurrence)
            audit_signal = (
                DetectorSignal(
                    current.client_ip,
                    family,
                    _LABELS[family],
                    strength,
                    client.history_confidence,
                    evidence,
                    _audit_reasons(client, ReasonCode.PERSISTENT_RARE_RELATIONSHIP),
                    current.service_id.hex(),
                    current.asn_id,
                    baseline.service_confidence,
                )
                if strength >= self._policy.audit_floor_strength
                else None
            )
            return None, _relationship_diagnostic(
                current,
                family,
                DecisionStatus.INELIGIBLE,
                ReasonCode.INSUFFICIENT_SUPPORT,
                near_threshold_signal=audit_signal,
            )
        return (
            DetectorSignal(
                current.client_ip,
                family,
                _LABELS[family],
                min(rarity, recurrence),
                client.history_confidence,
                evidence,
                _signal_reasons(client, ReasonCode.PERSISTENT_RARE_RELATIONSHIP),
                current.service_id.hex(),
                current.asn_id,
                baseline.service_confidence,
            ),
            None,
        )


def _current_relationships(
    rows: tuple[ClientServiceDayRow, ...],
) -> dict[tuple[str, bytes, int], _CurrentRelationship]:
    result: dict[tuple[str, bytes, int], _CurrentRelationship] = {}
    for row in rows:
        key = (row.client_ip, row.service_id, row.asn_id)
        current = result.get(key)
        bitmap = ActivityBitmap(row.active_5m_bitmap)
        if current is None:
            current = _CurrentRelationship(row.client_ip, row.service_id, row.asn_id, bitmap)
            result[key] = current
        else:
            current.bitmap = current.bitmap | bitmap
        current.flow_count += row.flow_count
        current.up_bytes += row.up_bytes
        current.down_bytes += row.down_bytes
        current.large_flow_count += row.large_flow_count
        current.large_flow_up_bytes += row.large_flow_up_bytes
        current.max_large_flow_bytes = max(current.max_large_flow_bytes, row.max_large_flow_bytes)
        current.max_large_flow_duration_sec = max(
            current.max_large_flow_duration_sec, row.max_large_flow_duration_sec
        )
    return result


def _best_metric(
    metrics: dict[str, MetricCalibration],
    names: tuple[str, ...],
    confidence: HistoryConfidence,
) -> tuple[float, MetricCalibration] | None:
    candidates: list[tuple[float, int, MetricCalibration]] = []
    for index, name in enumerate(names):
        metric = metrics.get(name)
        if metric is None:
            continue
        strength = _effective_strength(metric, confidence)
        if strength is not None:
            candidates.append((strength, -index, metric))
    if not candidates:
        return None
    strength, _order, metric = max(candidates, key=lambda item: (item[0], item[1]))
    return strength, metric


def _effective_strength(metric: MetricCalibration, confidence: HistoryConfidence) -> float | None:
    if metric.metric_strength is not None:
        return metric.metric_strength
    if confidence is HistoryConfidence.COLD and metric.peer_percentile is not None:
        return 100.0 * metric.peer_percentile
    return None


def _strongest_alternative(
    *alternatives: tuple[tuple[float, MetricCalibration] | None, EvidenceGroup],
) -> tuple[float, MetricCalibration, EvidenceGroup] | None:
    available = [
        (value[0], -index, value[1], group)
        for index, (value, group) in enumerate(alternatives)
        if value is not None
    ]
    if not available:
        return None
    strength, _order, metric, group = max(available, key=lambda item: (item[0], item[1]))
    return strength, metric, group


def _metric_evidence(
    metric: MetricCalibration, group: EvidenceGroup, strength: float
) -> DetectorEvidence:
    return DetectorEvidence(
        group,
        metric.name,
        metric.current_value,
        client_baseline_value=(metric.recent.median_raw if metric.recent is not None else None),
        self_strength=(
            100.0 * metric.self_percentile if metric.self_percentile is not None else None
        ),
        peer_strength=(
            100.0 * metric.peer_percentile if metric.peer_percentile is not None else None
        ),
        metric_strength=strength,
    )


def _rarity_strength(value: RelationshipBaselineContext) -> float:
    """Uncalibrated `100 * (1 - prevalence)`, kept for the persistence family alone.

    The relationship family stopped reading this in `primary-detectors-v5`; it reads the tail
    probabilities `BaselineEngine` calibrates. Persistence still conjoins this with a recurrence
    figure that is `100 * comparable / prior_days` — also not a percentile — so calibrating one
    side alone would move persistence eligibility without making its threshold mean anything.
    Measured on 2026-08-09: doing so cuts persistence from 128 episodes to 46. Calibrating both
    sides of persistence is the same change as this one and is not in this one's scope.
    """
    historical = min(
        value.historical_service_prevalence,
        value.historical_route_prevalence
        if value.historical_route_prevalence is not None
        else value.historical_service_prevalence,
    )
    current = min(
        value.current_service_prevalence,
        value.current_route_prevalence
        if value.current_route_prevalence is not None
        else value.current_service_prevalence,
    )
    return 100.0 * (1.0 - max(historical, current))


def _client_supported(row: ClientDayRow, policy: DetectorPolicy) -> bool:
    return policy.support.admits(row)


def _principal_quality_diagnostic(
    context: ClientBaselineContext, family: DetectorFamily
) -> DetectorDiagnostic | None:
    if (
        not context.source_quality.principal_activity_complete
        or not context.source_quality.reconciliation_passed
    ):
        return _diagnostic(
            context.client_ip,
            family,
            ReasonCode.DEGRADED_SOURCE_QUALITY,
            status=DecisionStatus.DIAGNOSTIC,
        )
    return None


def _relationship_quality_diagnostic(
    context: ClientBaselineContext,
    current: _CurrentRelationship,
    family: DetectorFamily,
) -> DetectorDiagnostic | None:
    principal = _principal_quality_diagnostic(context, family)
    if principal is not None:
        return _relationship_diagnostic(
            current,
            family,
            DecisionStatus.DIAGNOSTIC,
            ReasonCode.DEGRADED_SOURCE_QUALITY,
        )
    if context.source_quality.classifier_context_degraded:
        return _relationship_diagnostic(
            current,
            family,
            DecisionStatus.DIAGNOSTIC,
            ReasonCode.DEGRADED_SOURCE_QUALITY,
        )
    return None


def _signal_reasons(
    context: ClientBaselineContext,
    family_reason: ReasonCode,
    *,
    missing_optional: bool = False,
) -> tuple[ReasonCode, ...]:
    reasons = [family_reason]
    if context.history_confidence is HistoryConfidence.COLD:
        reasons.append(ReasonCode.COLD_HISTORY)
    elif context.history_confidence is HistoryConfidence.LIMITED:
        reasons.append(ReasonCode.LIMITED_HISTORY)
    if missing_optional:
        reasons.append(ReasonCode.MISSING_OPTIONAL_CONTEXT)
    return tuple(sorted(reasons, key=int))


def _diagnostic(
    client_ip: str,
    family: DetectorFamily,
    reason: ReasonCode,
    *,
    status: DecisionStatus = DecisionStatus.INELIGIBLE,
    near_threshold_signal: DetectorSignal | None = None,
) -> DetectorDiagnostic:
    return DetectorDiagnostic(
        client_ip,
        family,
        status,
        (reason,),
        near_threshold_signal=near_threshold_signal,
    )


def _relationship_diagnostic(
    current: _CurrentRelationship,
    family: DetectorFamily,
    status: DecisionStatus,
    reason: ReasonCode,
    *,
    near_threshold_signal: DetectorSignal | None = None,
) -> DetectorDiagnostic:
    return DetectorDiagnostic(
        current.client_ip,
        family,
        status,
        (reason,),
        current.service_id.hex(),
        current.asn_id,
        near_threshold_signal,
    )


def _as_near_threshold(signal: DetectorSignal) -> DetectorSignal:
    reasons = tuple(sorted({*signal.reason_codes, ReasonCode.INSUFFICIENT_SUPPORT}, key=int))
    return DetectorSignal(
        signal.client_ip,
        signal.family,
        signal.label,
        signal.family_strength,
        signal.history_confidence,
        signal.evidence,
        reasons,
        signal.service_id_hex,
        signal.asn_id,
        signal.service_confidence,
    )


def _audit_reasons(
    context: ClientBaselineContext, family_reason: ReasonCode
) -> tuple[ReasonCode, ...]:
    return tuple(
        sorted(
            {*_signal_reasons(context, family_reason), ReasonCode.INSUFFICIENT_SUPPORT},
            key=int,
        )
    )


def _relationship_large_flow(current: _CurrentRelationship, strength: float) -> DetectorEvidence:
    """Large-flow context, carrying how unusual the flow is for this host.

    Emitted whenever the day recorded one, qualified or not: an analyst reading the episode is
    entitled to know a large transfer happened. What the strength decides is whether the ranking
    engine treats it as independent corroboration and promotes the episode a full tier — see
    `RankingPolicy.corroboration_strength`.
    """
    return DetectorEvidence(
        EvidenceGroup.LARGE_FLOW_CONTEXT,
        "filtered_large_flow_count",
        float(current.large_flow_count),
        metric_strength=strength,
        support_count=current.large_flow_count,
    )


def _comparable_time_shape(current: ActivityBitmap, prior: ActivityBitmap) -> bool:
    prior_buckets = set(prior.active_buckets())
    timing_overlap = any(
        candidate in prior_buckets
        for bucket in current.active_buckets()
        for candidate in (bucket - 1, bucket, bucket + 1)
        if 0 <= candidate < 288
    )
    run_tolerance = max(1, current.run_count // 2)
    gap_tolerance = max(1, current.internal_gap_count // 4)
    return (
        timing_overlap
        and abs(current.run_count - prior.run_count) <= run_tolerance
        and abs(current.internal_gap_count - prior.internal_gap_count) <= gap_tolerance
    )


def _dns_concept(metric_name: str) -> str:
    if metric_name in {"session_volume", "query_volume"}:
        return "volume"
    if metric_name in {"unanswered_session_ratio", "unanswered_query_ratio"}:
        return "unanswered"
    if metric_name in {"unsolicited_session_ratio", "unsolicited_response_ratio"}:
        return "unsolicited"
    return metric_name


def _dns_evidence_group(metric_name: str) -> EvidenceGroup:
    concept = _dns_concept(metric_name)
    return {
        "new_resolver": EvidenceGroup.DNS_RESOLVER,
        "volume": EvidenceGroup.DNS_VOLUME,
        "unanswered": EvidenceGroup.DNS_UNANSWERED,
        "unsolicited": EvidenceGroup.DNS_UNSOLICITED,
        "mean_service_nanos": EvidenceGroup.DNS_SERVICE_TIME,
    }.get(concept, EvidenceGroup.DNS_CHANGE)


def _collect(
    signal: DetectorSignal | None,
    diagnostic: DetectorDiagnostic | None,
    signals: list[DetectorSignal],
    diagnostics: list[DetectorDiagnostic],
) -> None:
    if signal is not None:
        signals.append(signal)
    if diagnostic is not None:
        diagnostics.append(diagnostic)


def _signal_sort_key(signal: DetectorSignal) -> tuple[object, ...]:
    return (
        FAMILY_ORDER[signal.family],
        signal.client_ip,
        signal.service_id_hex or "",
        signal.asn_id if signal.asn_id is not None else -1,
    )


def _diagnostic_sort_key(diagnostic: DetectorDiagnostic) -> tuple[object, ...]:
    return (
        FAMILY_ORDER[diagnostic.family],
        diagnostic.client_ip,
        diagnostic.service_id_hex or "",
        diagnostic.asn_id if diagnostic.asn_id is not None else -1,
    )
