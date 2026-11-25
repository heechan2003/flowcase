"""Read-only DuckDB history selection and deterministic baseline calibration."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import date, timedelta
from typing import Any

import duckdb
import pyarrow as pa

from network_behaviour.aggregation import ClientDayRow, ClientServiceDayRow
from network_behaviour.baselines.models import (
    CLIENT_METRICS,
    BaselineBatch,
    BaselinePolicy,
    ClientBaselineContext,
    HistoryConfidence,
    MetricCalibration,
    RelationshipBaselineContext,
    ServiceConfidence,
    SourceQualityContext,
    SourceQualityInput,
)
from network_behaviour.baselines.statistics import (
    empirical_percentile_sorted,
    positive_residual,
    quantile,
    robust_summary,
)
from network_behaviour.population import CURRENT_SUPPORT_DEFINITION, SupportDefinition
from network_behaviour.time import UtcDay

_METRIC_SQL = ", ".join(CLIENT_METRICS)
# Sorts above every finite novelty statistic, so never-contacted destinations share the top
# of the novelty ordering rather than being spread across it by an arbitrary large number.
_NEVER_CONTACTED = float("inf")


@dataclass(frozen=True, slots=True)
class _ClientObservation:
    day: date
    client_ip: str
    metrics: tuple[float, ...]

    @property
    def total_bytes(self) -> float:
        return self.metric("up_bytes") + self.metric("down_bytes")

    @property
    def active_minutes(self) -> float:
        return self.metric("active_minutes")

    @property
    def unique_servers(self) -> float:
        return self.metric("unique_servers")

    def metric(self, name: str) -> float:
        return self.metrics[CLIENT_METRICS.index(name)]

    def admitted_by(self, support: SupportDefinition) -> bool:
        return support.admits_quantities(self.metric)


@dataclass(frozen=True, slots=True)
class _RelationshipKey:
    client_ip: str
    service_id: bytes
    asn_id: int


@dataclass(frozen=True, slots=True)
class _LargeFlowReference:
    """One host's own prior large flows, sorted, as the pool a new one is qualified against."""

    sizes: tuple[float, ...]
    durations: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class _RelationshipHistory:
    service_active_days: int
    service_last_seen: date | None
    route_active_days: int
    route_last_seen: date | None
    population_clients: int
    service_population_clients: int
    route_population_clients: int


class BaselineHistoryRepository:
    """Own the small set of explicitly leakage-bounded history queries."""

    def __init__(self, connection: duckdb.DuckDBPyConnection, policy: BaselinePolicy) -> None:
        self._connection = connection
        self._policy = policy

    def client_history(
        self, day: UtcDay, client_ips: tuple[str, ...]
    ) -> tuple[_ClientObservation, ...]:
        if not client_ips:
            return ()
        registration = "_baseline_current_clients"
        self._connection.register(registration, pa.table({"client_ip": sorted(set(client_ips))}))
        try:
            rows = self._historical_query(
                f"""
                SELECT h.day, h.client_ip, {_qualified_metrics("h")}
                FROM history.client_day h
                JOIN {registration} c ON c.client_ip = h.client_ip
                WHERE h.day >= ? AND h.day < ?
                ORDER BY h.client_ip, h.day
                """,
                [day.value - timedelta(days=self._policy.retained_lookback_days), day.value],
            )
        finally:
            self._connection.unregister(registration)
        return tuple(_observation_from_db(row) for row in rows)

    def calibration_history(self, day: UtcDay) -> tuple[_ClientObservation, ...]:
        rows = self._historical_query(
            f"""
            SELECT h.day, h.client_ip, {_qualified_metrics("h")}
            FROM history.client_day h
            WHERE h.day >= ? AND h.day < ?
            ORDER BY h.client_ip, h.day
            """,
            [day.value - timedelta(days=self._policy.calibration_lookback_days), day.value],
        )
        return tuple(_observation_from_db(row) for row in rows)

    def large_flow_reference(
        self, day: UtcDay, client_ips: tuple[str, ...]
    ) -> dict[str, _LargeFlowReference]:
        """Return each host's own prior large flows, at the grain a large flow is recorded on.

        One pool per host, over `large_flow_reference_days`, from the service-day rows that
        carried a large flow. A client-day maximum and a relationship maximum are both maxima
        over the same underlying flows, so both are placed against this one pool rather than
        against two pools that would put the same threshold on two different scales.
        """
        if not client_ips:
            return {}
        registration = "_baseline_large_flow_clients"
        self._connection.register(registration, pa.table({"client_ip": sorted(set(client_ips))}))
        try:
            rows = self._historical_query(
                f"""
                SELECT h.client_ip, h.max_large_flow_bytes, h.max_large_flow_duration_sec
                FROM history.client_service_day h
                JOIN {registration} c ON c.client_ip = h.client_ip
                WHERE h.day >= ? AND h.day < ? AND h.large_flow_count > 0
                ORDER BY h.client_ip
                """,
                [day.value - timedelta(days=self._policy.large_flow_reference_days), day.value],
            )
        finally:
            self._connection.unregister(registration)
        sizes: dict[str, list[float]] = defaultdict(list)
        durations: dict[str, list[float]] = defaultdict(list)
        for row in rows:
            client_ip = str(row[0])
            sizes[client_ip].append(float(row[1]))
            durations[client_ip].append(float(row[2]))
        return {
            client_ip: _LargeFlowReference(
                tuple(sorted(values)), tuple(sorted(durations[client_ip]))
            )
            for client_ip, values in sizes.items()
        }

    def relationship_history(
        self, day: UtcDay, keys: tuple[_RelationshipKey, ...]
    ) -> dict[_RelationshipKey, _RelationshipHistory]:
        if not keys:
            return {}
        unique = sorted(set(keys), key=lambda key: (key.client_ip, key.service_id, key.asn_id))
        registration = "_baseline_relationship_keys"
        self._connection.register(
            registration,
            pa.table(
                {
                    "client_ip": [key.client_ip for key in unique],
                    "service_id": pa.array([key.service_id for key in unique], type=pa.binary(16)),
                    "asn_id": pa.array([key.asn_id for key in unique], type=pa.uint64()),
                }
            ),
        )
        retained_start = day.value - timedelta(days=self._policy.retained_lookback_days)
        population_start = day.value - timedelta(days=self._policy.population_lookback_days)
        try:
            rows = self._historical_query(
                f"""
                WITH service_history AS (
                    SELECT k.client_ip, k.service_id,
                           count(DISTINCT h.day) AS active_days, max(h.day) AS last_seen
                    FROM {registration} k
                    LEFT JOIN history.client_service_day h
                      ON h.client_ip = k.client_ip AND h.service_id = k.service_id
                     AND h.day >= ? AND h.day < ?
                    GROUP BY k.client_ip, k.service_id
                ),
                route_history AS (
                    SELECT k.client_ip, k.service_id, k.asn_id,
                           count(DISTINCT h.day) AS active_days, max(h.day) AS last_seen
                    FROM {registration} k
                    LEFT JOIN history.client_service_day h
                      ON h.client_ip = k.client_ip AND h.service_id = k.service_id
                     AND h.asn_id = k.asn_id AND h.day >= ? AND h.day < ?
                    GROUP BY k.client_ip, k.service_id, k.asn_id
                ),
                -- The population a prevalence is over must be the population its numerator
                -- is drawn from. Every numerator below counts clients in client_service_day; a
                -- denominator counted from client_day includes addresses that appear in no
                -- service row at all and so can never be in any numerator. Measured 2026-08-24
                -- over the 90-day window: 12,237 against 6,929, a 1.77x inflation that made
                -- every service look rarer than it is.
                population AS (
                    SELECT count(DISTINCT h.client_ip) AS client_count
                    FROM history.client_service_day h
                    WHERE h.day >= ? AND h.day < ?
                ),
                relevant_services AS (
                    SELECT DISTINCT service_id FROM {registration}
                ),
                service_population AS (
                    SELECT k.service_id, count(DISTINCT h.client_ip) AS client_count
                    FROM relevant_services k
                    LEFT JOIN history.client_service_day h ON h.service_id = k.service_id
                     AND h.day >= ? AND h.day < ?
                    GROUP BY k.service_id
                ),
                relevant_routes AS (
                    SELECT DISTINCT service_id, asn_id FROM {registration}
                ),
                route_population AS (
                    SELECT k.service_id, k.asn_id, count(DISTINCT h.client_ip) AS client_count
                    FROM relevant_routes k
                    LEFT JOIN history.client_service_day h
                      ON h.service_id = k.service_id AND h.asn_id = k.asn_id
                     AND h.day >= ? AND h.day < ?
                    GROUP BY k.service_id, k.asn_id
                )
                SELECT k.client_ip, k.service_id, k.asn_id,
                       s.active_days, s.last_seen, r.active_days, r.last_seen,
                       p.client_count, sp.client_count, rp.client_count
                FROM {registration} k
                JOIN service_history s
                  ON s.client_ip = k.client_ip AND s.service_id = k.service_id
                JOIN route_history r
                  ON r.client_ip = k.client_ip AND r.service_id = k.service_id
                 AND r.asn_id = k.asn_id
                CROSS JOIN population p
                JOIN service_population sp ON sp.service_id = k.service_id
                JOIN route_population rp
                  ON rp.service_id = k.service_id AND rp.asn_id = k.asn_id
                ORDER BY k.client_ip, k.service_id, k.asn_id
                """,
                [
                    retained_start,
                    day.value,
                    retained_start,
                    day.value,
                    population_start,
                    day.value,
                    population_start,
                    day.value,
                    population_start,
                    day.value,
                ],
            )
        finally:
            self._connection.unregister(registration)
        result: dict[_RelationshipKey, _RelationshipHistory] = {}
        for row in rows:
            key = _RelationshipKey(str(row[0]), bytes(row[1]), int(row[2]))
            result[key] = _RelationshipHistory(
                int(row[3]),
                _optional_date(row[4]),
                int(row[5]),
                _optional_date(row[6]),
                int(row[7]),
                int(row[8]),
                int(row[9]),
            )
        return result

    def _historical_query(self, sql: str, parameters: list[object]) -> list[tuple[Any, ...]]:
        # This is intentionally a runtime fail-closed check in addition to leakage tests.
        if "day < ?" not in sql:
            raise RuntimeError("historical baseline query is missing the day < D boundary")
        return self._connection.execute(sql, parameters).fetchall()


class BaselineEngine:
    """Build immutable detector inputs without persisting derived baselines."""

    def __init__(
        self,
        connection: duckdb.DuckDBPyConnection,
        policy: BaselinePolicy | None = None,
    ) -> None:
        self._policy = policy or BaselinePolicy()
        self._repository = BaselineHistoryRepository(connection, self._policy)

    def build(
        self,
        day: UtcDay,
        current_clients: tuple[ClientDayRow, ...],
        current_services: tuple[ClientServiceDayRow, ...],
        source_quality: SourceQualityInput | None = None,
        support: SupportDefinition = CURRENT_SUPPORT_DEFINITION,
    ) -> BaselineBatch:
        """`support` decides which client-days may sit in a peer or calibration pool.

        It is the detector's own definition (`DetectorPolicy.support`), passed rather than held a
        second time, so the population a strength is ranked against is the population that may
        receive one. Every observed address still gets a context: DNS reads its activity band.
        """
        quality = source_quality or SourceQualityInput()
        current = tuple(_observation_from_current(row, day) for row in current_clients)
        _require_unique_clients(current)
        current_by_client = {row.client_ip: row for row in current}
        if any(row.day != day.value for row in current_services):
            raise ValueError("current service rows must belong to day D")
        if any(row.client_ip not in current_by_client for row in current_services):
            raise ValueError("current service row has no current client row")

        client_history = self._repository.client_history(day, tuple(current_by_client))
        # Only hosts that moved a large flow today can have one qualified, so only they need a
        # reference pool. Taken from both grains rather than from the client rows alone: the two
        # agree by construction in `aggregation`, and a staged day that disagreed would otherwise
        # silently score a service-level flow against no pool at all.
        large_flow_references = self._repository.large_flow_reference(
            day,
            tuple(
                sorted(
                    {row.client_ip for row in current_clients if row.large_flow_count}
                    | {row.client_ip for row in current_services if row.large_flow_count}
                )
            ),
        )
        history_by_client = _group_clients(client_history)
        calibration_pools = self._calibration_pools(
            self._repository.calibration_history(day), support
        )
        bands = {
            row.client_ip: self._activity_band(
                tuple(history_by_client.get(row.client_ip, ())[-self._policy.recent_active_days :])
                or (row,)
            )
            for row in current
        }
        peer_values = _peer_values(tuple(row for row in current if row.admitted_by(support)), bands)
        client_contexts = tuple(
            self._client_context(
                row,
                tuple(history_by_client.get(row.client_ip, ())),
                bands[row.client_ip],
                calibration_pools,
                peer_values,
                quality,
                large_flow_references.get(row.client_ip),
            )
            for row in sorted(current, key=lambda item: item.client_ip)
        )
        relationship_contexts = self._relationship_contexts(
            day, current_services, large_flow_references
        )
        return BaselineBatch(
            day.value.isoformat(), self._policy.version, client_contexts, relationship_contexts
        )

    def _calibration_pools(
        self, history: tuple[_ClientObservation, ...], support: SupportDefinition
    ) -> dict[tuple[str, str], tuple[float, ...]]:
        raw: dict[tuple[str, str], list[float]] = defaultdict(list)
        for rows in _group_clients(history).values():
            for index, current in enumerate(rows):
                if index < self._policy.calibration_min_prior_days:
                    continue
                if not current.admitted_by(support):
                    continue
                prior = tuple(rows[max(0, index - self._policy.recent_active_days) : index])
                band = self._activity_band(prior)
                for metric_index, name in enumerate(CLIENT_METRICS):
                    summary = robust_summary(tuple(row.metrics[metric_index] for row in prior))
                    residual = positive_residual(current.metrics[metric_index], summary)
                    if residual is not None:
                        raw[(band, name)].append(residual)
        return {key: tuple(sorted(values)) for key, values in raw.items()}

    def _client_context(
        self,
        current: _ClientObservation,
        history: tuple[_ClientObservation, ...],
        band: str,
        pools: dict[tuple[str, str], tuple[float, ...]],
        peer_values: dict[tuple[str, str], tuple[float, ...]],
        quality: SourceQualityInput,
        large_flow_reference: _LargeFlowReference | None,
    ) -> ClientBaselineContext:
        recent = history[-self._policy.recent_active_days :]
        long_rows = (
            history[-self._policy.long_max_active_days :]
            if len(history) >= self._policy.long_min_active_days
            else ()
        )
        weekday = tuple(row for row in history if row.day.weekday() == current.day.weekday())
        same_weekday_eligible = len(weekday) >= self._policy.same_weekday_min_occurrences
        calibrations: list[MetricCalibration] = []
        can_self_compare = len(history) >= self._policy.calibration_min_prior_days
        for index, name in enumerate(CLIENT_METRICS):
            recent_summary = robust_summary(tuple(row.metrics[index] for row in recent))
            long_summary = robust_summary(tuple(row.metrics[index] for row in long_rows))
            weekday_summary = (
                robust_summary(tuple(row.metrics[index] for row in weekday))
                if same_weekday_eligible
                else None
            )
            residual = (
                positive_residual(current.metrics[index], recent_summary)
                if can_self_compare
                else None
            )
            self_percentile = empirical_percentile_sorted(residual, pools.get((band, name), ()))
            peer_pool = peer_values.get((band, name), ())
            # A cohort below `min_cohort` cannot place any value in the moderate tail regardless
            # of how extreme it is (CASE_STUDY §4): refuse the percentile rather than emit one
            # no behaviour could ever clear.
            peer_percentile = (
                empirical_percentile_sorted(current.metrics[index], peer_pool)
                if len(peer_pool) >= self._policy.min_cohort
                else None
            )
            strength = (
                100.0 * min(self_percentile, peer_percentile)
                if self_percentile is not None and peer_percentile is not None
                else None
            )
            calibrations.append(
                MetricCalibration(
                    name,
                    current.metrics[index],
                    recent_summary,
                    long_summary,
                    weekday_summary,
                    residual,
                    self_percentile,
                    peer_percentile,
                    strength,
                )
            )
        total_bytes = current.total_bytes
        opaque = current.metric("opaque_bytes")
        source_context = SourceQualityContext(
            quality.principal_activity_complete,
            quality.reconciliation_passed,
            quality.rate_context_available,
            quality.dns_context_available,
            quality.long_flow_context_available,
            quality.classifier_context_degraded,
            opaque / total_bytes if total_bytes else 0.0,
        )
        size_strength, duration_strength, large_flow_strength = _large_flow_strengths(
            current.metric("large_flow_count"),
            current.metric("max_large_flow_bytes"),
            current.metric("max_large_flow_duration_sec"),
            large_flow_reference,
            self._policy,
        )
        return ClientBaselineContext(
            current.client_ip,
            len(history),
            HistoryConfidence.from_active_days(len(history)),
            band,
            same_weekday_eligible,
            tuple(calibrations),
            source_context,
            size_strength,
            duration_strength,
            large_flow_strength,
        )

    def _relationship_contexts(
        self,
        day: UtcDay,
        services: tuple[ClientServiceDayRow, ...],
        large_flow_references: dict[str, _LargeFlowReference],
    ) -> tuple[RelationshipBaselineContext, ...]:
        basis_by_key: dict[_RelationshipKey, set[str]] = defaultdict(set)
        service_clients: dict[bytes, set[str]] = defaultdict(set)
        route_clients: dict[tuple[bytes, int], set[str]] = defaultdict(set)
        # Aggregated exactly as the detector aggregates the same rows into one relationship:
        # counts add, maxima take the maximum. A strength calibrated over a different grouping
        # than the one it is read against is the drift this repository is recovering from.
        large_flow_count: dict[_RelationshipKey, int] = defaultdict(int)
        largest_flow: dict[_RelationshipKey, float] = defaultdict(float)
        longest_flow: dict[_RelationshipKey, float] = defaultdict(float)
        for row in services:
            key = _RelationshipKey(row.client_ip, row.service_id, row.asn_id)
            basis_by_key[key].add(row.service_basis)
            service_clients[row.service_id].add(row.client_ip)
            route_clients[(row.service_id, row.asn_id)].add(row.client_ip)
            large_flow_count[key] += row.large_flow_count
            largest_flow[key] = max(largest_flow[key], float(row.max_large_flow_bytes))
            longest_flow[key] = max(longest_flow[key], float(row.max_large_flow_duration_sec))
        keys = tuple(basis_by_key)
        histories = self._repository.relationship_history(day, keys)
        # Same correction for day D: the observed population is every address seen at all, which
        # on 2026-08-09 was 12,234 against the 3,523 seen contacting any service — a 3.47x
        # inflation of the denominator below. Under it a
        # service passed the moderate rarity threshold while used by up to 305 clients, where the
        # population that could have used it admits 88.
        current_population = len({row.client_ip for row in services})
        contexts: list[RelationshipBaselineContext] = []
        for key in sorted(keys, key=lambda item: (item.client_ip, item.service_id, item.asn_id)):
            history = histories[key]
            service_prevalence = _fraction(
                history.service_population_clients, history.population_clients
            )
            current_service_prevalence = _fraction(
                len(service_clients[key.service_id]), current_population
            )
            if key.asn_id:
                route_active_days: int | None = history.route_active_days
                route_since = _days_since(day.value, history.route_last_seen)
                new_route: bool | None = history.route_active_days == 0
                route_prevalence: float | None = _fraction(
                    history.route_population_clients, history.population_clients
                )
                current_route_prevalence: float | None = _fraction(
                    len(route_clients[(key.service_id, key.asn_id)]), current_population
                )
            else:
                route_active_days = None
                route_since = None
                new_route = None
                route_prevalence = None
                current_route_prevalence = None
            size_strength, duration_strength, large_flow_strength = _large_flow_strengths(
                large_flow_count[key],
                largest_flow[key],
                longest_flow[key],
                large_flow_references.get(key.client_ip),
                self._policy,
            )
            contexts.append(
                RelationshipBaselineContext(
                    key.client_ip,
                    key.service_id.hex(),
                    key.asn_id,
                    _service_confidence(basis_by_key[key]),
                    history.service_active_days,
                    _days_since(day.value, history.service_last_seen),
                    history.service_active_days == 0,
                    route_active_days,
                    route_since,
                    new_route,
                    service_prevalence,
                    route_prevalence,
                    current_service_prevalence,
                    current_route_prevalence,
                    large_flow_size_strength=size_strength,
                    large_flow_duration_strength=duration_strength,
                    large_flow_strength=large_flow_strength,
                )
            )
        return _calibrate_relationships(tuple(contexts))

    def _activity_band(self, history: tuple[_ClientObservation, ...]) -> str:
        """Bytes and destination count only. `active_minutes` was dropped in
        `baseline-calibration-v6`: measured over the same 7-day median this band is built from,
        98.98% of addresses sit at 1,440 minutes, the daily maximum (`CASE_STUDY` §3), so it
        never separated a cohort — it only fragmented the ones the surviving two axes already
        separate.
        """
        byte_median = quantile(tuple(row.total_bytes for row in history), 0.5)
        destination_median = quantile(tuple(row.unique_servers for row in history), 0.5)
        byte_band = _band_index(byte_median, self._policy.total_byte_edges)
        destination_band = _band_index(destination_median, self._policy.destination_edges)
        return f"bytes{byte_band}-destinations{destination_band}"


# ----------------------------------------------------------------------------- large flows


def _large_flow_strengths(
    large_flow_count: float,
    size: float,
    duration_sec: float,
    reference: _LargeFlowReference | None,
    policy: BaselinePolicy,
) -> tuple[float, float, float]:
    """Qualify one large flow against the host's own prior large flows.

    Two tail probabilities on the scale every other strength already uses — "more extreme than
    this share of the large flows this host has made" — combined by taking the more extreme axis,
    because size and duration are alternative ways for one transfer to be unusual and neither
    implies the other (measured 2026-08-31 over 2026-08-09: of 1,132 qualifying units, 758 qualify
    on size, 394 on duration, and only 335 on both).

    Zero where the day carried no large flow here, and zero where the host has too few prior large
    flows for a midpoint rank to place one in a 2.5% tail at all. Both are fail-closed: an
    unqualified large flow stays in the stream as context and stops promoting an episode a tier.
    """
    if large_flow_count <= 0 or reference is None:
        return 0.0, 0.0, 0.0
    if len(reference.sizes) < policy.large_flow_reference_min_units:
        return 0.0, 0.0, 0.0
    size_strength = 100.0 * (empirical_percentile_sorted(size, reference.sizes) or 0.0)
    duration_strength = 100.0 * (
        empirical_percentile_sorted(duration_sec, reference.durations) or 0.0
    )
    return size_strength, duration_strength, max(size_strength, duration_strength)


# --------------------------------------------------------------------------- relationship scale


def _novelty_statistic(context: RelationshipBaselineContext) -> float:
    """How unfamiliar this destination is to this host. Ordered, not calibrated.

    Only the ordering matters: the value is fed to an empirical percentile, so the scale it is
    expressed on is never compared to anything. A destination the host has never contacted ranks
    above every contacted one and they are equal to each other, because "never" has no degrees —
    on 2026-08-09 that was 9,381 of 125,862 units. Among contacted destinations, longer since the
    last contact is more novel and more prior active days is less novel, which is the ordering the
    retired four-rung ladder expressed in its `days_since` and `prior_service_active_days`
    branches. This states it once, continuously, instead of at four cut points.
    """
    if context.new_service and (context.new_route is None or context.new_route):
        return _NEVER_CONTACTED
    days_since = max(
        context.service_days_since_seen or 0,
        context.route_days_since_seen or 0,
    )
    prior_days = context.prior_service_active_days + (context.prior_route_active_days or 0)
    return days_since / (1.0 + prior_days)


def _rarity_statistic(context: RelationshipBaselineContext) -> float:
    """How few other clients use it. Negated so that larger is rarer, matching novelty.

    The quantity is the same one the uncalibrated rule used — the larger of the historical and
    current prevalence, each taken as the more specific of service and route. What changes is that
    it is turned into a tail probability rather than read as `100 * (1 - prevalence)`, which made
    it depend on the population size. `CASE_STUDY` §2 records the distinct-address count halving
    on 2026-08-11, in addresses with no service row; a percentile over the day's own units is
    invariant to any population size, whichever one moves.
    """
    historical = min(
        context.historical_service_prevalence,
        context.historical_route_prevalence
        if context.historical_route_prevalence is not None
        else context.historical_service_prevalence,
    )
    current = min(
        context.current_service_prevalence,
        context.current_route_prevalence
        if context.current_route_prevalence is not None
        else context.current_service_prevalence,
    )
    return -max(historical, current)


def _calibrate_relationships(
    contexts: tuple[RelationshipBaselineContext, ...],
) -> tuple[RelationshipBaselineContext, ...]:
    """Attach the calibrated novelty, rarity and joint strengths for one day.

    Every strength here is an empirical tail probability over this day's own relationship
    population: "more extreme than this share of today's relationships". That is the same scale a
    client metric strength is already on (`MetricCalibration.metric_strength`), so a threshold
    compared against it means one thing across families for the first time.

    The joint is the product of the two tails, re-calibrated. The product is a combining function
    and assumes nothing about independence — which matters, because the two axes are measurably
    correlated (`docs/EVALUATION.md` §5 reports a lift of 2.87). Calibrating the product over the
    population is what makes the result a tail probability again whatever the dependence is.

    Calibration is within-day and uses no history beyond what each context already carries, so
    the `day < D` boundary is untouched, and it is a pure function of the day's staged rows, so
    a rerun of an unchanged day reproduces it exactly.
    """
    if not contexts:
        return contexts
    novelty_pool = tuple(sorted(_novelty_statistic(item) for item in contexts))
    rarity_pool = tuple(sorted(_rarity_statistic(item) for item in contexts))
    tails = []
    for item in contexts:
        novelty = _tail_probability(_novelty_statistic(item), novelty_pool)
        rarity = _tail_probability(_rarity_statistic(item), rarity_pool)
        tails.append((novelty, rarity))
    joint_pool = tuple(sorted(-(novelty * rarity) for novelty, rarity in tails))
    return tuple(
        replace(
            item,
            novelty_strength=100.0 * (1.0 - novelty),
            rarity_strength=100.0 * (1.0 - rarity),
            joint_strength=100.0 * (1.0 - _tail_probability(-(novelty * rarity), joint_pool)),
        )
        for item, (novelty, rarity) in zip(contexts, tails, strict=True)
    )


def _tail_probability(value: float, pool: tuple[float, ...]) -> float:
    """Share of the pool at least this extreme, by the midpoint rank `statistics.py` uses."""
    return 1.0 - (empirical_percentile_sorted(value, pool) or 0.0)


def _qualified_metrics(alias: str) -> str:
    return ", ".join(f"{alias}.{name}" for name in CLIENT_METRICS)


def _observation_from_db(row: tuple[Any, ...]) -> _ClientObservation:
    return _ClientObservation(
        day=row[0],
        client_ip=str(row[1]),
        metrics=tuple(float(value) for value in row[2:]),
    )


def _observation_from_current(row: ClientDayRow, day: UtcDay) -> _ClientObservation:
    if row.day != day.value:
        raise ValueError("current client rows must belong to day D")
    values: list[float] = []
    for name in CLIENT_METRICS:
        value = getattr(row, name)
        if not isinstance(value, (int, float)):
            raise TypeError(f"client metric {name} is not numeric")
        values.append(float(value))
    return _ClientObservation(row.day, row.client_ip, tuple(values))


def _group_clients(
    rows: tuple[_ClientObservation, ...],
) -> dict[str, list[_ClientObservation]]:
    result: dict[str, list[_ClientObservation]] = defaultdict(list)
    for row in rows:
        result[row.client_ip].append(row)
    for values in result.values():
        values.sort(key=lambda row: row.day)
    return result


def _peer_values(
    rows: tuple[_ClientObservation, ...], bands: dict[str, str]
) -> dict[tuple[str, str], tuple[float, ...]]:
    result: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in rows:
        band = bands[row.client_ip]
        for index, name in enumerate(CLIENT_METRICS):
            result[(band, name)].append(row.metrics[index])
    return {key: tuple(sorted(values)) for key, values in result.items()}


def _band_index(value: float, edges: tuple[float, ...]) -> int:
    return sum(value >= edge for edge in edges)


def _require_unique_clients(rows: tuple[_ClientObservation, ...]) -> None:
    clients = [row.client_ip for row in rows]
    if len(clients) != len(set(clients)):
        raise ValueError("current client rows must be unique by client_ip")


def _optional_date(value: object) -> date | None:
    if value is None:
        return None
    if not isinstance(value, date):
        raise TypeError("DuckDB returned a non-date history value")
    return value


def _days_since(day: date, previous: date | None) -> int | None:
    return (day - previous).days if previous is not None else None


def _fraction(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _service_confidence(bases: set[str]) -> ServiceConfidence:
    values = {
        "domain": ServiceConfidence.HIGH,
        "application_asn": ServiceConfidence.MEDIUM,
        "asn": ServiceConfidence.MEDIUM,
        "server_ip": ServiceConfidence.LOW,
    }
    ranks = {
        ServiceConfidence.HIGH: 2,
        ServiceConfidence.MEDIUM: 1,
        ServiceConfidence.LOW: 0,
    }
    try:
        return min((values[basis] for basis in bases), key=ranks.__getitem__)
    except KeyError as exc:
        raise ValueError("unsupported service basis in current rows") from exc
