"""Bind `config/parameters.toml` to the values actually compiled into the code.

`CLAUDE.md` makes the registry the authority for every threshold, window, band edge and
tolerance. Nothing enforced that. `scripts/generate_parameters_doc.py` renders the registry
without reading `src/`, and `docs/generated/ordering.md` prints the compiled defaults beside a
note saying a mismatch "means the registry is not wired up" — with nothing that fails when one
appears. A registry that documents the code without being checked against it is the v1 contract's
Jensen-Shannon defect in a new file, so this is the check that makes the authority real.

Checked 2026-09-08 before this test existed: 0 mismatches. The exposure was latent, not live.

Two tests, because the second is what keeps the first from rotting. Binding the values catches an
edit to one side; requiring every live entry to be bound or explicitly exempted catches a new
parameter that arrives with no binding at all.
"""

from __future__ import annotations

import pathlib
import tomllib
from collections.abc import Callable

from network_behaviour.baselines.models import BaselinePolicy, HistoryConfidence
from network_behaviour.detectors.dns import DNS_SHARED_CONTEXT_METRICS
from network_behaviour.detectors.models import DetectorPolicy
from network_behaviour.drift import DriftPolicy
from network_behaviour.evaluation.shadow import BeaconPolicy
from network_behaviour.population import CURRENT_SUPPORT_DEFINITION
from network_behaviour.publication import ReconciliationPolicy
from network_behaviour.ranking.models import RankingPolicy

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY = tomllib.loads((ROOT / "config" / "parameters.toml").read_text())


def _history_confidence_edges() -> list[int]:
    """The day edges probed out of the function that applies them, not transcribed from it."""
    edges: list[int] = []
    previous = HistoryConfidence.from_active_days(0)
    for days in range(1, 400):
        current = HistoryConfidence.from_active_days(days)
        if current is not previous:
            edges.append(days - 1)
            previous = current
    return edges


def _long_flow_min_bytes() -> int:
    """The floor lives in SQL literals, so read it back from every file that carries one."""
    values = set()
    for path in sorted((ROOT / "sql" / "clickhouse").glob("*.sql")):
        for line in path.read_text().splitlines():
            if "up_bytes + down_bytes >=" in line:
                values.add(int(line.split(">=")[1].strip().rstrip(";")))
    if len(values) != 1:
        raise AssertionError(f"the long-flow byte floor is not one value across sql/: {values}")
    return values.pop()


_BINDINGS: dict[str, Callable[[], object]] = {
    "strength.moderate": lambda: DetectorPolicy().moderate_strength,
    "strength.strong": lambda: DetectorPolicy().strong_strength,
    "strength.audit_floor": lambda: DetectorPolicy().audit_floor_strength,
    "long_flow.min_bytes": _long_flow_min_bytes,
    "long_flow.corroboration_strength": lambda: DetectorPolicy().corroboration_strength,
    "long_flow.reference_days": lambda: BaselinePolicy().large_flow_reference_days,
    "long_flow.reference_min_units": lambda: BaselinePolicy().large_flow_reference_min_units,
    "dns.min_packets": lambda: DetectorPolicy().dns_min_packets,
    "dns.min_sessions": lambda: DetectorPolicy().dns_min_sessions,
    "dns.new_resolver_min_sessions": lambda: DetectorPolicy().dns_new_resolver_min_sessions,
    "dns.server_min_resolvers": lambda: DetectorPolicy().dns_server_min_resolvers,
    "dns.service_time_role": lambda: (
        "shared context" if "mean_service_nanos" in DNS_SHARED_CONTEXT_METRICS else "deciding"
    ),
    "baseline.recent_days": lambda: BaselinePolicy().recent_active_days,
    "baseline.long_days_min": lambda: BaselinePolicy().long_min_active_days,
    "baseline.long_days_max": lambda: BaselinePolicy().long_max_active_days,
    "calibration.min_prior_days": lambda: BaselinePolicy().calibration_min_prior_days,
    "calibration.max_prior_days": lambda: BaselinePolicy().calibration_lookback_days,
    "calibration.population_lookback_days": lambda: BaselinePolicy().population_lookback_days,
    "confidence.day_edges": _history_confidence_edges,
    "bands.byte_edges": lambda: list(BaselinePolicy().total_byte_edges),
    "bands.destination_edges": lambda: list(BaselinePolicy().destination_edges),
    "bands.min_cohort": lambda: BaselinePolicy().min_cohort,
    "fusion.default_gap_minutes": lambda: RankingPolicy().default_gap_minutes,
    "fusion.extended_gap_minutes": lambda: RankingPolicy().extended_gap_minutes,
    "reconciliation.relative_tolerance": lambda: ReconciliationPolicy().relative_tolerance,
    "duplicate.grain_tolerance": lambda: ReconciliationPolicy().duplicate_fraction_tolerance,
    "population.support_definition": lambda: CURRENT_SUPPORT_DEFINITION.describe(),
    "drift.population_step_fraction": lambda: DriftPolicy().population_step_fraction,
    "drift.composition_tvd": lambda: DriftPolicy().composition_tvd,
    "drift.dns_population_step_fraction": lambda: DriftPolicy().dns_population_step_fraction,
    "timing.max_cv": lambda: BeaconPolicy().max_cv,
    "shadow.beacon_min_active_buckets": lambda: BeaconPolicy().min_active_buckets,
    "shadow.beacon_max_active_buckets": lambda: BeaconPolicy().max_active_buckets,
    "shadow.beacon_max_cv": lambda: BeaconPolicy().max_cv,
    "shadow.beacon_min_mean_gap_buckets": lambda: BeaconPolicy().min_mean_gap_buckets,
    "shadow.beacon_min_span_hours": lambda: BeaconPolicy().min_span_hours,
    "shadow.beacon_max_bytes_per_active_bucket": (
        lambda: BeaconPolicy().max_bytes_per_active_bucket
    ),
    "shadow.beacon_max_campus_fanin": lambda: BeaconPolicy().max_campus_fanin,
}

_UNBOUND = {
    "timing.min_mean_gap_minutes": (
        "A property of the source, not a compiled threshold: CASE_STUDY §10 measures that "
        "activity_1m records occupied minute buckets rather than connection events. "
        "The shadow profile expresses the same constraint at bucket grain as "
        "shadow.beacon_min_mean_gap_buckets, which is bound above."
    ),
}


def _entries() -> dict[str, dict[str, object]]:
    found: dict[str, dict[str, object]] = {}
    for group, value in REGISTRY.items():
        if not isinstance(value, dict):
            continue
        if "value" in value:
            found[group] = value
            continue
        for name, entry in value.items():
            if isinstance(entry, dict) and "value" in entry:
                found[f"{group}.{name}"] = entry
    return found


def test_every_bound_registry_value_equals_the_compiled_default() -> None:
    """The registry states a number; `src/` applies one. They are the same number or this fails."""
    mismatches = [
        f"{name}: registry={entry['value']!r} compiled={_BINDINGS[name]()!r}"
        for name, entry in sorted(_entries().items())
        if name in _BINDINGS and entry["value"] != _BINDINGS[name]()
    ]

    assert not mismatches, "config/parameters.toml has drifted from the code:\n" + "\n".join(
        mismatches
    )


def test_every_live_registry_entry_is_bound_or_explicitly_exempt() -> None:
    """A new parameter cannot arrive without a binding or a stated reason it has none.

    Retired entries are exempt by status and must not be bound: their value records what was
    removed, so binding one would assert the removed behaviour is still compiled in.
    """
    unaccounted = sorted(
        name
        for name, entry in _entries().items()
        if entry.get("status") != "retired" and name not in _BINDINGS and name not in _UNBOUND
    )

    assert not unaccounted, (
        "these registry entries are neither bound to a compiled value nor listed in _UNBOUND "
        f"with a reason: {unaccounted}"
    )


def test_retired_entries_are_not_bound_to_compiled_values() -> None:
    retired_but_bound = sorted(
        name
        for name, entry in _entries().items()
        if entry.get("status") == "retired" and name in _BINDINGS
    )

    assert not retired_but_bound, (
        f"a retired parameter is bound as though still in force: {retired_but_bound}"
    )
