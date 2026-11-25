"""Runnable tooling for the five artifacts in `docs/EVALUATION.md`.

The evidence gate had no implementation: every reconstruction step needs a bundle, and none of the
five artifacts could be produced. This package is that gate, built on the same scoring path the
publisher uses so a measurement cannot drift from what ships.

Nothing here is imported by the publication path, nothing here writes to a database, and the
connection a harness is handed holds retained history for `day < D` and nothing else.

    from network_behaviour.evaluation import DayEvaluator, measure_redundancy

    evaluator = DayEvaluator(connection, day, staged, dns)
    report = measure_redundancy(str(day), evaluator.baseline().conditions)

`scripts/evaluate.py` is the command-line front end.
"""

from network_behaviour.evaluation.bundle import Bundle, Section, measured, missing
from network_behaviour.evaluation.harness import (
    DayEvaluator,
    RunOutcome,
    StagedTransform,
    compose,
    restrict_to_clients,
)
from network_behaviour.evaluation.injection import ImplantProfile, inject, sweep_profiles
from network_behaviour.evaluation.permutation import measure_permutation_null
from network_behaviour.evaluation.redundancy import measure_redundancy
from network_behaviour.evaluation.replay import seed_history_before
from network_behaviour.evaluation.sensitivity import measure_sensitivity
from network_behaviour.evaluation.stability import (
    build_report,
    perturb_parameters,
    resample_hosts,
)
from network_behaviour.evaluation.volume import measure_volume

__all__ = [
    "Bundle",
    "DayEvaluator",
    "ImplantProfile",
    "RunOutcome",
    "Section",
    "StagedTransform",
    "build_report",
    "compose",
    "inject",
    "measure_permutation_null",
    "measure_redundancy",
    "measure_sensitivity",
    "measure_volume",
    "measured",
    "missing",
    "perturb_parameters",
    "resample_hosts",
    "restrict_to_clients",
    "seed_history_before",
    "sweep_profiles",
]
