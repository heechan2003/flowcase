"""Whether a sweep may be called an envelope is arithmetic over its cells, not a measurement."""

from __future__ import annotations

from network_behaviour.evaluation.injection import InjectionFidelity
from network_behaviour.evaluation.sensitivity import EnvelopeCell, SensitivityEnvelope


def _cell(period: int, occurrences: int, amplitude: int) -> EnvelopeCell:
    return EnvelopeCell(period, occurrences, amplitude, 2, 4, 3)


def _envelope(*cells: EnvelopeCell) -> SensitivityEnvelope:
    return SensitivityEnvelope(
        "2026-07-10",
        11,
        ("198.51.100.1",),
        cells,
        InjectionFidelity(True, (), (), (), (), ()),
        300,
        100,
        12.5,
    )


def test_three_points_on_every_axis_is_an_envelope() -> None:
    cells = tuple(
        _cell(period, occurrences, amplitude)
        for period in (15, 60, 240)
        for occurrences in (4, 8, 12)
        for amplitude in (1_000, 10_000, 100_000)
    )
    envelope = _envelope(*cells)

    assert envelope.axes == (("period", 3), ("occurrences", 3), ("amplitude", 3))
    assert envelope.is_envelope
    assert "PILOT" not in envelope.render()


def test_one_axis_swept_twice_makes_it_a_pilot() -> None:
    cells = tuple(
        _cell(period, occurrences, 1_000) for period in (15, 60, 240) for occurrences in (4, 8, 12)
    )
    envelope = _envelope(*cells)

    assert envelope.axes == (("period", 3), ("occurrences", 3), ("amplitude", 1))
    assert not envelope.is_envelope
    assert "PILOT, NOT AN ENVELOPE" in envelope.render()


def test_the_report_states_the_grid_and_what_it_cost() -> None:
    rendered = _envelope(_cell(60, 8, 1_000), _cell(60, 12, 1_000)).render()

    assert "grid: period 1 x occurrences 2 x amplitude 1 = 2 scoring passes" in rendered
    assert "0.2 min" in rendered


def test_a_cell_reports_its_own_jitter_so_a_mixed_grid_stays_readable() -> None:
    assert "jitter +/-  2m" in _cell(60, 8, 1_000).render()
