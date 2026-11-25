from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from network_behaviour.evaluation.bundle import (
    VERDICT_PLACEHOLDER,
    Bundle,
    Section,
    measured,
    missing,
)


def _bundle(*sections: Section) -> Bundle:
    return Bundle("R1 support definition", date(2026, 8, 24), "day 2026-08-21", sections)


def test_every_section_is_rendered_even_when_nothing_measured_it() -> None:
    rendered = _bundle(measured(1, "envelope")).render()

    for number in (1, 2, 3, 4, 5):
        assert f"## {number}." in rendered
    assert rendered.count("NOT MEASURED") == 4


def test_a_skipped_section_states_its_reason_rather_than_disappearing() -> None:
    rendered = _bundle(missing(2, "The permutation null needs a full population.")).render()

    assert "**NOT MEASURED.** The permutation null needs a full population." in rendered


def test_an_absent_section_is_called_a_defect_rather_than_passing_quietly() -> None:
    rendered = _bundle().render()

    assert "No reason was stated, which is itself a defect." in rendered


def test_the_verdict_is_left_for_a_person_to_write() -> None:
    assert VERDICT_PLACEHOLDER in _bundle().render()


def test_a_section_carries_a_measurement_or_a_reason_but_never_both() -> None:
    with pytest.raises(ValueError, match="either a measurement or a stated reason"):
        Section(1, body="x", not_measured="y")
    with pytest.raises(ValueError, match="either a measurement or a stated reason"):
        Section(1)


def test_a_bundle_carries_each_section_at_most_once() -> None:
    with pytest.raises(ValueError, match="at most once"):
        _bundle(measured(1, "a"), measured(1, "b"))


def test_the_file_is_dated_and_named_for_the_change(tmp_path: Path) -> None:
    path = _bundle(measured(1, "envelope")).write(tmp_path)

    assert path.name == "2026-08-24-r1-support-definition.md"
    assert "cannot establish" in path.read_text()
