"""Pytest wiring only. The fixture itself lives in `day_fixture.py`, imported by name so the
module is not reachable as both a bare module and a dotted path.
"""

from day_fixture import fixture  # noqa: F401
