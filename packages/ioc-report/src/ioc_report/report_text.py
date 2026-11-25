"""Words both renderers use: the overview's four parts, and who wrote a piece of prose."""

from __future__ import annotations

from ioc_report.narrative import Narrative

PARTS = (
    ("threat", "Threat"),
    ("host", "Host"),
    ("what_happened", "What happened"),
    ("reading", "How to read it"),
)


def written_by(narrative: Narrative, model_label: str) -> str:
    if narrative.by_model:
        return f"written by {narrative.written_by}, checked by code; it never changes a decision"
    if narrative.problems:
        return "code's own text: the model's failed the checks"
    if model_label.startswith("no model"):
        return "code's own text (--no-model)"
    return "code's own text: " + (narrative.notes[0] if narrative.notes else "no model text")
