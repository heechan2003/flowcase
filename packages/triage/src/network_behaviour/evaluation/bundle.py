"""Assemble the five artifacts into the dated Markdown file `docs/EVALUATION.md` calls a bundle.

Two rules from that document are enforced here rather than left to discipline:

- **A missing artifact is stated as missing, never omitted.** Every section is rendered, and one
  with nothing to report renders the reason it has nothing.
- **A bundle reporting a regression is still a valid bundle.** Nothing here can suppress a
  section, and the verdict is left unwritten for a person to fill in: a tool that wrote its own
  verdict would be grading its own homework.

Bundles are evidence, not authority. They never amend the contract, and once a change ships its
bundle is not edited — a superseding measurement is a new bundle that references the old one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path

SECTIONS = (
    (1, "Sensitivity envelope", "What behaviour can this system see at all?"),
    (2, "Blocked permutation null", "How much of the output responds to structure, not a host?"),
    (
        3,
        "Rank stability",
        "Would the same run tomorrow, on slightly different data, order the same?",
    ),
    (4, "Volume and cost projection", "What does an operator receive, and what does it cost?"),
    (5, "Conjunction redundancy", "Does adding a condition actually remove anything?"),
)

VERDICT_PLACEHOLDER = (
    "**NOT STATED.** State plainly whether this change improves the output, leaves it unchanged, "
    "or degrades it in exchange for something named. A bundle without a verdict is incomplete."
)

_CANNOT_MEASURE = """## What this bundle cannot establish

There is no ground truth, no asset inventory, no incident history, and no payload, TCP state,
process, user or DNS query-name context in this deployment.

- **Precision is unknown.** Dispositions drawn only from what the system surfaces are
  selection-biased, and a re-ranker fitted on them learns to reproduce the current queue.
- **Recall against real compromise is not measurable.** §1 measures sensitivity to synthesised
  behaviour, which is a statement about the instrument, not about any threat.
- **No bundle establishes that any host is compromised.**
"""


@dataclass(frozen=True, slots=True)
class Section:
    """One of the five. `body` is the measurement; `not_measured` is why there isn't one."""

    number: int
    body: str | None = None
    not_measured: str | None = None

    def __post_init__(self) -> None:
        if bool(self.body) == bool(self.not_measured):
            raise ValueError("a section carries either a measurement or a stated reason, not both")
        if not any(self.number == number for number, _, _ in SECTIONS):
            raise ValueError(f"section {self.number} is not one of the five")


@dataclass(frozen=True, slots=True)
class Bundle:
    change: str
    measured_on: date
    data_range: str
    sections: tuple[Section, ...]
    verdict: str = VERDICT_PLACEHOLDER
    supersedes: str | None = None

    def __post_init__(self) -> None:
        numbers = [section.number for section in self.sections]
        if len(numbers) != len(set(numbers)):
            raise ValueError("a bundle carries each section at most once")

    def render(self) -> str:
        by_number = {section.number: section for section in self.sections}
        lines = [
            f"# Evidence bundle — {self.change}",
            "",
            f"Measured {self.measured_on.isoformat()} over {self.data_range}.",
            "",
        ]
        if self.supersedes:
            lines += [f"Supersedes {self.supersedes}.", ""]
        lines += [
            "Produced by `scripts/evaluate.py`. Evidence, not authority: this file does not amend",
            "`docs/PRODUCT_CONTRACT.md`, and it is not edited after the change ships.",
            "",
            "## Verdict",
            "",
            self.verdict,
            "",
        ]
        for number, title, question in SECTIONS:
            lines += [f"## {number}. {title}", "", f"*{question}*", ""]
            section = by_number.get(number)
            if section is None:
                lines += ["**NOT MEASURED.** No reason was stated, which is itself a defect.", ""]
            elif section.not_measured:
                lines += [f"**NOT MEASURED.** {section.not_measured}", ""]
            else:
                lines += ["```", (section.body or "").rstrip(), "```", ""]
        lines += [_CANNOT_MEASURE]
        return "\n".join(lines).rstrip() + "\n"

    def write(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{self.measured_on.isoformat()}-{_slug(self.change)}.md"
        path.write_text(self.render())
        return path


def missing(number: int, reason: str) -> Section:
    return Section(number, not_measured=reason)


def measured(number: int, body: str) -> Section:
    return Section(number, body=body)


def _slug(value: str) -> str:
    kept = [character if character.isalnum() else "-" for character in value.casefold()]
    slug = "".join(kept)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "bundle"
