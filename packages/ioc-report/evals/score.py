"""Score a model's verdicts against the evaluation set. The bars were fixed before any paid run.

A case's verdict is the majority of the samples requested: a reply that failed counts as no vote,
so failures make a majority harder, never easier.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from evals.cases import EvalCase
from ioc_report.casefile import Observed
from ioc_report.model import check_reply, unattributed_labels
from ioc_report.shadow import SHADOW_PROMPT

# Fixed with the user before the first paid run (plan, "Pass criteria"). MIN_PAIRS went from 5 of
# 6 to 6 of 7 when the name-age pair (P7) was added, and to 7 of 8 when the shared-network pair
# (P8) was added, each before that set was run: still one miss.
MAX_SAFETY_MISSES = 1
MIN_CLEAR_SHARE = 0.8
MIN_PAIRS = 7
MIN_UNANIMOUS_SHARE = 0.9
MAX_FLAGGED_SHARE = 0.1
MIN_KNOWLEDGE = 3

SAFETY_EXTRA = ("P6b",)
"""The unknown-family trap counts toward safety too: clearing it would be inventing knowledge."""
KNOWLEDGE_IDS = ("X1", "X2", "X3", "P6b")


def grounding_problems(text: str, case_file: str, observed: Observed) -> list[str]:
    """`check_reply` without its threat-label attribution check, which was built for summaries.

    A verdict's reasoning must talk about the family's channel ("NanoCore's command-and-control
    channel carries no TLS"), as the prompt itself does, so that check flags correct reasoning.
    Invented numbers, host-state words and contradicted shapes still count. A number counts as
    grounded when it is in what the reader read: the case file or the policy, whose thresholds
    (the 32-day registration window) a verdict has to quote.
    """
    labels = set(unattributed_labels(text))
    read = f"{SHADOW_PROMPT}\n{case_file}"
    return [problem for problem in check_reply(text, read, observed) if problem not in labels]


@dataclass(frozen=True, slots=True)
class CaseScore:
    case: EvalCase
    votes: tuple[str, ...]
    errors: int
    majority: str | None
    flagged: int
    """Replies whose reasoning `grounding_problems` flags."""

    @property
    def correct(self) -> bool:
        return self.majority == self.case.expected

    @property
    def unanimous(self) -> bool:
        return not self.errors and len(set(self.votes)) == 1


@dataclass(frozen=True, slots=True)
class ModelScore:
    model: str
    cases: tuple[CaseScore, ...]
    cost: float
    seconds: float
    criteria: Mapping[str, tuple[str, bool]] = field(default_factory=dict)
    """Criterion → (measured value as text, passed)."""

    @property
    def outcome(self) -> str:
        passed = {name: ok for name, (_value, ok) in self.criteria.items()}
        if not passed["safety"] or not passed["pairs"]:
            return "not verdict-capable"
        if not all(passed[name] for name in ("usefulness", "stability", "grounding")):
            return "not verdict-capable (unreliable)"
        if not passed["knowledge"]:
            return "faithful to the policy, adds nothing beyond the rules"
        return "verdict-capable for the cases the rules leave for lack of knowledge"


def score(
    model: str, cases: Sequence[EvalCase], records: Sequence[Mapping[str, Any]], samples: int
) -> ModelScore:
    by_case: dict[str, list[Mapping[str, Any]]] = {}
    for item in records:
        by_case.setdefault(str(item["case_id"]), []).append(item)
    scored = []
    for case in cases:
        replies = [r for r in by_case.get(case.id, []) if int(r["sample"]) < samples]
        votes = tuple(str(r["verdict"]) for r in replies if r.get("verdict"))
        majority = next((v for v in set(votes) if votes.count(v) * 2 > samples), None)
        flagged = sum(
            1
            for r in replies
            if r.get("verdict")
            and grounding_problems(str(r.get("reasoning", "")), case.case_file, case.observed)
        )
        scored.append(CaseScore(case, votes, samples - len(votes), majority, flagged))
    cost = sum(float(r.get("cost") or 0) for r in records)
    seconds = sum(float(r.get("seconds") or 0) for r in records)
    return ModelScore(model, tuple(scored), cost, seconds, _criteria(scored))


def _criteria(scored: Sequence[CaseScore]) -> dict[str, tuple[str, bool]]:
    by_id = {s.case.id: s for s in scored}
    safety = [s for s in scored if s.case.group == "must_review" or s.case.id in SAFETY_EXTRA]
    misses = [s for s in safety if s.majority == "explained"]
    clear = [s for s in scored if s.case.group == "must_clear"]
    cleared = sum(1 for s in clear if s.correct)
    pairs = sorted({s.case.pair for s in scored if s.case.pair})
    pairs_right = sum(1 for pair in pairs if all(s.correct for s in scored if s.case.pair == pair))
    unanimous = sum(1 for s in scored if s.unanimous)
    replies = sum(len(s.votes) for s in scored)
    flagged = sum(s.flagged for s in scored)
    knowledge = sum(1 for key in KNOWLEDGE_IDS if key in by_id and by_id[key].correct)
    return {
        "safety": (
            f"{len(misses)} of {len(safety)} must-review cases cleared"
            + (f" ({', '.join(s.case.id for s in misses)})" if misses else ""),
            len(misses) <= MAX_SAFETY_MISSES,
        ),
        "usefulness": (
            f"{cleared} of {len(clear)} must-clear cases cleared",
            cleared >= MIN_CLEAR_SHARE * len(clear),
        ),
        "pairs": (
            f"{pairs_right} of {len(pairs)} twin pairs fully right",
            pairs_right >= MIN_PAIRS,
        ),
        "stability": (
            f"{unanimous} of {len(scored)} cases unanimous",
            unanimous >= MIN_UNANIMOUS_SHARE * len(scored),
        ),
        "grounding": (
            f"{flagged} of {replies} reasonings flagged",
            replies > 0 and flagged <= MAX_FLAGGED_SHARE * replies,
        ),
        "knowledge": (
            f"{knowledge} of {len(KNOWLEDGE_IDS)} knowledge cases right",
            knowledge >= MIN_KNOWLEDGE,
        ),
    }


def scorecard(results: Sequence[ModelScore], prompt_version: str) -> str:
    lines = [
        f"# Verdict evaluation (prompt {prompt_version})",
        "",
        "Grounding counts invented numbers, host-state words and contradicted shapes; it does not "
        "count unattributed threat labels, a check built for summaries.",
        "",
        "| Model | Outcome | " + " | ".join(results[0].criteria) + " | Cost | Model time |",
        "|---|---|" + "---|" * len(results[0].criteria) + "---|---|",
    ]
    for result in results:
        cells = [f"{'pass' if ok else 'FAIL'}: {value}" for value, ok in result.criteria.values()]
        lines.append(
            f"| {result.model} | {result.outcome} | "
            + " | ".join(cells)
            + f" | ${result.cost:.4f} | {result.seconds / 60:.1f} min |"
        )
    lines += [
        "",
        "## Per case (votes per sample; `-` is a failed reply)",
        "",
        "| Case | Group | Expected | Code | " + " | ".join(r.model for r in results) + " |",
        "|---|---|---|---|" + "---|" * len(results),
    ]
    for index, case_score in enumerate(results[0].cases):
        case = case_score.case
        cells = []
        for result in results:
            item = result.cases[index]
            mark = "" if item.correct else " ✗"
            votes = "/".join(v[0] for v in item.votes) + "-" * item.errors
            cells.append(f"{item.majority or 'split'} ({votes}){mark}")
        lines.append(
            f"| {case.id} | {case.group} | {case.expected} | {case.code} | "
            + " | ".join(cells)
            + " |"
        )
    return "\n".join(lines) + "\n"
