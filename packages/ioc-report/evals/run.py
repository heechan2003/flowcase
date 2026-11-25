"""Run one model over the evaluation set, under a hard budget, or score what has been run.

    python -m evals.run --model openrouter:anthropic/claude-haiku-5.5 --budget 0.20 --dry-run
    python -m evals.run --model openrouter:anthropic/claude-haiku-5.5 --budget 0.20
    python -m evals.run --model ollama:<local model>
    python -m evals.run --score

Every reply is appended to `output/eval/<evaluation version>/<model>.jsonl` the moment it
arrives, so an interrupted run resumes without paying twice. The evaluation version is the prompt
version plus a digest of the exact blind case files: replies are cached by case id, so a case file
that changed must not be answered from the cache of the old one. Before each paid call the worst
case (the whole prompt, every reply token, at listed prices) must fit what is left of `--budget`;
the account balance is read before and after. Only counts and synthetic case ids are printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from network_behaviour.config import ConfigurationError, load_default_environment

from evals.cases import EvalCase, build_cases
from evals.score import score, scorecard
from ioc_report.model import ModelClient, ModelError, OllamaClient, OllamaConfig
from ioc_report.openrouter import OpenRouterClient, OpenRouterConfig
from ioc_report.shadow import (
    PROMPT_VERSION,
    SHADOW_PROMPT,
    SHADOW_SCHEMA,
    SHADOW_SEEDS,
    SHADOW_TEMPERATURE,
    VERDICTS,
)

OUT = Path("output/eval")
EVAL_MAX_TOKENS = 3000


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    load_default_environment()
    cases = build_cases()
    version = evaluation_version(cases)
    folder = OUT / version
    if args.score:
        return _score(cases, folder, args.samples, version)
    if args.only:
        wanted = set(args.only.split(","))
        cases = [case for case in cases if case.id in wanted]
    try:
        client = make_client(args.model, os.environ)
        client.require_model()
    except (ConfigurationError, ModelError) as exc:
        print(f"evals: {exc}", file=sys.stderr)
        return 2
    paid = isinstance(client, OpenRouterClient)
    calls = len(cases) * args.samples
    chars = sum(len(SHADOW_PROMPT) + len(case.case_file) for case in cases) * args.samples
    worst = (
        sum(client.worst_case_cost(len(SHADOW_PROMPT) + len(c.case_file)) for c in cases)
        * args.samples
        if isinstance(client, OpenRouterClient)
        else 0.0
    )
    print(
        f"{client.label}: {len(cases)} case(s) x {args.samples} sample(s) = {calls} call(s), "
        f"about {chars // 3:,} prompt tokens; worst case ${worst:.4f}, budget ${args.budget:.2f}; "
        f"evaluation {version}"
    )
    if args.dry_run:
        return 0
    if paid:
        assert isinstance(client, OpenRouterClient)
        before = client.credits_remaining()
        print(f"credit remaining before: ${before:.4f}")
        if before < args.budget:
            print("evals: the account holds less than the budget; not running", file=sys.stderr)
            return 2
    cache = folder / f"{_slug(args.model)}.jsonl"
    summary = run_model(cases, client, args.samples, args.budget, cache, progress=_progress)
    print(
        f"done: {summary['calls']} new call(s), {summary['errors']} failed, "
        f"${summary['spent']:.4f} reported spend; {summary['stopped'] or 'completed'}"
    )
    if paid:
        assert isinstance(client, OpenRouterClient)
        print(f"credit remaining after: ${client.credits_remaining():.4f}")
    return 0


def evaluation_version(cases: Sequence[EvalCase]) -> str:
    """The prompt version and the blind case files it is judged on. A change to either is a new
    evaluation with a cache of its own ("How we proceed")."""
    files = hashlib.sha256("\n\x00\n".join(case.case_file for case in cases).encode()).hexdigest()
    return f"{PROMPT_VERSION}-{files[:12]}"


def make_client(spec: str, env: os._Environ[str] | dict[str, str]) -> ModelClient:
    provider, _, model = spec.partition(":")
    if provider == "ollama":
        return OllamaClient(replace(OllamaConfig.from_env(env), model=model))
    if provider == "openrouter":
        config = replace(OpenRouterConfig.from_env({**env, "OPENROUTER_MODEL": model}),
                         max_reply_tokens=EVAL_MAX_TOKENS)  # fmt: skip
        return OpenRouterClient(config)
    raise ConfigurationError("--model must be ollama:<model> or openrouter:<model>")


def run_model(
    cases: Sequence[EvalCase],
    client: ModelClient,
    samples: int,
    budget: float,
    cache: Path,
    progress: Callable[[str], None] = lambda _line: None,
) -> dict[str, Any]:
    """Every (case, sample) not already answered, until the budget would be exceeded."""
    done = {
        (str(item["case_id"]), int(item["sample"]))
        for item in _read(cache)
        if item.get("verdict") in VERDICTS
    }
    cache.parent.mkdir(parents=True, exist_ok=True)
    spent = 0.0
    calls = errors = 0
    stopped = ""
    worst_case = getattr(client, "worst_case_cost", None)
    for case in cases:
        for sample in range(samples):
            if (case.id, sample) in done:
                continue
            if worst_case is not None:
                worst = float(worst_case(len(SHADOW_PROMPT) + len(case.case_file)))
                if spent + worst > budget:
                    stopped = (
                        f"stopped before {case.id} sample {sample}: budget ${budget:.2f} reached"
                    )
                    return {"calls": calls, "errors": errors, "spent": spent, "stopped": stopped}
            seed = SHADOW_SEEDS[sample]
            messages = [
                {"role": "system", "content": SHADOW_PROMPT},
                {"role": "user", "content": case.case_file},
            ]
            item: dict[str, Any] = {"case_id": case.id, "sample": sample, "seed": seed}
            try:
                parsed, _raw, tokens, seconds = client.complete(
                    messages, SHADOW_SCHEMA, temperature=SHADOW_TEMPERATURE, seed=seed
                )
                verdict = parsed.get("verdict")
                item.update(
                    verdict=verdict if verdict in VERDICTS else None,
                    reasoning=str(parsed.get("reasoning", "")),
                    prompt_tokens=tokens,
                    seconds=round(seconds, 2),
                )
                if item["verdict"] is None:
                    item["error"] = "no usable verdict"
            except ModelError as exc:
                item.update(verdict=None, error=str(exc)[:300])
            item["cost"] = float(getattr(client, "last_cost", 0.0) or 0.0)
            spent += item["cost"]
            calls += 1
            errors += item["verdict"] is None
            with cache.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(item) + "\n")
            progress(f"{case.id} sample {sample}: {item['verdict'] or 'failed'}")
    return {"calls": calls, "errors": errors, "spent": spent, "stopped": stopped}


def _score(cases: Sequence[EvalCase], folder: Path, samples: int, version: str) -> int:
    results = [
        score(path.stem, cases, _read(path), samples) for path in sorted(folder.glob("*.jsonl"))
    ]
    if not results:
        print("evals: nothing to score yet", file=sys.stderr)
        return 2
    text = scorecard(results, version)
    (folder / "scorecard.md").write_text(text, encoding="utf-8")
    for result in results:
        print(
            f"\n{result.model}: {result.outcome}; ${result.cost:.4f}, {result.seconds / 60:.1f} min"
        )
        for name, (value, ok) in result.criteria.items():
            print(f"  {'pass' if ok else 'FAIL'} {name}: {value}")
    print(f"\nwrote {folder / 'scorecard.md'}")
    return 0


def _read(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _slug(spec: str) -> str:
    return spec.replace("/", "_").replace(":", "_")


def _progress(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evals.run", description=__doc__.split("\n\n")[0])
    parser.add_argument("--model", default="", help="ollama:<model> or openrouter:<model>")
    parser.add_argument("--samples", type=int, default=3, choices=range(1, len(SHADOW_SEEDS) + 1))
    parser.add_argument("--budget", type=float, default=0.0, help="hard USD cap for this run")
    parser.add_argument("--dry-run", action="store_true", help="estimate tokens and cost only")
    parser.add_argument("--only", default="", help="comma-separated case ids")
    parser.add_argument("--score", action="store_true", help="score every cached run")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
