# Runbook — backfill and replay

Three different operations that are easy to confuse:

| Operation | Writes retained history? | Reads source? | Use for |
|---|---|---|---|
| **Backfill** | Yes | Yes | Filling a gap in production history, chronologically |
| **Replay** | Yes | Yes | Re-running days in production after a behaviour change |
| **Isolated replay** | No — separate database | Yes | Comparing current behaviour against a published day |

Only the third is safe to run casually. The first two mutate production.

## Backfill

```shell
network-behaviour backfill --start 2026-08-10 --end 2026-08-17
```

Chronological and stops on the first failed day, because each day's baselines depend on every prior
day's retained history. A gap filled out of order produces days scored against incomplete history —
which does not fail, it just scores wrong.

A day backfills only while the source holds its detail. The original source kept about fifteen days
(`CASE_STUDY` §1); here a day stays while it is loaded, unless `NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS`
sets a retention. A backfill window reaching an expired or unloaded day fails on it rather than skipping
it.

## Replay

```shell
network-behaviour replay --start 2026-08-10 --end 2026-08-17
```

Same chronological, stop-on-failure semantics. Note what replay cannot do: a published day is
immutable, and a compatible rerun returns the stored bytes rather than recomputing. Replay does not
overwrite history under a new behaviour version — that would break Tier 0 immutability. To see what
current behaviour would produce for an already-published day, use isolated replay below.

## Isolated replay — the one to reach for

```shell
cd packages/triage
scripts/replay_day.sh 2026-08-18
scripts/replay_day.sh 2026-08-18 /tmp/my-replay
PRODUCTION_DB=/srv/network_behaviour.duckdb scripts/replay_day.sh 2026-08-18
```

Run it from `packages/triage`: `.env` and the default paths are relative to the working directory, and
the source settings (`NETWORK_BEHAVIOUR_SOURCE_PATH` and the rest) come from there as for `run-day`.
`PRODUCTION_DB` names the database to seed from (default `data/network_behaviour.duckdb`); `PYTHON` and
`CLI` override the workspace venv's interpreter and command. Without a second argument the replay goes to
a new temporary directory, and the script prints where.

Creates a fresh schema-10 database, seeds it with retained history strictly before the target day,
and publishes that day from source into it. Production is attached read-only and never written.

The `day < D` seeding is what makes the result comparable: the replay sees exactly the history the
original run would have seen, so a difference is attributable to behaviour rather than to hindsight.
This is the mechanism behind held-out-day evaluation in `docs/EVALUATION.md` §3.

Comparing against the stored stream:

```shell
NETWORK_BEHAVIOUR_DUCKDB_PATH=data/network_behaviour.duckdb \
  network-behaviour run-day --day 2026-08-18 > /tmp/stored.jsonl
python scripts/stream_stats.py --ties /tmp/my-replay/replay-2026-08-18.jsonl /tmp/stored.jsonl
```

What to compare, in order of what it tells you:

1. **Episode and host counts.** A large move means eligibility changed.
2. **Family mix.** Which detector moved.
3. **Tie structure.** Whether ordering became more or less informative — the number that should
   improve as calibration lands.

Byte-identical output is *not* the goal here. Identical bytes under a changed behaviour version
would mean the change had no effect.

## Cleaning up

Isolated replay databases are full schema-10 databases and are not small. They live in a temporary
directory by default; remove them when the comparison is done. They must never be used as a
production database — they contain a truncated history by construction, and publishing from one
would produce days scored against deliberately incomplete baselines.
