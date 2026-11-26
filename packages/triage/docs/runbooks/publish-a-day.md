# Runbook — publish a day

Produce the immutable evidence stream for one completed UTC day.

## Preconditions

- Day `D` is eligible from `D+1 08:00 UTC`. An earlier run is rejected, not queued.
- The day's Zeek logs are loaded: `network-behaviour load-zeek --day D --logs <dir>`. Zeek writes a
  connection when it ends, so give it D+1's logs too (a folder of dated subfolders does this itself).
- The source keeps a loaded day's detail until it is reloaded or removed. The original probe kept about
  fifteen days (`CASE_STUDY` §1); `NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS` reproduces that limit.
- `.env` present at mode `0600`.

## One day

Preflight first. It touches the database and local eligibility only, never the source:

```shell
network-behaviour run-day --day 2026-08-18 --dry-run
```

Reports `status`, `day`, `run_id`, client rows, service rows, candidate rows, query footprint and
projected storage bytes. Read `status` before continuing:

| status | Meaning | Action |
|---|---|---|
| `ready` | Not published, source expected available | Proceed |
| `already_published` | Stored stream exists | Publishing returns the stored bytes; no source access |

A run that cannot proceed prints no status. It prints `run-day blocked: <reason>` on stderr and exits 2:
before `D+1 08:00 UTC` the reason is that the day is not eligible until then, so wait. For any other
reason, do not force.

Then publish. **Redirect stdout** — the stream is the command's output, and its exact bytes are the
artifact:

```shell
network-behaviour run-day --day 2026-08-18 > candidate-feeds/daily-evidence-stream-2026-08-18.jsonl
```

## A trailing window

```shell
python scripts/publish_available_days.py                 # trailing 15 days, the original source's retention
python scripts/publish_available_days.py --days 7
```

Skips days that are already published, incomplete at source, or legacy selected-only. Writes each
stream through a `.partial` file and renames on success, so a killed run leaves no truncated stream.
Stops on the first genuine failure rather than continuing past it.

## Verifying output

```shell
python scripts/stream_stats.py --ties candidate-feeds/daily-evidence-stream-2026-08-18.jsonl
```

Sanity checks worth doing on a fresh day:

- **Episode count against the week.** On the original source, published volume ranged 1,510 to 19,676
  per day and tracked the academic week (`CASE_STUDY` §11); there, a weekday under 5,000 or a weekend
  over 15,000 was worth understanding before the stream was consumed. Judge a new deployment against its
  own weeks.
- **Family mix.** Relationship was ~96% on the original source. A large move means a detector or
  population change, not a quiet day.
- **Tie share.** `--ties` reports how much of each tier's ordering is decided by tie-break rather
  than evidence. It was ~90% on the original source.

## When it fails

Publication is all-or-nothing; a failed day leaves no partial state and staging is removed on both
paths. Common causes:

| Symptom | Cause | Action |
|---|---|---|
| `incomplete_day` from `source-check` | The loaded day is missing a required table or some of its minutes or buckets | Load the day again with `load-zeek` once all its logs are in place, D+1's included. Do not lower coverage requirements |
| Reconciliation beyond tolerance | Activity and rate sources disagree by more than the tolerance | Investigate the source; do not widen the tolerance to pass |
| `population_step beyond tolerance` | The addresses with a service row moved more than `drift.population_step_fraction` against the same UTC weekday, which the render names with its gap | Measure what moved before anything else. Addresses carrying only unaddressed rows cannot cause this; they are counted on the render's `not gated` line. A holiday week has moved it 30.87%. Do not widen the tolerance to pass |
| Log shows `dns_enabled: false`; the day published with no DNS episodes | The DNS population (clients that sent a query, DNS servers left out) moved beyond `drift.dns_population_step_fraction` against the same UTC weekday | Nothing to retry; the other families published. Measure what moved in `dns_pairs` before the next same weekday compares against it |
| `composition_tvd beyond tolerance` | The `service_basis` mix moved against the most recent published day | The source has changed what it resolves into a service. Investigate upstream |
| Storage stop | Projected retained growth hits the ceiling | Back up and prune before publishing. Publication never drops episodes to fit |
| Lock failure | Another run holds the database | Wait. Do not delete the lock file while a run is live |
| Version incompatibility | Stored day was built under behaviour versions this build cannot reproduce | Stream it back rather than re-deriving |

A rerun of a published day reads no source data and returns identical bytes. If it does not, that is
a determinism failure and a Tier 0 invariant break — stop and report it rather than republishing.
