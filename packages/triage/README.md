# Network Behaviour Triage

Processes one completed UTC day of network observations from a university campus network and publishes an immutable, versioned stream
of behavioural episodes — then reduces that stream to a short list of observed client hosts worth investigating.

Ordering is investigation sequencing. It is not a risk score, a threat verdict, or a probability of compromise.

## The evidence stream

`network-behaviour run-day` publishes one artifact: a complete, immutable, byte-stable record of every eligible
episode, uncapped by design and ranging from 1,510 to 19,676 episodes a day.

## Setup

This package is a member of the repository's uv workspace (Python 3.13). From the repository root:

```shell
make sync
```

Copy `.env.example` to `.env` and set mode `0600`. `.env` is git-ignored and process-environment values take
precedence. The product database defaults to `data/network_behaviour.duckdb`.

## Publish a day

Day `D` becomes eligible at `D+1 08:00 UTC`:

```shell
network-behaviour run-day --day YYYY-MM-DD > stream.jsonl
```

Redirect stdout to keep the exact bytes. Output is `daily-evidence-stream-jsonl-v2`: one header record, then one
episode per line in `sequence` order. It contains every eligible E1/E2/E3 episode and no diagnostic, suppressed,
ineligible or below-threshold observation.

Preflight without touching the source:

```shell
network-behaviour run-day --day YYYY-MM-DD --dry-run
```

Rerunning an already-published day reads no source data and emits identical bytes.

## Reading an episode

```json
{"record_type": "episode", "episode": {
  "client_ip": "…", "family": "relationship", "evidence_tier": "E2",
  "sequence": 47, "tie_group": 12,
  "service_id": "…", "service_domain": "www.example.test",
  "episode_start": "…", "episode_end": "…", "evidence": [ … ]}}
```

- **`evidence_tier`** — `E1`, `E2` or `E3`. A coarse evidence bucket, not a priority. E1 currently holds about
  30% of the stream, so treat it as "has corroborated strong evidence", not "is urgent".
- **`sequence`** — position in the file, contiguous from 1. Exists so you can verify nothing was dropped. **Not
  a priority.**
- **`tie_group`** — episodes with the same value are **indistinguishable on the evidence**. A large tie group
  means the ordering inside it carries no information. This is reported rather than hidden because roughly 90%
  of adjacent within-tier pairs are tied.
- **`service_domain`** — present only where the service was derived from a domain and that service affected the
  decision. Null for ASN- and IP-based services, which have no domain.

There is no `priority_score` and no `daily_rank`. Both asserted a total order the evidence does not support and
were removed in stream schema v2.

## Administrative commands

Supported, hidden from the release help surface:

```shell
network-behaviour source-check --metadata-only
network-behaviour source-check --day YYYY-MM-DD
network-behaviour backfill --start YYYY-MM-DD --end YYYY-MM-DD
network-behaviour replay   --start YYYY-MM-DD --end YYYY-MM-DD
network-behaviour storage-report
network-behaviour backup  --output /separate-storage/network_behaviour.duckdb
network-behaviour restore --input  /separate-storage/network_behaviour.duckdb \
                          --output data/restored-network_behaviour.duckdb
```

Source checks are read-only, UTC-bounded and aggregate-only. Backfill and replay are chronological and stop on
the first failed day. Keep verified backups off the 60 GiB writable volume. Restore refuses to overwrite an
existing output.

## Known limitations

Read the repository's `docs/CASE_STUDY.md` before trusting any number this system produces. The ones that most affect
interpretation:

- **The population is address space, not devices.** Every observed address carries an unaddressed
  `Web Browsing` row (no server address, port or domain) in nearly every minute of the day, and most addresses
  carry nothing else. What those rows count is not documented. Since `behavioural-support-v3` an address with
  no service row is out of scope for the transfer and fanout families and their peer pools — about 7,000 a day,
  reported in each run's census — and DNS still scores the addresses that sent a query.
- **`flow_count` is zero on exactly those unaddressed rows**, about half the source, so any gate resting on flow
  counts is carried by its other arm.
- **Source detail expires in about fifteen days.** Older days can be replayed from retained history but not
  re-derived.
- **`client_ip` is not a durable host identity.** No source field offers better continuity.
- **Direction is visible only in long flows.** The probe always orients the campus side as the client and
  `server_port` is always the remote side's port, so `activity_1m` cannot say who opened a
  connection. `long_flows.initiator` can, for long flows only.
- **Sessions the remote side opened are scored as the host's own.** No detector reads direction. Measured
  2026-10-23 over 390,056 published episodes (`CASE_STUDY` §7): 0.9% sit on host-days where remote-opened
  long flows carry most of the host's long-flow upload, rising to 7.7% of persistence episodes.
- **Data-quality confidence is constant.** No run sets the source-quality input except the DNS coverage check,
  and that one only switches DNS off (`CASE_STUDY` §12), so the data-quality term of the ordering key never
  separates two episodes.
- **Most of the ordering inside a tier is a hash.** Roughly 90% of adjacent within-tier pairs tie on every
  substantive key (`docs/generated/ordering.md`); `tie_group` says so rather than hiding it.
- **Persistence rarity is uncalibrated.** It is `100 × (1 − prevalence)` (`detectors/engine.py`,
  `_rarity_strength`), not a tail probability like relationship rarity.
- **The drift tolerances have thin legitimate margins.** The scored population moved 30.87% against the same
  weekday around the 2026-10-05 public holiday, against a tolerance of 0.35. The DNS population moved 70% and 43%
  on 2026-07-23 and 07-30 for reasons not established, which the 0.35 DNS tolerance would treat as a coverage
  failure (`config/parameters.toml`, `drift.*`).
- **DNS covers about 308 clients a day** (`CASE_STUDY` §9), the addresses that send a query, so the DNS family
  is context for few hosts.
- **The evidence cannot support threat conclusions.** No payload, TCP state, process, user, asset inventory or
  DNS query names. The output orders investigation; it does not identify compromise.

## Repository map

| Path | What |
|---|---|
| `docs/PRODUCT_CONTRACT.md` | Invariants, semantics, interface. Authoritative |
| `config/parameters.toml` | Every tuned number, with provenance |
| `../../docs/CASE_STUDY.md` | What the data actually is, measured and dated, and the evaluations behind each change |
| `docs/EVALUATION.md` | What must be measured before a behaviour change ships |
| `docs/generated/` | Emitted from code. Never hand-edited |
| `docs/runbooks/` | Operator procedures: publish, backfill/replay, backup/restore |
| `scripts/` | Read-only helpers, doc emitters and `evaluate.py`, the evidence-bundle harness |
| `CLAUDE.md` | Start here if you are an agent |

## Development

```shell
make check                      # from the repository root: format, lint, types, generated docs, tests
uv run pytest tests/unit         # from this directory: the fast suite
uv run network-behaviour --help
```

Changes to a parameter, detector or ordering also require the evidence bundle in `docs/EVALUATION.md`. Passing
tests proves the system computes the same thing twice; the bundle is how it shows the thing is worth computing.

`scripts/evaluate.py` produces one:

```shell
uv run python scripts/evaluate.py bundle --day 2026-08-21 --change "what changed" \
    --volume-start 2026-08-15 --volume-end 2026-08-21
```

It seeds an isolated database with retained history strictly before the day, scores that day repeatedly under
injection, permutation, resampling and parameter perturbation, and writes all five sections to
`docs/evaluations/` (git-ignored here, because a bundle measures a real day). Day D is reconstructed from retained history and costs no live query unless `--source` is
given. Sections it did not measure are written in as *not measured, and why*; the verdict is left for a person.
