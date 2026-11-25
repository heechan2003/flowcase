# Network Behaviour Triage — agent guide

Publishes a complete immutable stream of behavioural episodes for one UTC day, then reduces it to a short queue
of observed client hosts on the campus network worth investigating. Ordering is investigation sequencing, never risk.

## Where authority lives

Read the row for what you are changing. Do not read the whole set.

| Changing | Read | Requires |
|---|---|---|
| A threshold, window, band edge, tolerance | `config/parameters.toml` | Evidence bundle (`docs/EVALUATION.md`). **Not** a contract amendment |
| Detector or ordering behavior | `src/`, then `docs/generated/detectors.md` and `docs/generated/ordering.md` | Evidence bundle + regenerate `docs/generated/` |
| Leakage, determinism, immutability, completeness, fail-closed | `docs/PRODUCT_CONTRACT.md` Tier 0 | Major version + migration plan |
| Day, identity, sources, services, ports, bitmap, retained grains | Tier 1 | New version identifier + compatibility entry |
| Stream schema, encoding, commands | Tier 4 | Schema version bump |
| Claim limits | Tier 5 | Explicit amendment. Expect to be argued with |
| SQL against the source | `sql/CLAUDE.md` | Those rules, which are stricter |

**Before proposing any number, read the repository's `docs/CASE_STUDY.md`.** It records what this deployment's data actually
is, with measurement dates. Most defects here came from reasoning about the data instead of measuring it. Cite
the section; never copy the value, so staleness propagates.

Report conflicts between authorities. Never resolve one by choosing the broader behavior.

## Four rules with teeth

**1. `docs/generated/` is never hand-written.** It is emitted from code. The v1 contract hand-described a
Jensen-Shannon composition detector and a synchronized-emergence suppressor; neither exists in `src/`, and the
gap survived a full acceptance suite for months. Writing prose about detector behavior means you have the wrong
file open.

**2. Claims about behavior cite code, not the contract.** The contract states what must be true; only `src/`
states what is true. This repository has already shipped a contract that over-described its implementation, and
a review that reasoned from it as though it were a description.

**3. `sql/migrations/` is immutable.** Never delete, renumber, rename, reorder, squash or rewrite. Preserve
released checksums, compatibility aliases, legacy tables and views. Every retained day and every published
stream depend on it (`CASE_STUDY` §11).

**4. Never commit data.** `candidate-feeds/` and `data/` are data directories and nothing else. Both are
git-ignored; keep it that way. Never commit source rows, generated streams, databases, backups, credentials or
raw identifiers. Fixtures are synthetic: campus hosts use `10.0.0.0/8` or documentation ranges.

## Product rules

- Process day `D` no earlier than `D+1 08:00 UTC`; score only against history where `day < D`.
- `client_ip` is an observed address, not a durable device identity. `subscriber_id` and `client_tag` are 1:1
  aliases and add nothing (`CASE_STUDY` §6).
- Only the four authorized sources. Query DNS directly, retain no copy. Missing long-flow evidence never lowers
  strength.
- Persist only `history.client_day` and `history.client_service_day`, 365 days. **No raw domain, SNI or endpoint
  string in retained history** — the stream may carry a resolvable domain, the 365-day store may not.
- Publish every eligible non-diagnostic episode exactly once. No capacity or per-host cap in the publisher.
- Never use scanning, exfiltration, malware, command-and-control or compromise labels. The evidence cannot
  support them.
- Stop projected retained growth before the configured limit on the 60 GiB volume; keep backups elsewhere.

## Source safety

Any live source access follows `sql/CLAUDE.md`.
Read-only credentials, parameterized SQL, typed half-open UTC bounds, smallest sufficient aggregate. No
unbounded scans, no `SELECT *`, no one-query-per-client, no printing of SQL, credentials, raw identifiers,
domains, endpoints or source rows. Never select subscriber profiles, IDs or tags, or mobile identifiers —
`src/network_behaviour/source/sql.py` blocks these by regex and the guard stays even though the IDs and tags
add nothing and the mobile columns are empty (`CASE_STUDY` §5, §6). Report the query footprint of any live work.

`.env` stays untracked at mode `0600`; `.env.example` keeps a blank password.

## Working method

Inspect the code and the relevant authority row before changing behavior. Prefer deterministic typed functions,
parameterized SQL, separate current-day staging, bulk persistence, synthetic fixtures. Version every source,
schema, normalization, detector, ordering and stream change. Add focused tests, avoid unrelated refactors.

When a task touches both a document and the code it describes, change them in the same commit. Drift between
the two is the failure this repository is recovering from.

## Validation

```shell
make check                           # from the repository root: both packages, every gate
uv run pytest tests/unit             # fast
uv run network-behaviour run-day --help
```

Helper scripts:

| Script | Does |
|---|---|
| `stream_stats.py` | Composition of a published stream; `--ties` reports ordering that carries no information |
| `evaluate.py` | The `docs/EVALUATION.md` bundle: `bundle`, `volume`, `seed`. Reads day D from retained history unless `--source` |
| `generate_detectors_doc.py` | Emit `docs/generated/detectors.md`; `--check` in CI |
| `generate_ordering_doc.py` | Emit `docs/generated/ordering.md` — tier ladder and ordering key; `--check` in CI |
| `generate_parameters_doc.py` | Emit `docs/generated/parameters.md`; `--check` in CI |
| `publish_available_days.py` | Publish a trailing window of unpublished days |
| `replay_day.sh` | Re-derive one day in an isolated database, seeded with `day < D` history |

Bundles land in `docs/evaluations/`, which is git-ignored because a bundle measures a real day; the case
study reports what they found. They are evidence, never authority, and are not edited after a change ships. `network_behaviour.evaluation` is the library behind `evaluate.py`; nothing in the
publication path imports it.

Operator procedures are in `docs/runbooks/`.

This repository documents what the product **is**, not what it may become. There is no roadmap and
no plan file. If you find yourself writing a goal, a next step, a phase or an open direction into a
document here, that belongs in an issue tracker or a commit message, not in `docs/`.

## Definition of done

Preserves Tier 0 and Tier 1, the migrations and the privacy boundary; keeps compatible reruns byte-stable;
passes applicable offline checks; carries the evidence bundle if it touched a parameter, detector or ordering;
updates versioned behavior, `docs/generated/` and documentation together; avoids unrelated changes; and reports
commands run, live-query footprint, and every unverified assumption.

State plainly what you did not verify. A confident report of unverified work is the most expensive failure mode
here.
