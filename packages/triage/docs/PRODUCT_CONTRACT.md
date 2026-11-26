# Product Contract

Authoritative for **invariants, semantics, and the published interface**. Nothing else.

Three companion files carry what used to live here, and this document defers to each in its own domain:

| Concern | Authority | Rule |
|---|---|---|
| Every tuned number | `config/parameters.toml` | No threshold, window, edge or tolerance appears in this document |
| What the detectors actually do | `docs/generated/detectors.md` | Emitted from code. Never hand-written, never asserted here |
| What the data actually is | `docs/CASE_STUDY.md` | Measured and dated. Cite the section, never copy the value |
| What must be measured before a change | `docs/EVALUATION.md` | The quality gate |

The repository's `docs/SOURCE_CONTRACT.md` is a factual schema reference and cannot authorize behavior this
document does not permit.

**Version 2.** The v1 contract stated invariants, definitions, tuned parameters, product decisions and
descriptions of implementation at one authority level. The consequences were that unjustified thresholds became
as immutable as the leakage rule, and that §9 described two detectors — Jensen-Shannon composition shift and
synchronized-emergence suppression — which never existed in the code. Their evidence groups, and two others
that were also never emitted, were removed in `domain-codes-v3`; their codes are retired and never reused.
The tiering below, and generating detector descriptions from `src/` rather than asserting them here, exist to
prevent both failures.

---

## Tier 0 — Invariants

Never change without a major version and a migration plan for published days. Each names an enforcing test.

1. **Leakage.** Day `D` is scored only against retained history where `day < D`. Same-day population context is
   permitted and must be labelled as such wherever it contributes.
2. **Determinism.** Identical inputs, versions and parameters produce byte-identical output. A compatible rerun
   of a published day reads no source data and returns the stored bytes.
3. **Immutability.** A later day cannot mutate an earlier feed. Migration files are never deleted, renumbered,
   renamed, reordered or rewritten; released checksums are preserved.
4. **Source is read-only and bounded.** Parameterized SQL, typed half-open UTC bounds, smallest sufficient
   aggregate, no unbounded scans, no `SELECT *`, no per-client queries.
5. **Fail closed.** Publication aborts and rolls the whole day back on source schema or grain drift, incomplete
   principal coverage, out-of-window rows, duplicate or orphan retained keys, reconciliation beyond tolerance,
   population drift beyond tolerance, version incompatibility, partial or conflicting publication,
   count/evidence/digest mismatch, privacy-violating content, storage-stop projection, or lock failure.
6. **Completeness.** Every eligible non-diagnostic episode appears in the evidence stream exactly once. The
   publisher applies no capacity limit and no per-host or per-family cap.
7. **Storage ceiling.** Projected retained growth stops before the configured limit on the writable volume.

Invariant 6 is retained from v1 and is load-bearing: it is what makes reruns byte-stable and what anything
reading the stream downstream depends on. What v1 additionally forbade — that any downstream reader exist, that
any budget be applied anywhere — was a product decision, not an invariant, and is removed: a downstream stage
may exist, may budget, and may re-rank, so long as it never writes back into the publisher's eligibility, tier,
order or inclusion.

## Tier 1 — Semantics

Changing any of these requires a new version identifier and a compatibility entry. Published days keep the
version they were built under.

### Day and processing window

Day `D` is `[D 00:00:00, D+1 00:00:00)` UTC. Processing starts no earlier than `D+1 08:00 UTC`; an earlier run
is rejected. Current-day staging is separate from retained history and is deleted after success and failure
alike.

### Observed client identity

`client_ip` is the observed client address: the local side of each connection, as the original probe oriented
it and the Zeek loader still does. It is not a durable host identity, and no field in the
four authorized sources establishes stronger continuity — `subscriber_id` and `client_tag` are strict 1:1
aliases for the address (`CASE_STUDY` §6). Address reassignment may combine observations from different
assets. Any aggregation spanning more than one day carries an unquantifiable reassignment risk and must state
it.

IPv4 and IPv6 are canonicalized; IPv4-mapped IPv6 becomes IPv4; zone identifiers and invalid addresses are
rejected. Candidate wording uses "client IP" or "observed client".

**An address with at least one service row is in scope for behavioural comparison.** `behavioural-support-v3`
admits it however quiet it is: `client_ip` is an observed address and not a device, so "too quiet to be a host"
is not a question this data can answer, and the retired v1 gate (`active_5m_buckets >= 10 or flow_count >=
100`) showed what such a gate hides — on 2026-08-09 two of its three exclusions had moved tens of megabytes
through a single service. What v3 asks instead is whether any of the address's traffic can be interpreted.
An address with no service row has nothing external to measure; the transfer and fanout families do not score
it, and it sits in no peer or calibration pool (`baseline-calibration-v7`). On the original source that was
60–75% of observed addresses, which carried nothing but unaddressed rows, with no server address, port or
domain (`CASE_STUDY` §3). The Zeek loader writes no unaddressed rows (`docs/SOURCE_CONTRACT.md`). DNS is not gated:
`activity_1m` carries no DNS rows, so the DNS family scores its own population of addresses that sent
a query. Each run takes a population census and records what it put in or out of scope, in `ops.pipeline_run`.
`behavioural-support-v2` (no gate) decided days up to the first published under `primary-detectors-v9`.

### Source drift

Two gates abort a day before anything is written, under invariant 5.

| Gate | Aborts when | Catches |
|---|---|---|
| `population_step` | The scored population — addresses with at least one service row — moves more than `drift.population_step_fraction` against the most recent retained day with the same UTC weekday | The source measuring a different amount of what is scored. It is the population relationship and persistence prevalence are drawn from (`baselines/engine.py`) |
| `composition_tvd` | The `service_basis` mix moves further than `drift.composition_tvd` in total variation against the most recent published day | The source measuring a different thing — a basis shift that leaves the address count untouched |

The population is the scored one, not every observed address: on the original source 60–75% of observed
addresses carried only unaddressed rows (`CASE_STUDY` §3), every population step the first gate reacted to was
in them alone (`CASE_STUDY` §2), and since `behavioural-support-v3` no activity family scores such an address
or pools it. The gated
population and the in-scope population are the same addresses by definition. It is compared weekday to weekday because it follows the
week. Both counts come from retained history, so the comparison does not depend on which support definition
either day ran under. A day with no earlier same-weekday day, or no prior published day, has nothing to compare
and passes saying so; a gap is reported, never compensated for. Addresses with no service row are counted in
the drift render and gate nothing.

A third check aborts nothing. `dns_population_step` compares the DNS population — addresses that sent a DNS
query, DNS servers left out, the population DNS resolver novelty divides by — against the most recent day with
the same UTC weekday in the DNS observations the run already reads. Beyond `drift.dns_population_step_fraction`
it turns the DNS family off for the day, as an absent `dns_pairs` does, and the day publishes
(`CASE_STUDY` §9).

Tolerances are Tier 2 and live in `config/parameters.toml` with what they were fitted on. `composition_tvd` is
fitted on the legitimate range only — no observed composition failure exists in retained history to calibrate
the other side. The gate decides only whether a day not yet published may publish: a published day is returned
before source is read or the gate runs, so `drift-gates-v2` changes no published day.

### Authorized sources

Only these four tables. They live in a DuckDB source file that `network-behaviour load-zeek` writes from
Zeek logs, one UTC day at a time (`zeek-source-bundle-v1`); every reader opens it read-only. The column-by-column
mapping and its approximations are in the repository's `docs/SOURCE_CONTRACT.md`. The original deployment read the
same four tables from a commercial flow probe through ClickHouse (`phase3-source-bundle-v3`); the queries kept
their names, versions and output columns across the move.

| Source | Authorized use |
|---|---|
| `flow.activity_1m` | Client/service traffic, composition, fanout, activity shape. 1,440 minute buckets required |
| `flow.host_load_5m` | Upstream-rate shape and activity/rate reconciliation. 288 buckets required. Fields are percentiles, not exact maxima |
| `flow.dns_pairs` | Resolver novelty, volume, unanswered/unsolicited activity, weighted service time. Optional; absence, or a DNS population beyond tolerance, disables DNS context. Its only source of DNS: `activity_1m` carries no port-53 row (`CASE_STUDY` §9) |
| `flow.long_flows` | Individual-transfer duration, size, repetition. Optional; absence never lowers strength |

Subscriber profiles, raw subscriber IDs, client tags, mobile identifiers and unrelated metadata are not
selected. The mobile identifier columns are empty in this deployment (`CASE_STUDY` §5), so the guard costs
nothing and is retained against upstream change.

### Two facts that constrain design

Stated here because their absence has already produced incorrect designs:

- **`server_port` is the remote side's port, whichever side opened the session.** The original probe oriented
  the campus side as the client in every row of both tables, and the Zeek loader does the same. `activity_1m` records sessions the remote side opened
  like any other, and has no column for direction or for the campus port, so **direction cannot be read
  from it**. `long_flows.initiator` records direction for long flows only; in its `server` rows
  `client_port` is the campus service port, so direction is measured only on long flows (`CASE_STUDY` §7).
  A named TLS site served to many outside networks is also visible in retained history by its shape
  (`CASE_STUDY` §17). *Amended 2026-10-22:* this bullet said locally-served exposure was not observable in
  these sources, which §7 measured to be false. *Amended 2026-11-13:* it said served exposure was observable
  only through long flows, which §17 measured to be incomplete. No component reads direction or the serving
  shape, so neither amendment moves a version identifier or affects a published day. *Amended 2026-11-25:* the
  Zeek loader knows who opened every connection, but it keeps the original columns, so all of this still
  holds of the tables.
- **`activity_1m` records occupied minute buckets, not connection events.** A held-open connection
  yields gaps of exactly one minute. Any timing measure must impose a minimum mean gap or it measures session
  continuity rather than scheduling (`CASE_STUDY` §10).

### Logical services

Basis precedence: registered root domain, domain from SNI, domain from DNS, application + ASN, ASN, server IP.
ASN is a separate route dimension and is never folded into a domain-based `service_id`. Only a non-empty
public-routable destination or another meaningful basis creates service history; special-purpose destinations
contribute only to host totals and opaque bytes.

Port groups use the versioned `port-groups-v1` exact-value allowlist; all other values map to `other_system`,
`other_registered`, `dynamic` or `unknown`, and unknown ports do not support vertical fanout. `server_port` is
zero on most rows of the original source (`CASE_STUDY` §5), so port-group fanout rested on a sparse field
there. The Zeek loader sets it on every TCP and UDP row; ICMP and other protocols carry 0.

The activity bitmap has 288 five-minute buckets in exactly 36 bytes, bucket zero at the least-significant bit of
byte zero.

### Retained analytical history

Exactly two grains, 365 days: `history.client_day` (grain `day + client_ip`) and `history.client_service_day`
(grain `day + client_ip + service_id + asn_id + application_category_id + transport_protocol + port_group`).
Column definitions are unchanged from v1.

No endpoint, five-minute, DNS, rate or individual long-flow source rows are retained. **No raw domain, SNI, DNS
or endpoint string is retained in either grain.** Ratios and shares are derived at scoring time.

### Version registry

| Concern | Identifier |
|---|---|
| Package | `0.2.0` |
| DuckDB schema | `10` |
| Domain codes | `domain-codes-v3` — evidence-group codes 8, 10, 11 and 12 retired, never reused |
| Source query bundle | `zeek-source-bundle-v1` — the `sql/source/` queries over Zeek-loaded tables; `phase3-source-bundle-v2`/`-v3` were the ClickHouse originals |
| Normalization bundle | `service-id-v1/category-id-v1/port-groups-v1/bitmap-288-lsb-v1/tldextract-5.3.1`, with `+synthetic` on a day published in a synthetic world (`NETWORK_BEHAVIOUR_SYNTHETIC`) |
| Day aggregation | `day-aggregation-v2` |
| Reconciliation | `activity-rate-relative-v1` |
| Behavioural support | `behavioural-support-v3` — addresses with at least one service row; DNS scores its own population |
| Baselines | `baseline-calibration-v7` |
| Detectors | `primary-detectors-v9` |
| Episode ordering | `episode-ordering-v4` |
| Source drift gates | `drift-gates-v3` — scored population against the same UTC weekday, plus a DNS coverage check that disables DNS only; `drift-gates-v2` never decided a day; `drift-gates-v1` gated every observed address and decided days up to 2026-10-18 |
| Evidence stream schema | `daily-evidence-stream-v2` |
| Evidence stream encoding | `daily-evidence-stream-jsonl-v2` |

Migration versions and persisted names are immutable:
`0001_history`, `0002_operational`, `0003_phase3_manifest`, `0004_phase6_candidate_evidence`,
`0005_phase7_review_session`, `0006_phase8_baseline_review`, `0007_phase8c_daily_feed`,
`0008_evidence_stream_v2`, `0009_baseline_version`, `0010_population_census`. The `phase*`
strings are
compatibility identifiers with no product meaning. The released alternate checksum accepted only for
`0006_phase8_baseline_review` is
`6491769659f29877c276c2a58bf1c374fe5c041961395b5a6fee9a8502dd4513`.

### Reruns: forward-only

**A published day is never re-derived. A behaviour change applies to days published after it.**

This is not a preference. Source detail can expire while retained history runs 365 days: the original source
kept about fifteen, and here a day expires after `NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS` when that is set, so
most of an archive can have no source left to rebuild from; and a published day is reconstructed and verified
against a stored SHA-256, byte count and evidence count, so re-encoding one breaks its digest and invariant 2
with it. There is no conversion path between generations and there cannot be one. `feed_schema_version` and the
behavior version lists below are **dispatch keys and allow-lists, not converters**.

Consequently a change to what any number means bumps the version of the component that computes it, and the new
value joins that component's allow-list. Membership is what keeps already-published days readable; strict
equality would strand every one of them the moment a component moved.

Every generation a published day records is checked by membership: behaviour pair, baseline, source-query
bundle, per-query versions, schema, normalization, aggregation and reconciliation (`operations/pipeline.py`,
`_published`). What stays strict is integrity: the run record and the stored feed must name the same
behaviour pair, and the stored digest, byte count and evidence count must reconcile. Until 2026-10-23 the
schema and per-query versions were compared by equality, and the 25 `daily-candidate-feed-v1` days written
at schema 7 (2026-07-13 → 08-09) were refused although nothing about them had changed.

The registry holds 10 behaviour pairs (`ranking/models.py`, `COMPATIBLE_BEHAVIOUR_VERSION_PAIRS`): the
current `primary-detectors-v9 / episode-ordering-v4`, and 9 historical pairs, returned byte-for-byte without
source access and never re-ordered: `primary-detectors-v8 / episode-ordering-v4`,
`primary-detectors-v7 / episode-ordering-v4`, `primary-detectors-v6 / episode-ordering-v4`,
`primary-detectors-v5 / episode-ordering-v3`, `primary-detectors-v4 / episode-ordering-v3`,
`primary-detectors-v3 / episode-ordering-v3`, `primary-detectors-v2 / episode-ordering-v3`,
`primary-detectors-v2 / episode-ranking-v2`, `primary-detectors-v2 / episode-ranking-v1`.

Compatible baseline generations: `baseline-calibration-v7`, `baseline-calibration-v6`, `baseline-calibration-v5`, `baseline-calibration-v4`, `baseline-calibration-v3`, `baseline-calibration-v2`. A day whose `ops.pipeline_run.baseline_version` is
null was published before migration `0009` recorded it, and remains readable for the same reason — it cannot be
re-derived.

Days published under `daily-candidate-feed-v1` are reconstructed from `feed.candidate_episode` and
`feed.candidate_evidence` by the frozen contract in `feed/legacy_v1.py`, and stream back in their
original encoding. Migration `0008` is strictly additive; the v1 tables are never rewritten, because
a published day's digest was taken over its original bytes.

## Tier 2 — Parameters

Every tuned number is in `config/parameters.toml` with its provenance. Most currently carry
`status = "inherited-unjustified"`, which is accurate: they arrived from v1 with no record of what they were
chosen to achieve.

Changing one is an ordinary change requiring the `docs/EVALUATION.md` evidence bundle. It is not a contract
amendment. This is the central difference from v1, where a threshold nobody justified was as hard to move as
the leakage boundary.

## Tier 3 — Evaluation

`docs/EVALUATION.md` defines the evidence bundle required before any parameter, detector, ordering or
interface change ships. The acceptance suite in Tier 5 below proves correctness; the evaluation bundle proves
the output is worth reading. v1 had the first and not the second.

## Tier 4 — Interface

### The evidence stream

The publisher's sole artifact is the episode stream: complete, immutable, byte-stable, all-eligible, no caps.
Nothing downstream of it is specified by this contract.

### Ordering: no fabricated total order

v1 asserted a total order over every episode and rendered it as `daily_rank` plus an interpolated
`priority_score`. Both are removed.

- `priority_score` is deleted. It was linear interpolation of rank position — 21 distinct values across 3,100
  episodes, 155 sharing each — so it carried no information beyond position while implying measurement.
- `daily_rank` is deleted. A contiguous 1..N order over 10,000 episodes claimed a discrimination the evidence
  does not support: ~90% of adjacent in-tier pairs tied on every substantive key and were separated by a UUID
  digest (`CASE_STUDY` §12).

They are replaced by an honest partial order:

- **`sequence`** — contiguous 1..N position in the file. Exists solely so a consumer can verify nothing was
  dropped. Explicitly not a priority, and named so it cannot be read as one.
- **`tie_group`** — dense rank over the true ordering key. Episodes indistinguishable on the evidence share a
  `tie_group`. Where v1 spread 514 equivalent episodes across ranks 1–514, this reports 514 episodes at
  `tie_group` 1 and lets the consumer see they are equivalent.
- **`evidence_tier`** — `E1` / `E2` / `E3`, renamed from `priority_tier`. "Priority" asserted an ordering claim
  the evidence does not support, and the top tier held 30% of the stream on the original source.

The ordering key is unchanged in substance and remains fully deterministic: tier, then strength, then
independent family count, then corroboration, then history confidence, then data-quality confidence, then
candidate ID. Determinism is Tier 0. What is removed is the pretence that positions within a tie are meaningful.

### Resolvable destinations

`service_id: 009c356ffb6eda…` supports no investigation on its own, and the top-ranked candidate of 2026-08-05
carried `service_id: null`. Episodes are therefore resolvable:

- `service_domain` is emitted on an episode **only** when the service basis is `domain` and the service
  contributed to eligibility, tier or ordering. Where the basis is `application_asn`, `asn` or `server_ip`, no
  domain exists and the field is null.
- No domain appears on evidence rows that did not affect the decision.
- `null` carries two meanings and consumers must not conflate them: the basis is not `domain`, **or** the day
  was published before 2026-08-23, when population began. Days published earlier keep `null` permanently —
  retained history is hashed and the original source kept about fifteen days, so their domains are
  unrecoverable by construction. This is a gap in coverage, never evidence that a service had no domain.
- No raw domain, SNI, DNS or endpoint string is written to retained history, which stays hashed. The source's
  detail is short-lived (the original source kept about fifteen days); retained history keeps 365. Emitting a resolvable identifier on a short-lived
  stream is not the same act as building a year-long browsing archive, and only the first is authorized.
- No raw server IP, flow record, source row, user agent, review content or free-text evidence appears anywhere
  in the stream.

### Stream shape

`daily-evidence-stream-jsonl-v2`: exactly one header record, then one episode record per line in `sequence`
order.

Header: `record_type, stream_encoding_version, stream_schema_version, day, published_at, run_id,
detector_version, ordering_version, episode_count`.

Episode: `episode_id, run_id, day, detected_at, client_ip, family, episode_start, episode_end, service_id,
service_domain, asn_id, family_strength, evidence_tier, sequence, tie_group, evidence_group_mask,
history_confidence, data_quality_confidence, reason_code_mask, detector_version, ordering_version,
source_detail_expires_at, evidence`.

Evidence entry: `evidence_group, metric_code, observed_value, client_baseline_value, peer_reference_value,
self_strength, peer_strength, metric_strength, support_count`. At most one entry per evidence group, and only
groups that affected eligibility, tier or ordering.

`source_detail_expires_at` is the end of the day plus `NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS`, and null when
that is unset and the source keeps a day while it is loaded.

Counts, IDs, sequence contiguity, tie-group monotonicity, tier order, version linkage, UTC timestamps, masks and
stored digest must reconcile.

### Commands

`network-behaviour run-day --day YYYY-MM-DD` writes the header-first stream to stdout. `--dry-run` performs
local eligibility and database preflight. Administrative commands remain supported and hidden from the
release-facing help surface: `load-zeek`, `source-check`, chronological `backfill` and `replay`,
`storage-report`, `backup`, `restore`. Range processing is sequential and stops on the first failed day.

## Tier 5 — Claim limits and acceptance

### Claim limits

Retained in full, on epistemic grounds rather than regulatory ones. The evidence lacks endpoint process, file,
socket-owner, user, authentication, payload, TCP-state, failed-connection, asset-inventory and
threat-intelligence context, and DNS carries no query names, record types or response codes.

- No host is classified malicious or benign. No threat, compromise or risk probability is produced.
- No scanning, exfiltration, malware, command-and-control or compromise labels.
- Ordering is investigation sequencing for one day and one exact set of behavior versions. It is not risk, a
  verdict or a probability.
- Fanout claims no connection attempts. Bitmap recurrence establishes no exact interval. DNS claims no
  tunnelling and no response-code anomaly.

Detector and profile names describe the observable shape. A threat model may inform which shapes are worth
measuring — this is equally true of the existing families — but it never reaches the output as a label.

### Acceptance

The maintained suite proves: normalization, routability, service precedence, IDs, ports, protocols, bitmaps;
fresh and upgraded migrations agreeing on the schema through `0010_population_census`, and released schema-6
checksum compatibility; every live entry in `config/parameters.toml` equal to the value compiled into `src/`;
retained grains, uniqueness,
non-negativity, 365-day retention, transient cleanup; strict `day < D` baselines and confidence behavior;
detector eligibility, support, suppressor, optional-context, reason-code and wording boundaries; fusion,
confidence caps, deterministic ties, stable IDs, sequence contiguity, tie-group correctness and all-eligible
inclusion; stream field validation, privacy, evidence parity, digest checks, bulk persistence, rollback, and
reads beyond 10,000 episodes; atomic publication, interruption recovery, idempotency, source-free byte-stable
reruns, later-day immutability, legacy-day rejection, storage guards, backup and restore, CLI output; and
aggregate-only, read-only source queries, checked by `validate_sql` and run against a loaded synthetic source.
There is no live contract test: the source is the DuckDB file `load-zeek` writes.

This suite proves correctness only. `docs/EVALUATION.md` is the separate gate for output quality.

### Amendment

Changes to Tier 0 or Tier 1, to the stream schema or encoding, or to the claim limits require an explicit
amendment here with synchronized code and focused tests. Tier 2 parameter changes require the evaluation bundle
and not an amendment. Detector behavior is described in `docs/generated/detectors.md` and is never described
here.
