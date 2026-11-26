# Evaluation Contract

Authoritative for **output quality**. The acceptance suite in `PRODUCT_CONTRACT.md` Tier 5 proves the system
computes the same thing twice. This document is how the system shows the thing is worth computing.

v1 had no equivalent. Its acceptance list was thorough and entirely correctness: determinism, digests,
atomicity, rollback, migrations, retention, privacy. Nothing in it could have failed if the ranking were
random — and roughly 90% of within-tier ordering was in fact resolved by a UUID digest for months without any
test noticing.

## When a bundle is required

| Change | Bundle |
|---|---|
| Any value in `config/parameters.toml` | Required |
| Detector eligibility, evidence, or wording | Required |
| Ordering key, tier assignment, fusion | Required |
| Stream schema, encoding, CLI, storage, migrations | Not required — Tier 5 acceptance covers these |
| Documentation, generated files, refactors with no behavior change | Not required |

A bundle is five artifacts. Missing ones are stated as missing, never omitted silently. A bundle reporting a
regression is still a valid bundle; suppressing one is the failure this document exists to prevent.

---

## 1. Sensitivity envelope

**Question:** what behaviour can this system see at all?

Synthesise behaviours matching each detector or profile, sweep them across amplitude and period, inject into
held-out real host-days, and measure how often each produces an eligible episode attributed to the implant's own
service.

Requirements:

- **Synthesise at the source grain.** `activity_1m` records occupied minute buckets with volumes,
  not connection events (`CASE_STUDY` §10). An implant built from connection events measures the simulator.
- **Hold out the days.** Inject into days excluded from baseline construction, or the implant contaminates the
  history it is measured against.
- **Sweep, do not spot-check.** A single amplitude yields a claim, not an envelope.
- **Include jitter** for any timing profile. A schedule with no jitter is the easy case and is not the
  interesting one.

Report as a region of parameter space:

> Scheduled contacts with period ≤ 1 h and ≥ 20 occurrences produce an attributed episode in 90% of injections.
> Below 10 occurrences, never.

**Call this sensitivity, never recall.** Recall is measured against real compromise, which nobody here can
measure. The distinction is not pedantry — it is the difference between a defensible claim and one that will be
quoted back during an incident.

## 2. Blocked permutation null

**Question:** how much of the output is responding to structure rather than to a host?

Permute host labels and re-run. Whatever still fires is responding to the shape of the data, not to any host's
behaviour.

Requirements:

- **Block within time-of-day and day-of-week strata.** Naive shuffling destroys diurnal and weekly structure,
  which inflates the apparent null and makes the result flattering and useless.
- **Preserve marginals.** Volume, destination-count and activity distributions must survive the permutation.
- **Report per condition and per conjunction.** The gap between the two is the redundancy measurement in §5.

**Report the per-condition table. There is no single number here.** This section used to ask for the firing
rate under permutation, stated as an upper bound on the structural-artefact share of output. Measured on
2026-08-09 that quantity was **792%**, which bounds nothing, and the fault was in the instruction rather than
in the run.

`relationship` and `persistence` are defined against *a host's own history*. Permutation breaks the pairing
between a day and the history it is judged against — that is the whole point of it — so under the null every
service looks new to whichever host now carries the label. `novelty_moderate` went 9.75% to **44.77%** and
persistence collapsed 100 episodes to **0**. Permuted output exceeding observed output is what a
history-relative detector must do here, so no ratio of the totals means anything. Report the totals for
direction and scale; do not divide them into each other.

What survives is the comparison condition by condition, and it answers the question more directly than any
aggregate did:

- **A condition whose pass rate does not move under permutation carries no host-specific information.** Its
  information comes from the service, the population or the day. `relationship_eligibility.rarity_moderate`
  passes at **6.71% observed and 6.71% permuted** — population rarity is a property of the service, and no
  relabelling of hosts can touch it. This is a statement about where a condition's information comes from, not
  a verdict that it is redundant: a service-level filter may be exactly what a rule needs. `permutation.py`
  computes this classification relatively, so a condition passing at 0.58% against 0.43% counts as having
  moved.
- **A condition whose pass rate moves is responding to the host label**, and for a history-relative condition
  the size of the movement estimates nothing.

Invariance is also the section's own correctness check. A rate that ought to be untouchable by relabelling and
moves anyway means the permutation did not do what this section claims.

Neither figure is a real-world false-positive rate, and stating one as such would be overclaiming.

## 3. Rank stability

**Question:** would the same run tomorrow, on slightly different data, produce the same order?

Bootstrap the population, hold out days, perturb parameters within their stated precision. Measure Spearman
correlation across the stream's full episode ordering.

**The harness subsamples rather than resampling with replacement, and says so in every report.**
`client_ip` is the join key into retained history *and* the denominator of every rarity strength, so a
duplicated host is not representable: it would collide with itself in history, or need a fabricated label with
fabricated history to go with it. An m-out-of-n subsample answers the same question without inventing data.
Read a reported correlation as "stable under losing a fifth of the population", not as a bootstrap interval.

A ranking that reshuffles under resampling is noise wearing an order. The current ordering would score near
zero at the episode level: ~90% of adjacent in-tier pairs tie on every substantive key (`CASE_STUDY` §12).
The `tie_group` field exists so this is visible rather than hidden — report the share of episodes that sits
inside a tie group, because that share is not ordered at all.

## 4. Volume and cost projection

**Question:** what does an operator receive, and what does it cost?

Run across at least one full week including a weekend. Published output has ranged 1,510 to 19,676 episodes per
day, tracking the academic week (`CASE_STUDY` §11), so a single weekday measurement is not a projection.

Report: episodes and queued hosts per day across the week; source query footprint; projected retained
growth against the storage ceiling; runtime.

## 5. Conjunction redundancy

**Question:** does adding a condition actually remove anything?

For any rule requiring more than one condition, report the realised joint rate against the product of the
marginals.

This exists because of a specific suspicion about the relationship family, which conjoins novelty and
population rarity and requires both — and produces the overwhelming majority of the stream. The reasoning was
that a service seen today for the first time is almost by construction one that few others use, so the
conditions must be near-redundant and the conjunction must remove almost nothing.

**The first measurement refuted the second half of that.** On 2026-08-09 the conditions were correlated —
realised joint 2.21% against a product of marginals of 0.79%, a lift of 2.80 — and the conjunction still
removed **77%** of what its loosest condition admitted. Correlated is not redundant, and this document had been
confusing the two. Relationship still dominates the stream, but because the other families are more selective
still, not because its own conjunction fails to filter. See `CASE_STUDY.md`, evaluations (2026-08-24-baseline-2026-08-09).

Those figures predate `baseline-calibration-v3`, which corrected the prevalence denominator and so moved every
rarity rate. Re-measured on the same day after the fix, the conjunction filters harder still — lift 2.87,
removing 81% of what its loosest condition admits. The refutation holds in the stronger direction. See
`CASE_STUDY.md`, evaluations (2026-08-25-r1-prevalence-denominator-baseline-calibration-v3).

The episode is the argument for the section. The claim was made here and in the dated design reviews that led
to this document, on reasoning alone, and one run of the harness overturned it. Those reviews are evidence and
are not edited, so they still carry the superseded version. **Report the realised joint rate directly.**
It is observable and needs no independence assumption. Pairwise
independence does not establish joint independence, so treat any independence check as a screen for redundancy
rather than a proof of anything — and treat a plausible story about redundancy as neither.

**The motivating rule no longer conjoins — updated 2026-08-26, `primary-detectors-v5`.** Novelty and
population rarity are still the two axes above, but `relationship_eligibility` no longer thresholds them
separately and ANDs the result: both are calibrated into empirical tail probabilities over the day's own
relationship population and combined into one joint strength before the single threshold is applied. There is
therefore no conjunction left on this rule for this section's method to measure — `evaluate.py` reports it as
one condition (`joint_moderate`) rather than a vacuous joint of one. The two axes are still recorded
side by side as `relationship_axes`, an unthresholded `Combinator.ANY` observation, purely so §2 can still ask
whether each carries host-specific information; §5 still reports its realised rate and marginal for the same
reason. The general question this section asks is unaffected and still applies to every rule that does
conjoin before thresholding — persistence, corroboration, the tier gates — and the episode above is kept as
the reason the question is asked at all, not as a description of the relationship family today. See
`CASE_STUDY.md`, evaluations (2026-08-26-i4-relationship-calibration-primary-detectors-v5).

---

## Producing one

```shell
python scripts/evaluate.py bundle --day 2026-08-21 --change "what changed" \
    --volume-start 2026-08-15 --volume-end 2026-08-21
```

The harness seeds an isolated database with retained history strictly before the day — the same `day < D`
boundary `replay_day.sh` uses, from the same code — and scores that day repeatedly through the real pipeline
under injection, permutation, subsampling and parameter perturbation. It never writes to the database it
scores against.

Two things about it are worth knowing before reading a result:

- **Day D is reconstructed from the retained grains by default.** That costs no live query and works after the
  source's detail has expired (the original source kept about fifteen days; here a day stays while it is
  loaded, unless `NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS` sets a retention), but no DNS observation is retained,
  so the DNS family produces nothing and any figure for it is a floor. `--source` re-derives the day in full.
- **§5 is measured from the engines themselves**, through a write-only recorder at each decision site
  (`src/network_behaviour/instrumentation.py`). A harness that recomputed the conditions would keep scoring the
  old rule after the engine changed.

## Reporting

A bundle is a dated Markdown file named for the change, written to `docs/evaluations/` (`--output` moves
it). That directory is git-ignored, because a bundle measures a real day; the repository's
`docs/CASE_STUDY.md` reports what the bundles found. A bundle states the five sections, the
data range measured, what was not measured and why, and a plain verdict: does this change improve the output,
leave it unchanged, or degrade it in exchange for something named.

Bundles are evidence, not authority. They do not amend the contract and they are never edited after the change
ships — a superseding measurement is a new bundle that references the old one.

## What cannot be measured here

Stated so no bundle implies otherwise. There is no ground truth, no asset inventory, no incident history, and
no payload, TCP state, process, user or DNS query-name context. Therefore:

- **Precision is unknown** until dispositions accumulate somewhere, and dispositions drawn only from whatever a
  downstream stage selects are selection-biased: a re-ranker fitted on those labels alone will learn to
  reproduce the current selection. An unbiased estimate of what a downstream stage misses requires that stage
  to sample outside its own selection — nothing in this repository does that today.
- **Recall against real compromise is not measurable.** §1 measures sensitivity to synthesised behaviour, which
  is a statement about the instrument, not about the threat.
- **No bundle establishes that any host is compromised.** The honest summary of a complete bundle is "a
  characterised instrument with a stated sensitivity envelope and a known blind spot."
