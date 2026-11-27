# Case study: a large Australian university's network

I designed, built and ran this pipeline on a large Australian university's network from July to November 2026,
as part of the university's security project. It read the network's commercial flow probe through a read-only
ClickHouse account. This page records what that deployment measured, what each measurement decided, and what
the system produced. It reports aggregates only: no campus address or name, no indicator and no source row from
that network is in this repository.

- **Dates** are UTC, and every value carries the date it was measured. The record was re-verified on
  2026-10-22 and 10-23, every section but §6 and §16 re-measured or re-read; §17 and §18 were added on
  2026-11-13. A value that changed or proved wrong is kept under [Superseded values](#superseded-values),
  because parameters were fitted on some of them.
- **Names.** The probe's tables appear under the names this repository gives them: `flow.activity_1m` (minute
  rows per address, server and name), `flow.host_load_5m` (five-minute load per address), `flow.long_flows`
  (sessions of 1 MB or more) and `flow.dns_pairs` (hourly DNS counters per client and resolver).
  [`SOURCE_CONTRACT.md`](SOURCE_CONTRACT.md) describes their columns. `history.*` and `feed.*` are the
  pipeline's own retained store.
- **Method.** Bounded, aggregate-only, read-only queries through `ReadOnlyQueryRunner`, and read-only reads of
  the retained store. Only counts, cardinalities and quantiles were read out. No field-level documentation of
  the probe is public (checked 2026-10-22), so every meaning here was measured, not looked up.
- **Citations.** The code cites this page as `CASE_STUDY §N`. The numbering is fixed, so a citation stays valid
  when a section is rewritten. The values describe one network in 2026; a deployment elsewhere measures its
  own.

## The deployment at a glance

| | Value | § |
|---|---|---|
| Minute rows (`activity_1m`) | 27–34 M a weekday, 24–28 M a weekend day | 1 |
| Long flows | 380–640 K a weekday, 210–430 K a weekend day | 1 |
| DNS | about 155 K hourly rows a day, carrying 10.8 M complete sessions | 1 |
| Addresses observed | about 11,500 a day (11,492 on 2026-10-21) | 2 |
| … with any traffic that can be interpreted | 4,331 of those; the rest carried only rows with no server, port or domain | 2, 3 |
| … scored | a median of 2,799 on a Saturday to 4,490 on a Tuesday | 2 |
| DNS clients | about 308 addresses a day sent queries | 9 |
| Source detail | about 15 days of minute rows; long flows and DNS for longer | 1 |
| Query limits | 200 M rows read per query; parameter arrays of about 1,000 addresses | 1 |
| Retained store | 365 days of history allowed on a 60 GiB volume; at the end, 104 days of history and 92 published days in 4.7 GiB | 11 |

## What the measurements decided

Paths in the last column are relative to each package's source directory, as in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

| Measured | Decided | In code |
|---|---|---|
| Half the minute rows have no server address, port or domain. Every address carries them in nearly every minute, and most addresses carry nothing else (§2, §3) | Transfer and fanout score only addresses with a service row, and draw their peers from those alone; DNS keeps its own population (`behavioural-support-v3`, `baseline-calibration-v7`) | `population.py`, `baselines/engine.py` |
| Over a 7-day median, 98.98% of addresses are active in all 1,440 minutes of the day (§3) | Active minutes no longer split peer bands, and a cohort under 40 gets no peer percentile (§4) | `baselines/engine.py` |
| Every step in the address count was among addresses with only those rows; the scored population follows the week (§2) | The drift gate compares the scored population with the same weekday, at 0.35 (`drift-gates-v2`) | `drift.py` |
| About 308 addresses a day send DNS queries, beside unsolicited responses to up to 64,000 others and a few campus DNS servers (§9) | DNS scores only clients that sent a query, leaves out any that queried 100 or more resolvers, and has its own population gate | `detectors/dns.py`, `drift.py` |
| A minute row records an occupied minute, not a connection: 93.7% of regular-looking pairs are contiguous blocks of minutes, not schedules (§10) | A schedule needs a mean gap of at least 1.5 minutes, or 2 five-minute buckets | `contact.py`, `evaluation/shadow.py` |
| 99.9% of long flows pass the 1 MB floor, and 92% of addresses with traffic of their own have one (§8) | A long flow corroborates only in the top 2.5% of the host's own, by size or duration (`episode-ordering-v4`) | `baselines/engine.py`, `ranking/engine.py` |
| About 90% of adjacent pairs inside a tier tied on every substantive key (§12) | `priority_score` is gone, and ties are published as `tie_group` | `ranking/engine.py` |
| Only long flows record who opened a session (§7) | No detector, rule or report says who opened a contact | `narrative.py` |
| Minute detail expires after about 15 days (§1) | 365 days of hashed history per address; ioc-report labels a match day past its window as expired, never as no contact | `publication.py`, `live.py` |
| The subscriber and tag columns are 1:1 aliases of the address, and the mobile identifiers are empty (§5, §6) | An address is not a device; the columns stay blocked | `source/sql.py` |
| 10 registered domains a day is the 99th percentile per server address (§14); 7 addresses and 9 days are the 90th percentiles of a name's use (§15) | E4 reads an address at 10 or more as shared hosting, and a name 7 addresses used on 9 days in the 90 days before the match as established | `rules.py` |
| Of 16 E3 contacts with a known age, 1 rested on a name registered under 32 days before (§16) | E3 is withdrawn for such a name. The window is Unit 42's, cited rather than fitted; this measured its cost | `rules.py` |
| No case was ever labelled | Model verdicts are evaluated and shown, never applied, and nothing is tuned to them | `shadow.py`, `evals/` |

## What it produced

**Triage**, read 2026-11-27 from the retained store:

| Published | Days | Episodes | A day: min · median · max |
|---|---|---|---|
| 2026-07-13 → 08-09, the first feed format | 25 | 227,418 | 1,510 · 9,752 · 19,676 |
| 2026-09-01 → 11-09, the evidence stream | 67 | 590,381 | 2,954 · 10,517 · 12,756 |

- The evidence stream ran under three detector generations: `primary-detectors-v7` for 45 days, `-v8` for 4 and
  `-v9` for 18. [Evaluations](#evaluations) has what each change measured. Published days are never re-scored.
- Retained history held 104 days, 2026-06-29 → 11-09: 1,117,813 address-days and 34,429,752
  address-service-days, in 4.7 GiB. The 30 days missing from that span are listed in §11.

**IOC reports**, counted 2026-11-27 from each feed's latest run (2026-10-24 → 11-06):

- 11 IOC-match feed files, 10 of ThreatFox matches and 1 of Amazon Threat Intelligence's PHP2Shell exploit
  sources, held 2,173 match records, 2,092 of them in one feed. NanoCore accounted for 2,099 of the 2,141
  records held on 2026-10-21.
- They formed 89 (indicator, host) cases on 74 campus addresses and 34 indicators. **Code explained 73 and kept
  16 for review.** E1 and E2 together explained 34: contacts over UDP to a family whose C2 is TCP only, and
  contacts carrying the ECH outer name, which only browsers send. E3 alone explained 27; it is the rule §16
  qualified. 64 of the 89 were last run without the live source, whose minute detail had expired for them.
- Each of the 16 review cases got a one-page case report. Haiku drafted the paragraphs and code checked them;
  nine sentences across eleven of the reports were then corrected by hand.

**Model verdicts and spend:**

- Of the models the original evaluation screened, only Haiku 5.5 passed every bar. Its last run there, on 37
  cases, was 2026-11-06 (`packages/ioc-report/README.md`, "Evaluating model verdicts").
- In shadow mode on 2026-10-21 it read 15 live cases blind, 3 samples each, and agreed with code on 13. On one
  it said review in all 3 samples where code explained the case by E3. The registration-age check (§16) later
  turned exactly that case to review in code. On the other, its samples split 2 to 1 and the majority agreed
  with code.
- Beside that: on this repository's 27 synthetic cases and the published prompt (2026-11-26), Haiku failed two
  bars, usefulness (7 of 9) and twin pairs (6 of 8). Both failures are in the safe direction: it kept two cases
  the rules explain in review, and it cleared no case that must stay in review.
- External model spend for the whole project, this repository's runs included, was $0.88. A case report costs
  under half a cent, and an evaluation run of 81 to 111 calls $0.044 to $0.066.

**A third track, not carried here.** In its last days the deployment also wrote exposure reports from CISA's
Known Exploited Vulnerabilities catalogue, for entries naming a product it knew, from the same four tables. No
record shows a software version, so code decided only `candidate` or `no signal`, never "affected": a
candidate served on the product's ports (§7, §17) and had used the product's own domains. Advisories for PHP,
OpenSSH and WordPress produced 4, 10 and 1 candidates. Nothing was labelled.

## What could not be established

- **Labels.** No episode, case or host was ever labelled, so no accuracy, precision or recall is known for
  anything here. Triage's evaluation measures sensitivity to injected behaviour, never recall (§13), and
  ioc-report's evaluation screens models on synthetic cases. That is why model verdicts are shown and never
  applied.
- **Direction.** A minute row never says who opened a session. Long flows do, but most of a serving host's
  counterparts had no long flow, so their direction is unknown. Sessions the remote side opened are scored as
  the host's own (§7).
- **What the unaddressed rows count.** Half the probe's minute rows carry no server address, port or domain.
  They are not inbound sessions, and no field-level documentation of the probe is public (§3).
- **Smaller questions left open:** what sent the unsolicited DNS responses, and what the 2026-07-23 DNS burst
  was (§9); why one direction count did not reproduce (§7); whether episodes on a host's own served site
  should be marked (§18).

## Measured facts

The rest of this page is the record the code cites: each section's measurements, dated, and what they do not
establish.

### 1. Source shape and retention

| Fact | Value | Measured |
|---|---|---|
| `activity_1m` retention | about 15 days: the earliest row was 2026-10-07 09:40 when read 2026-10-22 13:35, and 2026-08-07 when read 2026-08-22 | 2026-10-22 |
| `activity_1m` rows a day | 27–34 M on weekdays, 24–28 M at weekends (32,198,835 on 2026-10-21) | 2026-10-22 |
| `long_flows` rows a day | 380–640 K on weekdays, 210–430 K at weekends (599,606 on 2026-10-21); rows back to at least 2026-09-20 | 2026-10-22 |
| `long_flows` reach | the earliest start was 2026-09-03: 63 distinct days to 2026-11-04, probed from 120 days back | 2026-11-13 |
| `dns_pairs` rows a day | about 155 K, carrying 10.8 M complete sessions (155,051 on 2026-10-21); rows back to at least 2026-09-20, and the earliest from 2026-04-01 (§9) | 2026-10-22 |
| Rows one query may read | 200 M, refused on the server's estimate before any row is read | 2026-10-22 |
| Largest parameter accepted | an array of 1,060 addresses passed; one of 7,277 was refused before running | 2026-11-13 |

**Consequence.** Minute detail expires in about two weeks. A day older than that cannot be re-derived, only
replayed from retained history, so backfill and re-calibration windows must fit inside it. Long flows outlive
the minute rows, so ioc-report's long-flow re-query, and K5 with it, outlives its minute window.

### 2. Population

| Fact | Value | Measured |
|---|---|---|
| Distinct `client_ip` a day | 12,234 on 2026-08-09; 11,492 on 2026-10-21 | 2026-10-22 |
| … the first step | 12,238 → 5,229 (2026-08-10 → 08-11), then 6,282 on 08-17 | August 2026, while the source held those days |
| … the second step | 10,579 → 5,655 → 6,135 (2026-09-13 → 09-15 → 09-17) | 2026-10-22 |
| … rising again | 6,272 → 7,915 (09-19 → 09-20) · 8,361 → 9,885 (09-26 → 09-27) · 10,279 → 11,303 (10-10 → 10-11) | 2026-10-22 |
| Addresses with 100 or more flows a day | 4,033 of 11,492 | 2026-10-21 |
| Addresses with any addressed row (§3) | 4,331 of 11,492 | 2026-10-21 |
| Addresses with a service row, by UTC weekday (median since 2026-09-16) | Mon 4,317 · Tue 4,490 · Wed 4,449 · Thu 4,243 · Fri 3,664 · **Sat 2,799** · Sun 3,525 | 2026-10-23 |
| … day-over-day movement, 75 consecutive retained pairs | median 13.0%, p90 26.0%, max 33.8% | 2026-10-23 |
| … against the last retained day with the same weekday, 75 pairs | median 1.67%, p90 4.26%, max 30.87% (2026-10-04 → 10-11, the public-holiday rebound); at most 5.4% outside the weeks around that holiday | 2026-10-23 |
| Values of the probe's network-segment tag | 1 | 2026-10-21 |

Days up to 2026-10-06 are read from `history.client_day`, later ones from the source; the two agree on every
complete day both hold (2026-10-08..18). The weekday and movement rows are read from
`history.client_service_day`, 2026-06-29 → 10-18.

**Every step in the distinct-address count is in addresses with no service row.** The scored population, the
addresses with at least one service row, did not step at either seam:

| Day | Distinct `client_ip` | With a service row | Only unaddressed rows (§3) |
|---|---|---|---|
| 2026-08-09 (Sun) | 12,234 | 3,523 | 8,711 |
| 2026-09-01 (Tue) | 10,221 | 4,278 | 5,943 |
| 2026-09-13 (Sun) | 10,579 | 3,498 | 7,081 |
| 2026-09-16 (Wed) | 5,987 | 4,454 | 1,533 |
| 2026-09-19 (Sat) → 09-20 (Sun) | 6,272 → 7,915 | 2,772 → 3,525 | 3,500 → 4,390 |
| 2026-10-10 (Sat) → 10-11 (Sun) | 10,279 → 11,303 | 2,816 → 3,663 | 7,463 → 7,640 |

The halving of 2026-08-10 → 08-11 (while flow volume rose from 20.9 M to 25.0 M) is outside retained history,
but 2026-08-09 → 09-01 brackets it and shows the same: the scored population rose. The falls are upstream
changes in how many addresses carry an unaddressed row, not in the population any detector scores. The rises
between them combine those changes with the weekly cycle of the scored population.

**What the denominators are.** Relationship and persistence prevalence count the addresses in
`history.client_service_day` (since `baseline-calibration-v3`), and relationship rarity is a rank within the
day (since `baseline-calibration-v4`). DNS resolver novelty divides by the day's own DNS clients (§9). None of
them is the distinct-address count. The drift gate watches the scored population against the same weekday
(since `drift-gates-v2`).

The network-segment tag carries a single value, so it offers no segmentation.

### 3. Activity shape: why the population is not a population of hosts

| Fact | Value | Measured |
|---|---|---|
| Active-minute quartiles across 11,492 addresses | 1,440 · 1,440 · 1,440 · 1,440 | 2026-10-21 |
| Addresses active in all 1,440 minutes | 10,569 (92.0%) | 2026-10-21 |
| `activity_1m` rows with `flow_count = 0` | 16,495,413 of 32,198,835 (**51.2%**) | 2026-10-21 |
| … with no `server_ip`, `server_port` 0, no `root_domain` and the application label `Web Browsing` | **all** 16,495,413 | 2026-10-21 |
| Rows with `flow_count > 0` and no `server_ip` or port | **0** | 2026-10-21 |
| Addresses carrying an unaddressed row / any addressed row | 11,492 / 4,331 | 2026-10-21 |
| Observed addresses with no service row, per retained day | median 64% (p10 56%, p90 73%); 60–75% on 71 of 104 days; from 26% (2026-09-16, the day after a step, §2) to 77% | 2026-11-27, retained days 2026-06-29 → 11-09 |
| `history.client_day` rows passing the retired client support gate | 12,231 of 12,234 (99.98%) | 2026-08-09 |
| Per-address median `active_minutes`, the 7 days ending 2026-08-09 | 1,440 for 98.98% of 12,235 addresses | 2026-09-08 |
| The lowest destination band's peer pool | 6,967 members, 6,801 of them with only unaddressed rows; 166 addressed hosts were ranked against it | 2026-10-23, over 2026-10-14 |
| Published episodes on addresses with only unaddressed rows | 11 of 390,056, 2026-09-01 → 10-18 | 2026-10-23 |

**Every address carries an unaddressed row in nearly every minute.** `flow_count = 0` marks exactly the rows
with no server address, no port and no domain, all labelled `Web Browsing`. 16,495,413 of them over 1,440
minutes is 11,455 a minute, against 11,492 addresses, and they moved 136 GB up and 334 GB down on 2026-10-21.
What they count is not documented and was not established. They are **not** inbound sessions: sessions the
remote side opened appear as addressed rows with `flow_count > 0` (§7). 7,161 addresses appear only in
unaddressed rows, so the population is address space, not devices.

**Consequences.**
- `active_minutes` is effectively constant, because the unaddressed rows occupy almost every minute. As a
  peer-band dimension it separated nothing, and as a support criterion it admitted everyone: the 1st
  percentile of an address's active five-minute buckets was 288, the daily maximum. It was retired as a band
  dimension in `baseline-calibration-v6`.
- `flow_count` is zero on half the rows, the unaddressed ones, so a gate whose other arm is a flow count is
  carried by the other arm alone. The two arms of the retired client support gate disagreed by a factor of
  about three: 11,492 addresses by buckets, 4,033 by flows (2026-10-21).
- Until `behavioural-support-v3`, the transfer and fanout families scored and pooled these addresses, so a
  quiet addressed host was ranked against traffic that cannot be interpreted.

### 4. Peer-band occupancy

The contract's band edges (bytes 1 MiB / 10 MiB / 100 MiB / 1 GiB; minutes 15 / 60 / 240 / 720; destinations
5 / 20 / 100 / 500) applied to the 4,033 addresses with 100 or more flows on 2026-10-21. Approximate: the
engine bands historical medians, and this bands one day's totals.

| Fact | Value |
|---|---|
| Occupied bands | 23 of 125 |
| Largest band | 1,196 addresses (29.7%), the top band on all three axes |
| Addresses in bands with n < 50 | 218 |
| Addresses in bands with n < 20 | 74 |

The minutes dimension is degenerate: nearly the whole population sits in its top bucket.

**Arithmetic consequence.** A midpoint-rank percentile over `n` peers cannot exceed `(n − 0.5)/n`, so a cohort
of 50 tops out at 99.0, of 20 at 97.5 and of 10 at 95.0. Where `metric_strength = min(self, peer)`, an address
in a small cohort cannot reach the eligibility thresholds, whatever it does.

**Re-measured 2026-09-08 on the engine's own inputs:** `history.client_day` over 2026-08-03..09, 12,235
addresses, the 7-day median per address, banded on bytes and destinations alone. The 2-dimension column was
reproduced exactly from retained history on 2026-11-27.

| Fact | 3 dimensions (bytes, minutes, destinations) | 2 dimensions (minutes dropped) |
|---|---|---|
| Occupied bands | 23 of 125 | 18 of 25 |
| Largest band | 8,359 addresses (68.3%) | 8,360 (68.3%): under 5 destinations and 1–10 MiB a day. The next is 1,505 (12.3%) |
| Addresses in bands with n < 50 | 155 | 91 |
| Addresses in bands with n < 40 | not measured | 91, in 4 bands (no band sits in [40, 50)) |
| Addresses in bands with n < 20 | 44 | 6, in 1 band |

Dropping the degenerate minutes dimension roughly halves the addresses in an unusably small cohort at every
floor checked, because it stops splitting cohorts the other two axes already separate. This is the basis for
`bands.min_cohort` (40) and for retiring `bands.minute_edges`, both in `baseline-calibration-v6`.

### 5. Field availability

Measured over the 1,845,450 `activity_1m` rows of 2026-10-21 00:00–01:00, 686,951 of them unaddressed (§3).
Counts of populated values only; no value was read.

| Field | Populated |
|---|---|
| The seven mobile subscriber identifier columns | **0** each |
| `root_domain` | 1,142,128 (61.9% of all rows; 98.6% of addressed rows, since no unaddressed row carries one) |
| `sni` | 1,107,205 (60.0%) |
| `dns` | 37,295 (2.0%) |
| User agent | 5,523 (0.4%) on 2026-08-20; not re-measured, because `source/sql.py` blocks the column even inside an aggregate |

The mobile identifiers are genuinely absent. Browsing destinations tied to an address are present at minute
grain.

**`application` is mostly a domain name, not a product.** On 2026-11-04 (measured 2026-11-13, addressed rows),
16,566 of 16,804 distinct (`application_category`, `application`) labels repeated the first label of a
registered domain on their rows: 12,280 of 12,317 in category `_unknown`, and 4,286 of 4,487 in a named
category. A label that names a company says a host reached that company's domain, not that it runs the
company's product, and printing labels prints domain names.

`server_port` by distinct address, same hour: unknown (0) 11,474 · system (below 1024) 3,352 · registered 347 ·
ephemeral 86. Every unknown row is an unaddressed row (§3), and `server_port` is the remote side's port (§7).
The port is unknown for most addresses, so port-group fanout rests on a sparse field. No row carries
`server_port` 53 (2026-10-14 and 10-21, measured 2026-10-23): DNS is not in this table at all, only in
`dns_pairs` (§9).

### 6. Identity

| Fact | Value | Measured |
|---|---|---|
| Distinct `subscriber_id` / `client_ip` / pairs, over 4 days | 6,392 / 6,392 / **6,392** | 2026-08-15 → 08-18 |
| Subscribers seen on more than one address | **0** | same |
| `long_flows`: distinct `client_tag` / `client_ip` | 2,073 / 2,073, none equal | 2026-08-18 |

`subscriber_id` and `client_tag` are strict 1:1 aliases of the address, and neither offers continuity across
reassignment. With the mobile identifiers empty (§5), no source field offers more continuity than the address
itself. Only cardinalities were read, once, and
the answer is recorded here so the query need not be repeated: `source/sql.py` blocks these columns, and the
guard stays, because unblocking them buys nothing and would remove a control that matters if the source ever
changes. Not re-measured on 2026-10-22, because it needs the blocked columns.

### 7. Direction and role

| Fact | Value | Measured |
|---|---|---|
| `long_flows` rows with a campus address as `server_ip` | **0** of 13,945,676 | 2026-09-20 → 10-22 |
| `long_flows` rows with a campus address as `client_ip` | all 13,945,676 | same |
| `activity_1m` rows with a campus address as `client_ip` / as `server_ip` | all 32,198,835 / **0** | 2026-10-21 |
| A column recording direction or the campus port in `activity_1m` | **none** | 2026-10-22 |
| `long_flows.initiator` values | `client`, `client_guess`, `server`, `server_guess`, on every day | 2026-09-20 → 10-22 |
| Rows per `initiator` value | `client` 6,587,645 · `client_guess` 119,682 · `server` 104,519 · `server_guess` 16,415 | 2026-10-07 → 10-21 |
| `initiator = 'server'` rows with `client_port` below 1024 | 102,828 of 104,519 (98.4%) | same |
| `initiator = 'server'` rows on 2026-10-21 | 6,854 on 49 addresses; with `client_port` 80, 443, 8080 or 8443 and the remote port 1024 or above, 6,006 on 26; `server_guess` 746 more | 2026-10-22, the same when re-read 2026-10-23 |
| Remote-opened web long flows also in `activity_1m` (same address pair, same day) | 4,174 of 4,175 pairs, all with `flow_count > 0` | 2026-10-21 |
| … whose minute row's `server_port` is the remote side's port / the campus port | **4,174 / 0** | same |
| Control: campus-opened long flows to remote 80/443, same test | 136,568 of 136,569 on the remote port, 0 on the campus port | same |
| Long flows with the remote port 1024 or above, by `initiator` | `server` 6,854 of 6,854 · `server_guess` 743 of 746 · `client_guess` 3,428 of 8,189 · `client` 370 of 584,152 | 2026-10-21, measured 2026-10-23 |
| Addressed minute pairs of the 49 hosts with a remote-opened long flow that have no long flow at all | 30,967 of 36,065 (85.9%), carrying 27.8 GB of their 294 GB (9.4%); 26,396 of them on a remote port of 1024 or above | 2026-10-21, measured 2026-10-23 |
| Published episodes on host-days where remote-opened long flows carry most of the host's long-flow upload | 0.9% of 390,056 (2026-09-01 → 10-18), and 7.7% of persistence episodes | 2026-10-23 |

**The probe oriented the campus side as the client in every row measured in both tables, whichever side opened
the session.** `server_port` is the remote side's port. Sessions the remote side opened are recorded in
`activity_1m` like any other addressed traffic, with `flow_count > 0`, the remote address as `server_ip` and
the remote's port as `server_port`. Nothing in that table says which side opened the connection or which
campus port it reached, so a minute row with `server_port` 80 means the remote side's port 80, and direction
cannot be read there.

**`long_flows` records direction, for long flows only.** Its `initiator = 'server'` rows have the campus side
on a service port (80, 443, 22, 5900, …) in `client_port`, and the remote side on an ephemeral or registered
port: sessions the remote side opened. Direction is therefore measured only on sessions long enough to become
long flows. A named site served to many outside networks is also visible in retained history, without a
direction column, by the shape §17 measures against this one.

**What this does not establish.**
- **Most of a serving host's counterparts have no long flow, so their direction is unknown.** For the hosts
  that received remote-opened long sessions on 2026-10-21, 85.9% of their addressed minute pairs had no long
  flow at all (9.4% of their bytes). Most of those sit on a remote port of 1024 or above, the shape every
  `server` long flow has, but on short sessions nothing confirms the direction: the port is a proxy, not a
  measurement.
- The `_guess` values are undocumented, presumably a direction the probe inferred rather than saw. The counts
  above leave `server_guess` out.
- Nothing checks that every inbound long session is labelled `server` or `server_guess`.
- The 2026-10-21 count first read on 2026-10-22 (5,752 on 23 addresses) did not reproduce. Every later reading,
  later that day and again at 03:16 on 2026-10-23, gave 6,854 on 49, so the first reading is the outlier, and
  why it differed is unknown. Late arrival does not explain it: §8 puts long flows still open at processing
  time at 0.1–0.4% of a day's rows.

### 8. Long-flow evidence

| Fact | Value | Measured |
|---|---|---|
| `long_flows` rows with `up_bytes + down_bytes >= 1000000` | 599,011 of 599,606 (**99.90%**); at least 99.84% on every day 2026-09-20 → 10-22 | 2026-10-21 |
| Addresses with at least one qualifying flow | 3,987: 34.7% of the 11,492 observed, **92.1%** of the 4,331 with any addressed row (§3) | 2026-10-21 |
| Long flows starting on day D still open at D+1 08:00, when D is first processed | 0.10–0.37% of the day's rows (607–1,399), every day 2026-10-09 → 10-21; all of them qualifying | 2026-10-23 |

The table already contains only long flows. The mandatory 1 MB filter removes about 0.1% of its rows; it is not
a selective filter. Nearly every address with traffic of its own carries a qualifying flow, which is why
presence alone could not be a corroboration route.

#### What a large flow looks like in retained history

Read 2026-08-31 from `history.client_service_day` and `history.client_day` over 2026-08-09, with reference
pools from the preceding 90 days. These are what `long_flow.corroboration_strength` was fitted against.

| Fact | Value |
|---|---|
| Service-days carrying a large flow | 29,488 of 156,933 (**18.79%**) |
| Client-days carrying a large flow | 3,036 of 12,234 (**24.82%**) |
| `max_large_flow_bytes` among them | p50 4.8 MB · p90 44.8 MB · p99 425 MB |
| `max_large_flow_duration_sec` among them | p50 **24 s** · p75 149 s · p90 1,364 s · an hour or more 1,553 (5.3%) |
| Units in the top 2.5% of their own host's prior large flows, by size **or** duration | 1,132 (**3.84%**) |
| … by size / by duration / by both | 758 / 394 / 335 |
| Units whose host has fewer than 40 prior large flows to compare against | 666 (**2.26%**) |

**A "large flow" is usually neither large nor long.** Half of them move under 5 MB and last under half a
minute: the 1 MB filter admits nearly everything the table holds, and the table is the term's only source.
Measured against the flows the same host has already made, only 3.84% are unusual for it.

**Repetition does not work as a qualifier, measured on both sides.** Of the 22,644 (client, service) pairs
carrying a large flow on 2026-08-09, 19,989 (88.3%) had a prior day carrying one too, so requiring repetition
would remove almost nothing. And 1,861 (8.2%) were first contacts, where a prior day cannot exist by
construction: precisely the units the relationship family is built to surface. Size and duration are the two
axes that survive, and they are close to independent: 335 units of a possible 1,132 qualify on both.

### 9. DNS coverage

Measured 2026-10-23 on `dns_pairs`. A **DNS client** is an address that sent at least one query that day, and a
**DNS server** is a client-day that queried 100 or more distinct resolvers.

| Fact | Value |
|---|---|
| `dns_pairs` retention | earliest row 2026-04-01 01:00 |
| DNS clients a day, servers left out | median 308, range 209–574, 2026-07-01 → 10-22 |
| … by UTC weekday since 2026-09-01 (median) | Mon 312 · Tue 319 · Wed 326 · Thu 308 · Fri 276 · **Sat 221** · Sun 250 |
| … against the same weekday a week earlier, 107 pairs | median 4.8%, p90 14.9%; 70% on 07-23, 43% on 07-30, 32% on 09-21, 24% on 09-14, 21% on 10-12 |
| … on 2026-10-14 and on 2026-10-21 | 324 and 324 |
| Addresses that sent no query and received one unsolicited response | 31,000–64,000 a day in late July; 804 of the 1,057 addresses on 2026-08-30; 10,669 on 10-03; 864 on 10-14; **0** on 10-21 |
| Share of 2026-10-08..14's complete sessions carried by clients still present after 10-16 | **99.8%** |
| Resolvers queried per client-day with a query, p50 / p90 / p99 / p99.9 | 3 / 4 / 2,238 / 18,374, 2026-07-01 → 10-22 |
| … client-days at 10–99 / 100–999 / 1,000 or more resolvers | 556 / 10 / 421; the last two on 7 addresses |
| DNS servers a day, and their share of complete sessions | 3–5; 15–31% |
| Sessions per client-day, servers left out, p50 / p90 | about 30 / 800–1,650; 37–44% reach 50 sessions, and 47–49% reach 100 query packets |
| Sessions per queried (client, resolver) pair-day, servers left out, p50 / p75 | 12–15 / 24–26 |
| `activity_1m` rows with `server_port` 53 | **0**, on 2026-10-14 and 10-21 (§5) |
| Client-days with complete or unanswered sessions and no query packet | **0**, against 34,123 query-sending client-days, 2026-07-01 → 10-22 |
| DNS clients on Thursdays | 07-09 360 · 07-16 337 · **07-23 574** · 07-30 329 · 08-06 348; every hour present each day |
| … of 07-23's, seen on neither neighbouring Thursday | 347, a median of 2 query packets to 1 resolver, mostly from 16:00 |
| The probe's response-code column | −1 on every row, every day 2026-09-20 → 10-22 |

**The DNS table holds two populations.** About 308 addresses a day send queries; that population is stable
and follows the week. Beside it, a varying number of campus addresses appear only because each received a
single unsolicited DNS response and sent nothing: from none to 64,000 a day, 10,669 of them on 2026-10-03, when
two remote addresses each reached thousands of campus addresses. Most are not even observed in `activity_1m`
that day. They read as backscatter; what sends them was not established, and nothing in the product labels it.
Nothing collapsed on 2026-10-16: that is the day the unsolicited responses stopped, and the clients that query
carried on unchanged.

**A few clients are DNS servers.** Seven campus addresses query thousands of resolvers a day: they are campus
resolvers asking authoritative servers, where an ordinary client queries three or four. The gap is two orders
of magnitude wide.

**DNS is visible only here.** `activity_1m` carries no port-53 row, so no other table shows a DNS exchange or
its direction. The DNS table carries no query names or record types, and its response code is −1 on every row,
so it carries no response codes either.

**What the DNS family scores** (`primary-detectors-v8`): the clients that sent a query, servers left out, in
day D and in history. `drift.dns_population_step_fraction` watches that population against the same weekday
(`drift-gates-v3`). Until v8, every address in the table counted: the unsolicited-response addresses were most
of novelty's denominator (about 1,100 in September and October, up to about 64,000 in July, about 300 after
10-16), and the DNS servers carried 129 of the 335 DNS episodes published 2026-09-01..10-18.

**The July moves are one spike and its rebound.** On 2026-07-23, 347 addresses that queried on neither
neighbouring Thursday each sent about two queries, mostly in the afternoon, with ingestion complete all day.
2026-07-30's 43% move is measured against that spike; against 07-16 it is 2%.

**A query packet misses no client.** No client-day in 2026-07-01 → 10-22 carried a complete or unanswered
session without a query packet.

**What this does not establish:** what the 2026-07-23 burst was, and what the unsolicited responses are.

### 10. Timing structure

Measured on `(client_ip, server_ip)` pairs with 12–400 distinct active minutes in the day. `CV` is the
coefficient of variation of the gaps between active minutes. 2026-08-18 is the day
`timing.min_mean_gap_minutes` was fitted on; 2026-10-21 was measured on 2026-10-22.

| Condition | 2026-08-18 | 2026-10-21 |
|---|---|---|
| Base: 12 to 400 active minutes | 173,707 | 176,119 |
| `CV < 0.15` | 6,656 | 7,421 |
| … of which the mean gap is under 1.5 minutes (**contiguous, not scheduled**) | **6,234 (93.7%)** | **6,585 (88.7%)** |
| … gapped and regular | 422 | 836 |
| + a span of 6 h or more | 111 | 153 |
| + under 50 KB per active minute | 74 | 110 |
| + a destination fan-in of 5 addresses or fewer | **8** (8 distinct addresses) | **12** |

The inter-contact periods of the 8 survivors on 2026-08-18 were **15, 16, 60, 60, 60, 60, 60 and 120 minutes**.
On 2026-10-21 fan-in was counted as distinct campus addresses per `server_ip` over the whole day, which may not
be how the 2026-08-18 count was taken, and the periods were not read.

**The caveat for any timing work.** `activity_1m` records occupied minute buckets, not connection events. A
held-open connection produces gaps of exactly one minute and a CV of zero, so a minimum mean gap is mandatory,
or the metric measures session continuity rather than scheduling.

### 11. Retained history and published output

From the retained store. The 2026-06-29 → 08-09 rows were read 2026-08-22 and re-read identically 2026-10-22;
the feed counts were corrected on 2026-10-22, and the last three rows were read 2026-11-27.

| Fact | Value |
|---|---|
| `history.client_day`, 2026-06-29 → 08-09 | 417,699 rows, 37 days |
| `history.client_service_day`, same range | 8,397,445 rows |
| Service basis mix, same range | `domain` 8,285,335 · `application_asn` 110,381 · `server_ip` 1,729 |
| Published feeds, 2026-07-13 → 08-09 | 25, all non-empty, 227,418 candidates, all `daily-candidate-feed-v1` |
| Candidates a day, same range | 1,510–19,676 (median 9,752) |
| 2026-08-05 | 10,156 candidates over 1,799 addresses; relationship 96.2%; P1 3,100 (30.5%) |
| The whole store on 2026-10-22 | `history.client_day` 857,684 rows over 82 days, 2026-06-29 → 10-18; `history.client_service_day` 25,441,014 rows; 70 published days, 617,474 episodes, two feed schema versions |
| The whole store at the end | 104 retained days, 2026-06-29 → 11-09: `history.client_day` 1,117,813 rows, `history.client_service_day` 34,429,752; 92 published days, 817,799 episodes; 4.7 GiB |
| Days missing from the retained span | 07-03, 07-08, 07-29 → 07-31, 08-10 → 08-31, 09-03, 09-14, 09-15: 30 days |
| Evidence-stream episodes a day, by UTC weekday (median, 2026-09-01 → 11-09) | Mon 11,342 · Tue 12,398 · Wed 11,440 · Thu 10,916 · Fri 7,772 · **Sat 3,322** · Sun 6,012 |

**Published volume follows the week**: a weekday carries three to four times a Saturday, so a single weekday is
not a projection of a week. 2026-09-14 and 09-15 failed the source-completeness check, with 438 and
1,276 of 1,440 minutes ingested.

History confidence flipped for nearly every address between two consecutive days (2026-08-03: 12,586 `normal`,
0 `mature`; 2026-08-04: 51 `normal`, 10,826 `mature`), because retained history began on 2026-06-29 and those
addresses crossed the 31-day boundary together. Confidence by history depth was a deployment clock, not a host
property.

### 12. Implementation facts

Static reads of the code, first 2026-08-22, re-read 2026-10-22 and again 2026-11-27 on this repository.
Recorded because they contradict, or once contradicted, the contract.

| Fact | Where |
|---|---|
| Four evidence codes (8, 10, 11, 12) were declared and never emitted, confirmed statically and by their absence from 47,692 published evidence rows. Removed in `domain-codes-v3`; the four codes are retired and never reused | `domain.py` |
| A qualified large flow is the **only** corroboration route to the top tier. E1 is otherwise reached by two strong families | `ranking/engine.py` |
| Baselines get a default source-quality input. The only caller that sets one is the DNS coverage check, and it sets only whether DNS context is available (`drift-gates-v3`), so data-quality confidence is constant by construction | `operations/scoring.py`, `operations/pipeline.py` |
| The best episode per address is computed in ranking and read only by the evaluation harness, never by publication | `ranking/engine.py` (`_client_view`), `evaluation/harness.py` |
| The ordering key ends in the episode's UUID5 digest, and the tie key drops it, so episodes equal on every other term share a tie group | `ranking/engine.py` (`_tie_key`) |
| `priority_score` is gone from the stream; it survives only in the frozen v1 format | `feed/domain.py`, `feed/legacy_v1.py` |

**Most of the ordering inside a tier is a tie-break.** On the first feed format (July and August 2026), about
90% of adjacent pairs inside a tier tied on every substantive key and were separated only by the digest. Its
`priority_score`, a linear interpolation of rank position, took 21 distinct values across 3,100 episodes, 155
sharing each. Ties are now published as `tie_group`. The share of the host queue inside one was 55.5–70.2% in
the August bundles, and 97.6% of the 2026-10-14 stream sat in one ([Evaluations](#evaluations)).

The v1 contract described three supporting-context mechanisms, and two did not exist. Matching large flows
were therefore the only corroboration route to P1, which is why 3,011 of the 3,100 P1 episodes on 2026-08-05
were a new relationship plus a large flow.

### 13. Shadow beacon profile

Measured 2026-09-08 on `history.client_service_day` over 2026-08-09 (156,933 rows), with no live query, and
reproduced exactly on 2026-10-22 (`scripts/evaluate.py shadow --day 2026-08-09`).
`network_behaviour.evaluation.shadow.beacon_candidates` at its fitted defaults: `min_active_buckets=6`,
`max_active_buckets=80`, `max_cv=0.15`, `min_mean_gap_buckets=2`, `min_span_hours=6`,
`max_bytes_per_active_bucket=250000`, `max_campus_fanin=5`.

| Stage | Survivors |
|---|---|
| Evaluated | 156,933 |
| + a plausible contact count (6–80 buckets) | 32,360 |
| + low timing variation (CV < 0.15, mean gap of 2 buckets or more) | 714 |
| + sustained across the day (a span of 6 h or more) | 684 |
| + low volume per active bucket (under 250,000 B) | 605 |
| + a destination almost nobody else uses (fan-in of 5 or fewer) | **17** |

Selectivity is 156,933 → 17, about 1 in 9,231. The minute-grain measurement of 2026-08-18 (§10) was 173,707 →
8, about 1 in 21,713: a different day, a coarser grain here (5-minute buckets), and thresholds re-fitted rather
than rescaled, so the two are not directly comparable. The signature matches: 7 of the 17 survivors sit at
almost exactly 60-minute periods, as five of §10's eight did. `min_active_buckets` was swept from 3 to 8 before
settling on 6. Below it, pairs with only 3–5 active buckets pass the regularity stage by coincidence (a CV over
one or two gaps measures nothing), inflating survivors past the rarity stage from 17 to 45 at 3, with noisier,
less periodic candidates.

**All 17 candidates are `domain`-basis**: they resolved to a registered domain rather than falling back to an
ASN or a bare server address, the highest service-confidence tier. That is a statement about the evidence
basis, not about what the destinations are: no domain string is retained or read here.

**A client-label permutation null is structurally uninformative for this profile.** `beacon_candidates` reads
only a row's own bitmap, bytes and service, and campus fan-in groups by service, never by address. Relabelling
the hosts of 2026-08-09 and rescoring reproduced byte-identical funnel counts at every stage, and the same
candidates up to which label each carried; `test_a_client_label_permutation_is_a_structural_no_op` pins the
same result on a synthetic fixture. A null that tested something here would perturb the shape itself (which
minutes a host's existing contacts occupy, holding count and bytes fixed), and that is unbuilt.

**Sensitivity, each implant scored alone.** `measure_beacon_sensitivity` synthesises at the source grain and
scores the result directly, without merging it into a real day, which is exact by construction: each host gets
a distinct synthetic destination the population cannot already share. 20 hosts per cell, 2,000 bytes up per
contact.

| Period | 10 occurrences, no jitter | 10, ±5 min | 40 occurrences, no jitter | 40, ±5 min |
|---|---|---|---|---|
| 15 min | 0% | 0% | 100% | 0% |
| 60 min | 100% | 100% | 100% | 100% |
| 120 min | 100% | 100% | 100% | 100% |
| 240 min | 100% | 60% | 100% | 60% |

**The 15-minute row is a real boundary of the envelope, and it moves with the occurrence count.** At 10
occurrences a 15-minute period spans only 2.5 h, short of the 6 h floor, so it never surfaces. At 40 it spans
well past 6 h and surfaces every time without jitter, but drops to 0% at ±5 minutes, a 33% perturbation of a
15-minute period against 2% of a 240-minute one. Short-period beacons need more contacts to be seen at all, and
are more fragile to jitter once they are. **The 240-minute row is jitter-sensitive whatever the count:** ±5
minutes pushed 8 of 20 implants' CV over the 0.15 ceiling at both settings.

**What this does not establish.** One profile, one day, no look at benign lookalikes, no multi-day replay and
no held-out validation against a labelled set, none of which exists for this deployment. This is selectivity
at the pipeline's own grain, not against raw source rows. Matching the shape is not evidence that a candidate
is anything but a monitoring agent, an update checker or a licence heartbeat.

### 14. Address sharing

Measured 2026-10-15 for the days 2026-10-08 and 2026-10-14, and reproduced exactly on 2026-10-22, on
`activity_1m` rows with `flow_count > 0`: the rows with a server address, in either direction (§7), which
leaves out §3's unaddressed rows. Per server address: distinct non-empty `root_domain`, with the ECH outer name
`cloudflare-ech.com` left out, and distinct `client_ip`. Two queries, 29.7 M and 33.0 M rows, under a second
each.

| Fact | 2026-10-08 | 2026-10-14 |
|---|---|---|
| Server addresses | 77,621 | 83,180 |
| … carrying at least one registered domain | 75,768 | 81,145 |
| Registered domains per address, p50 / p90 / p99 / p99.9 | 1 / 1 / **10** / 32 | 1 / 1 / **10** / 31 |
| Addresses with 2 / 5 / 10 / 20 / 50 / 100 or more domains | 6,021 / 1,808 / 855 / 215 / 21 / 5 | 6,383 / 1,898 / 934 / 217 / 23 / 6 |
| Campus hosts per named address, p50 / p90 / p99 / p99.9 | 1 / 12 / 687 / 2,330 | 1 / 11 / 560 / 2,509 |
| Named addresses with exactly one campus host | 49,080 | 52,953 |

**Nine addresses in ten carry one registered domain a day, and 10 or more is the top 1%, on both days.** That
top 1% is where shared front ends, such as CDN edges and large shared hosts, would sit, though which addresses
sit there was not checked. ioc-report reads an address at or above the 99th percentile as shared hosting
(`SHARED_MIN_DOMAINS`). That qualifies, and never explains on its own: a shared address only lets an
established name (§15) explain the contact.

**What this does not establish.** Two days, one weekday each; no check that the addresses at the top are CDNs
rather than, say, large shared hosts. `root_domain` is populated on 98.6% of addressed rows (§5), so the counts
are lower bounds, and a flagged address measured on a later day may have changed tenants since the match.

### 15. Service prevalence in retained history

Measured 2026-10-15 and reproduced exactly on 2026-10-22, read-only from `history.client_service_day`:
`domain`-basis services over the 90 days ending 2026-10-05, 61 of them retained. Per service: distinct
`client_ip`, distinct days and distinct non-zero `asn_id`. Quantiles and counts only; no service or domain was
read out.

| Fact | Value |
|---|---|
| Services / service-day rows | 127,160 / 18,197,353 |
| Services used by exactly one address | **69.8%** |
| Distinct addresses per service, p50 / p75 / p90 / p95 / p99 | 1 / 2 / **7** / 19 / 309 |
| Distinct days per service, p50 / p75 / p90 / p95 / p99 | 1 / 3 / **9** / 23 / 58 |
| Services with 7 or more addresses on 9 or more days | 11,107 (**8.7%**), carrying 17,897,606 rows (**98.4%**) |
| … of services with 6 / 10 / 20 or more addresses, served from more than one ASN | 48.2% / 53.0% / 56.9% |

Every pair of floors swept, from 2 addresses on 1 day to 50 addresses on 30 days, passed 2.5–30.2% of services
but 96.1–99.3% of service-day rows: where the floors sit changes which names count as established far more than
how many service-day rows those names cover.

**Seven names in ten are used by one address, and under a tenth of names (8.7%) carry 98.4% of service-day
rows.**
ioc-report calls a name established when, in the 90 days before a case's first match, at least the 90th
percentile of addresses (7) used it on at least the 90th percentile of days (9) (`ESTABLISHED_MIN_ADDRESSES`,
`ESTABLISHED_MIN_DAYS`). 7 is also above §13's fan-in ceiling of 5, so no destination the beacon profile could
select is established, by construction. About half of the common names are served from more than one network,
so the network check ioc-report adds is membership in every ASN seen, not the most common one.

**What this does not establish.** One window. Prevalence counts addresses, which are not devices (§3), though
the ones it counts, those with a service row, are the scored population, which did not step (§2). A platform's
tenants share one hashed service, which is why ioc-report never treats a platform tenant as established.

### 16. Registration age of the names E3 rests on

Measured 2026-10-21 and 2026-10-22 over the six IOC-match feeds ioc-report had run (67 cases), with no live
query; not re-run on 2026-10-22, because it needs outside lookups rather than the store. Each name's registered
domain was looked up over RDAP, at the server IANA's bootstrap file lists for its top-level domain. Only
registered domains were sent, and only two kinds: names an E3 explanation could rest on, and flagged domains.
Counts and ages only; no name was read out. About 60 RDAP requests over two runs; one run took 36 minutes,
because the `.au` registry's RDAP server rate-limited.

| Fact | Value |
|---|---|
| Registered domains looked up | 35: 21 with a registration date, 2 under a top-level domain with no RDAP service, 12 failed |
| … the failures | all 12 under `.au`: HTTP 403 and 429 from the registry's RDAP server, still failing after waits and retries |
| Contacts explained by E3 alone, before the check | 30 |
| … with a known registration age | 16 |
| … age at the first match, in days: min / p25 / median / p75 / max | 18 / 1,256 / 2,143 / 3,909 / 9,087 |
| … registered under 32 days before the match | **1** |
| … registered under a year before | 3 |
| Decisions changed by the check | 1 (explained by E3 → review) |

**The rule.** ioc-report withdraws E3 when the TLS name was registered under 32 days before the first match
(`NEW_NAME_DAYS`). 32 days is Unit 42's definition of a newly registered domain, one registered or changed in
ownership within the last 32 days; Unit 42 also reports that such names are disproportionately malicious or
suspicious ([Unit 42, "Newly Registered Domains: Malicious Abuse by Bad
Actors"](https://unit42.paloaltonetworks.com/newly-registered-domains-malicious-abuse-by-bad-actors/)). The
window is cited, not fitted: nothing here is labelled. What was measured is its cost. One E3 contact in 16 with
a known age fell inside it, and that case is the one the evaluated model had called review in all 3 samples
when the rules explained it.

**What this does not establish.**
- **Coverage is the main limit.** 14 of the 30 E3 contacts have no known age: the `.au` registry refused nearly
  every lookup, and two names sit under a top-level domain with no RDAP service. An unknown age leaves E3
  standing, with a caveat.
- **A registration date is a domain's age, not its tenant's.** A platform tenant (`*.workers.dev`) carries the
  platform's date.
- **The sample is small:** 16 known ages, from feeds dominated by one NanoCore listing.

### 17. Serving addresses

Measured 2026-11-13. Retained history from `history.client_service_day`, read-only, and direction from
`long_flows.initiator` (§7) over the same days. Counts only; no address or name was read out. One sweep query,
15.6 M rows.

**The mark.** On one day, one address and one `domain`-basis TCP service, counting only the rows in the port
groups `other_registered` (65537) and `dynamic` (65538), which hold remote ports of 1024 and above: the
`unique_servers` summed over those rows, and the distinct `asn_id`. Remote-opened sessions have that
remote-port shape (§7), and a named service reached from many outside networks is the address's own site.

Swept over 2026-10-11 → 11-09, 30 retained days. Precision is the share of the marked addresses' long flows on
a remote port of 1024 or more, `server` or `client` initiated, that the remote side opened. 28 campus
addresses served TLS long flows (`initiator = 'server'`, campus port 443 or 8443) in the window.

| Remote addresses ≥ | Networks ≥ | Dynamic port required | Addresses | Remote-opened share | TLS servers caught |
|---|---|---|---|---|---|
| 3 | 1 | no | 347 | 95.04% of 224,756 | 27 |
| 5 | 3 | no | 92 | 99.56% of 189,184 | 27 |
| 10 | 1 | no | 59 | 99.96% of 212,803 | 26 |
| **10** | **3** | **no** | **56** | **99.98% of 188,374** | **26** |
| 10 | 3 | yes | 53 | 99.98% of 181,825 | 23 |
| 20 | 3 | no | 36 | 99.99% of 187,849 | 23 |

**At 10 addresses and 3 networks, 56 addresses meet the mark in 30 days, and 99.98% of their measured long
flows were opened by the remote side.** Precision rises steeply up to 10 and is flat after it, while recall of
TLS servers falls after it. Requiring a dynamic port loses three TLS servers and gains nothing.

| Fact | Value |
|---|---|
| Marked addresses on 2026-11-04 / per retained day, min · median · max (30 days) | 31 / 25 · 30.5 · 40 |
| Marked on 3 or more / 15 or more of the 30 days | 45 / 30 |
| Marked since 2026-06-29 | 78 |
| Distinct services marked (30 days) | 6; 54 of the 56 addresses under the campus's own registered domain |
| Of the 56, addresses whose long flows were all campus-opened | 8 |
| Campus addresses serving any remote-opened long flow, 2026-11-04 | 48: 29 on a web port, 8 on SSH, 11 on other ports only |
| … 2026-10-11 → 11-09 | 153: 28 on 443/8443, 23 on 80/8080 only, 102 on no web port |

**What this does not establish.**
- **Only named TLS is marked.** A site reached by its bare address, or a service with no TLS name, has no
  `domain` basis and is not seen. Two thirds of the addresses serving remote-opened long flows served no web
  port at all.
- **`unique_servers` summed across rows counts a remote once per row,** so the count is an upper bound on
  distinct remote addresses.
- **Most marked sites are under one registered domain,** so a mark says that a site is served, not which
  product serves it.
- An address is not a device (§3, §6), and the mark is one day's observation.

### 18. Episodes at a served name

Measured 2026-11-13, read-only from `feed.episode` and `history.client_service_day`, 2026-10-11 → 11-09. An
episode counts when its day, `client_ip` and `service_id` meet §17's mark: the service the address was itself
serving that day.

| Family | Episodes | On the served service |
|---|---|---|
| relationship | 262,880 | 1,991 |
| persistence | 5,953 | 423 |
| transfer, fanout, dns | 3,291 | 0 |

2,414 episodes on 20 addresses: 0 in E1, 312 in E2, 2,102 in E3. **They describe outside addresses reaching the
campus address's own site, not the address reaching a service.** No detector reads direction, so they score as
the address's own relationships.

**What this does not establish.** Whether any of these episodes should be excluded or marked: that is a detector
change, which needs an evidence bundle (`packages/triage/docs/EVALUATION.md`).

## Superseded values

Values this record once stated and no longer does, because the 2026-10-22 re-measurement found them changed or
wrong. Two kinds are kept: values a parameter was fitted on, so a citation to one is a citation to the data as
it was, and readings that proved wrong, several of which had shaped the design. **None of these is a current
fact.** "Changed" means the value was right when measured and the data has since moved; "wrong" means it was not
right when written.

| § | Fact | Superseded value (measured) | Why |
|---|---|---|---|
| 2 | What the population steps were | "a source-side measurement change", "the population-measurement regime changes underneath this pipeline" (2026-08-22, 2026-09-27) | **Wrong** as a reading of the scored population. Every step was in addresses with no service row, and the scored population rose across both seams (2026-10-23) |
| 2 | Which `N` the population rescales | "Persistence rarity and DNS resolver novelty are still `1 − k/N` and still rescale; `drift.population_step` reacts to the step" | **Wrong.** Persistence counts `history.client_service_day` since `baseline-calibration-v3`, and DNS novelty the day's DNS clients; neither is the distinct-address count `drift-gates-v1` gated |
| 3 | Addresses active in all 1,440 minutes | 11,822 of 12,234, 96.6% (2026-08-09) | Changed |
| 3 | What the zero-flow rows are | "campus addresses absorbing continuous unsolicited inbound traffic" | **Wrong.** They carry no server address, port or domain; inbound sessions are addressed rows |
| 7 | Exposure | "Locally served exposure is not observable in these sources" | **Wrong.** `long_flows.initiator` marks remote-opened long sessions |
| 7 | `initiator = 'server'` long flows, 2026-10-21 | 5,752 on 23 addresses; 5,742 on 21 on a web port (read 2026-10-22) | **Not reproduced.** The same day reads 6,854 on 49 and 6,006 on 26; late-arriving rows explain 54 |
| 8 | Filter pass rate | 439,675 of 440,359, 99.84% (2026-08-11) | Changed |
| 8 | Addresses with at least one qualifying flow | 4,157 of about 5,200 active, 80% (2026-08-11) | Changed |
| 9 | Addresses in the DNS table | 1,186 of about 5,200 active, 23% (2026-08-11); 1,034–1,215 a day over 2026-08-10..30 | **Wrong as a DNS population.** It counted every address with a row, and about three in four had only received one unsolicited response; the clients that queried were about 250–300 a day (2026-10-23) |
| 9 | Address-day total sessions | median 1, p10 0, p90 50; 808 of 7,998 (10.1%) reach 50 (2026-08-31) | **Wrong as a DNS population,** for the same reason. The clients that queried carried a median of about 30, and 37% reached 50 (2026-10-23) |
| 9 | "DNS coverage collapsed on 2026-10-16" | "addresses fell from about 1,100 to about 300 … the remaining addresses are heavy users"; "the DNS family was fitted on a population that no longer exists" (2026-10-22) | **Wrong.** What stopped on 10-16 were the unsolicited-response addresses. The clients that queried were 324 on both 10-14 and 10-21, and 99.8% of the week-before sessions were carried by clients still present (2026-10-23) |
| 11 | Published feeds, 2026-07-13..08-09 | 23 non-empty, 205,234 candidates, median 9,304 (2026-08-22) | **Wrong.** The store holds 25, 227,418, median 9,752, every one published by 2026-08-16 |
| 14 | `flow_count > 0` | "traffic the campus host opened" | **Wrong.** It selects rows with a server address, which include sessions the remote side opened |
| 15 | What prevalence counts | "addresses, which §2 shows are not devices and whose population steps" (2026-10-15, kept on 2026-10-22) | **Wrong.** §15 counts `history.client_service_day` addresses, the scored population, and §2 shows that population never stepped (2026-10-24) |

### What the DNS family was fitted on

`dns.new_resolver_min_sessions` and `dns.service_time_role` were fitted on the DNS table over 2026-08-10..30,
counting every address with a DNS row. On 2026-08-30, 804 of those 1,057 addresses had sent no query and only
received one unsolicited response (§9, measured 2026-10-23), so the figures below about "new resolvers" and "no
prior DNS day" are mostly about them. `primary-detectors-v8` removes such addresses before anything is computed,
and the floor was re-measured on the clients that query (`packages/triage/config/parameters.toml`). This is the
fitting record, as §9 then stated it:

- 6,317 distinct addresses over 2026-08-24..30, with no single day carrying more than 1,215. The median
  address-day held one session, and 75% of sessions sat on the 1,036 resolvers that more than two addresses used.
- The median *established* (address, resolver) pair carried 4 sessions a day (p75 17, p90 84, p99 1,341),
  against 1 for a new pair (p75 2, p90 4, p99 73).
- 60–85% of the addresses present each day used a resolver they had not used before. On 2026-08-30 that was 668
  of 1,057, and 647 of those 668 had no prior DNS day at all. Only 44 of the day's 1,465 new (address, resolver)
  pairs carried 10 sessions or more, and 23 carried 50 or more. A floor of 10, with a prior DNS day required,
  left 12 addresses of 1,057, and 5–24 a day across 2026-08-11..30.
- Over the 1,171 (address, resolver) pairs on 2026-08-30 with 10 or more sessions on a resolver that 3 or more
  addresses used, 56.5% of the variance in log10 mean service time sat between resolvers rather than within
  them. Over 2026-08-17..30, a resolver's whole-cohort median moved twofold or more between consecutive days on
  3 occasions, implicating 170 address-days.

## Evaluations

Every change to a parameter, detector, ordering key or tier shipped with an evidence bundle
(`packages/triage/docs/EVALUATION.md`): a dated measurement against real days, by `scripts/evaluate.py`. The
bundles stay with the original deployment, because they measure real days; this is what each measured and
decided. Unless a row says otherwise, a bundle scored 2026-08-09 from retained history against the bundle before
it, on the same day and seed.

| Bundle | Change | What it measured | Verdict |
|---|---|---|---|
| `2026-08-24-baseline-2026-08-09` | None: the harness's first run against real data | The relationship conjunction was called near-redundant. Its conditions are correlated (lift 2.80), yet it removed 77.37% of what its loosest condition admitted. One corroboration condition passed 100% of the time, leaving the rule to large-flow presence (55.17%) | A baseline. It refuted a claim the evaluation guide had made on reasoning alone |
| `2026-08-25-r1-prevalence-denominator-baseline-calibration-v3` | Prevalence counted a service's users among addresses with a service row (3,523 that day) but divided by every observed address (12,234) | Relationship rarity 8.09% → 6.71% and its joint 2.21% → 1.88%; persistence's joint 0.17% → 0.14%. Rarity passed at 6.71% observed and permuted: correct now, and still carrying no host-specific information. 55.5% of the queue sat in a tie group | Improves the output |
| `2026-08-25-r1-support-gate-removed-primary-detectors-v3-behavioural-support-v2` | The client-day support gate removed | Transfer and fanout evaluated 12,234 addresses, not 12,231; nothing else moved. It found a second gate at the service level that excluded 51,172 of 156,933 service-days (32.61%), unjustified and untested | Improves the output, and smaller than described |
| `2026-08-25-i13-service-level-support-gate-removed-primary-detectors-v4` | That service-level gate removed | The excluded service-days had moved 36.90 GB; 32 moved 100 MiB or more, the largest 2.32 GB, none with a long flow. Episodes 2,620 → 4,598, queued hosts 677 → 940, queue in a tie group 55.5% → 68.1%, the top tier unchanged at 877 | Correct, and more expensive than expected |
| `2026-08-26-i4-relationship-calibration-primary-detectors-v5` | The four-rung novelty ladder (its top rung carried 82.5% of relationship candidates) replaced by empirical tail probabilities over the day's own relationship population, combined before one threshold | Episodes 4,598 → 4,120, queued hosts 940 → 860, queue in a tie group 68.09% → 59.07%, distinct relationship strengths 181 → 359. The joint is structural (2.50% observed, 2.52% permuted) because rarity dominates it, and novelty alone tops out at 96.27, under the 97.5 threshold | Improves the output, and names a cost it does not fix |
| `2026-08-31-r2-large-flow-corroboration-qualified-primary-detectors-v6` | A long flow corroborates only in the top 2.5% of the host's own prior 90 days, by size or duration | Relationship units corroborated 818 (26.01%) → 19 (0.60%); E1 495 → 49; episodes and hosts unchanged (4,120 over 860). Presence was invariant to the host label (26.01% observed, 25.89% permuted); the qualified condition moves (0.60%, 1.84%). Queue in a tie group 59.07% → 70.2% | Improves the top tier's evidence, and degrades the ordering by 11.1 points of ties |
| `2026-08-31-r3-dns-floor-shared-context-primary-detectors-v7` | A new resolver needs a prior DNS day and 10 sessions on it; DNS service time demoted to context | The retired rule fired for 60–85% of DNS-visible addresses every day, 97% of them with no prior DNS day (§9 superseded); with both conditions, 12 of 1,057 on 2026-08-30. 56.5% of service-time variance sat between resolvers. Scored 2026-08-29 | Removes a condition that fired on identity, not behaviour |
| `2026-09-08-r5-i6-peer-band-reachability-and-active-minutes-retirement-baseline-calibration-v6` | Active minutes dropped from peer bands; no peer percentile from a cohort under 40 | Episodes 4,120 → 4,124, queued hosts unchanged at 860, E1 unchanged at 49. 96 hosts (0.78%) now have no calibrated transfer or fanout metric, reported as `no_calibrated_metric` (§4) | Stops a comparison small cohorts cannot support, and makes the gap visible |
| `2026-09-10-drift-tolerance-one-time-seam-widening`, `2026-09-27-drift-tolerance-second-seam-widening` | The population drift tolerance widened 0.20 → 0.30 → 0.44, to admit 2026-08-26 and then 2026-09-16 | Moves of 29.28% (8,652 addresses against 12,234) and 43.41% (10,579 → 5,987, while bytes and flows rose), each read as a change in what the source measured | Recorded human decisions. Their reading was superseded on 2026-10-23 |
| `2026-10-23-drift-gates-v2-scored-population` | The population gate moved to the scored population, against the same weekday, at 0.35 | v1 gated every observed address; the addresses with only unaddressed rows produced 11 of 390,056 published episodes, and every step v1 reacted to was in them (§2, §3). Same-weekday movement: median 1.67%, max 30.87%, the public-holiday rebound | Replaces a gate on a population no detector scores. Supersedes both widenings' reasoning; their measurements stand |
| `2026-10-23-dns-population-primary-detectors-v8` | DNS scores only clients that sent a query, leaves out DNS servers, and gets its own population gate (`drift-gates-v3`) | On 2026-10-14, 1,188 addresses in the DNS table became 320 DNS clients plus 4 servers left out, and DNS episodes 10 → 1, 4 of the 10 on DNS servers. The servers had carried 129 of the 335 DNS episodes published 2026-09-01..10-18 (§9) | The family was scoring backscatter and DNS servers; v8 scores the clients that query |
| `2026-10-23-behavioural-support-v3-baseline-calibration-v7-primary-detectors-v9-transfer-and-fanout-score-and-pool-only-addresses-with-a-service-row-an-absent-long-flow-source-is-reported-as-missing-context` | Transfer and fanout score and pool only addresses with a service row; an absent long-flow source is reported as missing context | Re-scored 2026-10-14 and 10-18 from the same history: transfer 63 → 20 and 112 → 18, fanout 101 → 35 and 130 → 28, E1 53 → 25 and 91 → 18. No episode was added, none removed sat on an out-of-scope address, and relationship and persistence were unchanged (§3) | Changes the output on purpose: transfer and fanout fire 65–85% less. Accepted 2026-10-24 |
