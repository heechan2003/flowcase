# IOC match report

Turns an IOC-match feed, from ThreatFox by default, into one report for an analyst. Each (indicator, host) case ends
**`review`** or **`explained`**. **Code makes that decision** with the fixed rules below. The local
model never decides anything. It writes the prose: an overview of every case (what the threat is,
what the address did, what happened, how to read it), a paragraph per group of like cases and the
executive summary, all from code-built digests and all checked by code.

A match is a trigger, not a finding. Most are a laptop touching a shared CDN address that also hosts
something bad. "Explained" is a statement about the match: the contact the indicator matched has an
ordinary reason. No case says a host is compromised, infected or benign. Flow records carry no payload,
process or user, so they cannot show that.

## How a case is decided

Every observed contact with a flagged address must be explained, and no keep rule may hold. A contact
is one kind of minute contact, from either source:
- the feed's matched minutes;
- live minute contact on any day the source still holds.

"One kind" means one address, port, transport and set of names. Long flows are attributed to the
contacts they overlap. Missing data never explains anything.

On a day the live source re-read, a feed contact or long flow it holds in full is the same traffic
seen twice. Both copies are still judged, so no decision changes; the case file, K5's count and the
ledger show the traffic once ("[Live source, also in the IOC feed]"), and the JSON marks the feed
copy with `duplicate_of`.

| Rule | Explains a contact when | Basis |
|---|---|---|
| E1 | UDP, and the family's C2 channel is TCP only (botnet_cc, cited profile) | `knowledge.py` |
| E2 | an ECH outer name (only browsers send ECH), and the family is a native program | `knowledge.py` |
| E3 | TLS to another site, not dynamic DNS or a tunnel, not registered in the 32 days before the match, and the family's C2 has no TLS | `knowledge.py`, CASE_STUDY §16 |
| E4 | an established site: used by enough campus addresses on enough days before the first match, served from the same network (ASN) on campus, on an address carrying enough registered domains to be shared hosting, or on a network that shares its addresses by design (`knowledge.SHARED_NETWORKS`: Cloudflare) | CASE_STUDY §14, §15; `knowledge.py` |
| E5 | a tunnelling service's own client port (bore 7835): the host runs the tunnel client | `knowledge.py` |
| E6 | the host sent nothing: inbound traffic it did not answer | feed |

| Rule | Keeps a case for review when | Basis |
|---|---|---|
| K1 | the host's traffic named the flagged domain, unless it was a tunnel client. Every visit to a flagged lure or payload site stays here | feed |
| K2 | a tunnelling service was reached on another port: the host was a visitor to something published | `knowledge.py` |
| K3 | the published triage stream has an episode on the flagged destination itself on a match day | stream |
| K4 | a scheduled low-volume contact exists (minute grain, or the retained 5-minute bitmap), not explained as an established site | CASE_STUDY §10, §13 |
| K5 | on a payload-delivery indicator, a transfer of 1 MB or more is not explained as an established site. On a network that shares its addresses by design, the finding also says when no TLS name ties a transfer to the flagged site; the case stays in review either way | CASE_STUDY §8 |

Protocol rules (E1-E3) apply only to `botnet_cc`, and only to a family with a cited profile. A
payload-delivery listing names a download server, so its family says nothing about the protocol that
served the file. A case whose records disagree on the family gets no family rule. K4 is the guard
against a mislabelled family: the schedule shapes are rare (§10, §13), so it costs little.

### What each context does

| Context | Role |
|---|---|
| ThreatFox family and threat type | Pick the family profile. Confidence is shown, never used |
| Family and tunnel profiles (`knowledge.py`, every entry cited) | Enable E1-E3 and E5; K2 |
| Per-contact transport, SNI, ECH and bytes sent | Basis of E1-E4 and E6 |
| Address sharing: across every feed host, and live per day | Qualifies E4 |
| Retained name prevalence and serving networks before the first match | Qualifies E4 |
| Minute timing on the pair, 5-minute bitmap on the service | K4 |
| Long flows | Explained like contacts; K5 |
| Registration date of a TLS name (RDAP, opt-in) | Qualifies E3: a name registered under 32 days before the match is no evidence of another site |
| Coverage: live re-query, published stream, retained days | Caveats on every explained case; never decides |
| Triage episode on the flagged destination | K3. An episode on the site the host actually visited is shown, never decisive |
| Products with a known purpose the address used on retained days (`knowledge.SOFTWARE_SIGNALS`, each cited, such as Windows Update or the CrowdStrike sensor), looked up by hash in retained history | Shown only, in the overview's Host part: what the address used, never what it is |
| Host's other matches, host day profile (set against the campus addresses with a service row), traffic around the contact, DNS-only names, app labels, lexical features, the feed's match window, the flagged domain's registration date | Shown only |
| The whole host in retained history: its span, stream episodes on every day, services first used since the match | Shown only (review case files) |
| After the contact (live, review cases): destinations new to the host, traffic with no name, uploads of 1 MB or more to new destinations, continuity of its named destinations before and after | Shown only. Ranked against retained name use; no threshold |
| ThreatFox's own first and last seen dates | Shown only, and only from `data/ioc_metadata.json`, which `ioc-match` fills from the export: the feed's `threatfox.first_seen_utc`/`last_seen_utc` are the matched minute |

## How it runs

| Step | What | Where |
|---|---|---|
| 1 | Group the feed by (indicator, host), and correlate across the feed | `feed.py` |
| 2 | Live source, phase 1: minute contact, address sharing, long flows | `live.py`, `sql/` |
| 3 | Retained history and published stream; registration dates over RDAP when `NAME_LOOKUP=rdap` | `history.py`, `registration.py` |
| 4 | Build contacts and timing, then decide every case | `contact.py`, `rules.py` |
| 5 | Live source, phase 2, review cases only: the host's other traffic around the contact | `live.py` |
| 6 | Live source, phase 3, review cases only: every destination the host exchanged traffic with on each day of its after-contact span, one query per day; then the retained use of every name phases 2 and 3 show | `live.py`, `history.py` |
| 7 | Every case: the case file (the blind verdict's input), and a digest that groups its facts and reasons. Review cases also get next steps. With `--shadow`, a blind verdict per case | `casefile.py`, `digest.py`, `after.py`, `shadow.py` |
| 8 | The writer, a local model, turns each digest into the case's overview, then writes a paragraph per group of like cases and the executive summary. Every reply is checked, and cached by its exact request | `narrative.py`, `summary.py` |
| 9 | Write the HTML page, the Markdown copy and the JSON, with the actions and the checks behind every verdict | `outline.py`, `report.py`, `html_report.py` |
| 10 | With `--case-reports`, a short PDF for each review case, written by Haiku from that JSON. Off by default. `ioc-case-report` does the same step on its own, for any case in a finished run | `case_report.py`, `case_report.typ` |

Minute detail is queried for as long as the source holds it. A Zeek-loaded source keeps every
loaded day: the live phases stop at its last loaded day, never reading or calling silent a day it
never loaded, and each review case's after-contact span runs from the day before its first match to
13 days later. With `NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS` set, as the original probe's fifteen days
(§1), only the last N − 2 days are queried, and an older match day is labelled expired, never
"no traffic". History before the first match is clipped to the
retained days, and the case file states how many there were.

## Setup

This package is a member of the repository's uv workspace and depends on `network_behaviour`
(`packages/triage`) for source guards, service hashing and its DuckDB. It needs Python 3.13 and,
for the local writer, Ollama.

```shell
make sync                                        # from the repository root
cp .env.example .env && chmod 600 .env
ollama pull qwen3:4b-instruct
OLLAMA_KV_CACHE_TYPE=q8_0 OLLAMA_FLASH_ATTENTION=1 ollama serve
```

`.env` holds:
- the live source settings;
- the path to the triage DuckDB, which is opened read-only;
- the Ollama settings;
- optionally `REPORT_TIMEZONE`, an IANA zone whose clock the reports show beside UTC (UTC alone
  by default).

Process environment values take precedence. `OLLAMA_URL` must be a loopback address, because the case
files hold internal addresses and domains. `NAME_LOOKUP=rdap` turns on the name check (see
[Name check](#name-check-rdap)).

An external model through OpenRouter is available with the academic lead's approval. Set
`MODEL_PROVIDER=openrouter`, `OPENROUTER_MODEL=anthropic/claude-haiku-5.5` (the evaluated model; see
[Evaluating model verdicts](#evaluating-model-verdicts)) and `OPENROUTER_API_KEY` in `.env`. Before any text is sent, the case's
internal host address is replaced with `HOST`. Every request asks OpenRouter for zero-retention,
no-collection routing, and the run stops if a model has no such endpoint. Such a run needs `--budget`.

## Running

### Match a ThreatFox export (`ioc-match`)

The feed comes from matching a ThreatFox JSON export (CC0, https://threatfox.abuse.ch/export/) against the
source tables triage's `load-zeek` wrote:

```shell
uv run ioc-match data/threatfox.json --day YYYY-MM-DD        # or --start/--end; writes data/ioc-matches-*.json
```

| What | How |
|---|---|
| `ip:port` | A minute whose remote address and port are the listed ones |
| `domain` | A minute whose TLS name or resolved name is the domain or a subdomain of it, or whose registered domain is the domain |
| `url` | Reduced to its host, then matched as `ip:port` (scheme's default port when none is given) or `domain` |
| Other types | Skipped: a hash names no traffic |

It writes one record per (indicator, host, matched minute), with the pair's long flows, and merges ThreatFox's
own first and last seen dates into `data/ioc_metadata.json` (`IOC_METADATA_PATH`). With `--asn-table` (or
`NETWORK_BEHAVIOUR_ASN_TABLE`) it adds each server's network name and country. It prints counts only. One day
is one bounded query, plus one for the matched pairs' long flows.

### Report

```shell
uv run ioc-report data/matches.json              # live context, history and the model
uv run ioc-report data/matches.json --limit 5    # the first 5 cases by first match
uv run ioc-report data/matches.json --no-model   # same decisions, code's own prose
uv run ioc-report data/matches.json --no-live    # no source queries
SHADOW_PROVIDER=openrouter uv run ioc-report data/matches.json --shadow 3 --budget 0.20
                                                        # the local model writes; Haiku gives a blind verdict
uv run ioc-report data/matches_domains.jsonl data/matches_ip_port.jsonl --name matches
NAME_LOOKUP=rdap uv run ioc-report data/matches.json   # with the E3 name check
uv run ioc-report data/matches.json --case-reports --budget 0.10   # also a PDF per review case
```

| Flag | Meaning |
|---|---|
| `feed ...` | One or more feed files, each a JSON array of match records (host under `affected_host`) or JSON Lines. Give both halves of a split export (domains and ip:port) in one run, so that "another indicator" sees every indicator of the export. `tests/fixtures/` has a synthetic example |
| `--name NAME` | The report's file name. Required with several feed files; otherwise the feed's own name |
| `--out DIR` | Report directory, default `output/` |
| `--no-live` | Skip the live source. Cases say so, and E4 can then rely only on the feed's own sharing count |
| `--no-model` | No model: no overview from the writer and no shadow verdict. Code's own sentences stand in, and decisions are identical |
| `--limit N` | Only the first N cases by first matched minute |
| `--shadow N` | Also ask for a blind verdict on every case: the verdict model reads the case file without the decision or any rule outcome, N times (at most 5) with different seeds. It comes from `SHADOW_PROVIDER` (default: `MODEL_PROVIDER`); the evaluated model is Haiku through OpenRouter. Shown on each case card and in the appendix, never applied |
| `--budget USD` | Hard cap on OpenRouter spend, required when `MODEL_PROVIDER` or `SHADOW_PROVIDER` is `openrouter`, and with `--case-reports`. The run stops before any query if the account holds less. No request is sent whose worst case (the whole prompt, every reply token, at listed prices) could take the reported spend past the cap; that verdict or summary is recorded as not sent |
| `--listing KEY` | The list these records come from (see [Feeds from other lists](#feeds-from-other-lists)). Default `threatfox` |
| `--case-reports` | Also write a short PDF for each review case (see [Case reports](#case-reports)). Off by default, and `--no-case-reports` says so outright. With `--no-model` the PDFs hold code's own text and nothing is sent |

A feed is a JSON array of match records, or JSON Lines (`.jsonl`, one record per line).

### Feeds from other lists

ThreatFox is the default, not a requirement. A record needs an indicator, the host and the matched
evidence. `knowledge.LISTINGS` says, for each list, who publishes it and where its records keep the
rest:

```shell
uv run ioc-report data/other_list.jsonl --listing amazon-php2shell
```

| Field | Meaning |
|---|---|
| `source` | Who publishes the list. Every report, digest and prompt names them instead of ThreatFox |
| `indicator_field` | The record's key for the indicator (`aws_indicator` in the PHP2Shell export) |
| `claim_field` | The object holding `malware`, `threat_type` and `confidence`. Without one, `family` and `threat_type` apply to every record |
| `address_only` | The list names addresses, so a port in the indicator is only the one seen on the contact: two ports on one address and host are one case |
| `inbound` | The list names addresses that connect in to their targets. The TLS name is then the campus host's own site, so E4 does not apply, and the digest and prompts read the contact that way round |
| `sources` | Public sources for the list |

**To add a list,** add an entry with its sources, plus a cited `REPORT_FAMILIES` entry if its family needs describing. Nothing else changes: an unknown family enables no rule. One run reads one list.

On another list, two things differ at live time. A later match day inside the minute window is enough
to read what followed, since merged records can start before it. And a name with no letters, such
as a visitor's `2.10` or `10:80`, is dropped: it is a piece of the campus address, not a name.

What stays ThreatFox-only:
- **The second opinion.** Its prompt and evaluation are about ThreatFox cases, so a run on another list asks for none and says so. Extending it means a new evaluation.
- **Listing dates.** `data/ioc_metadata.json` holds ThreatFox's dates only.

**Lists tied to an advisory.** When a list's publisher names the CVEs its addresses were seen
exploiting (`Listing.advisories`, so not ThreatFox), each case digest also says whether the host
served a named site to many outside networks (`history.read_serving`).

A ThreatFox run's decisions, digests, case files and prompts are unaffected by any of this: `tests/test_evals.py` and `tests/test_listing.py` pin them.

### The writer

The local model (`qwen3:4b-instruct` by default) writes every overview, so it reads the case's
digest, about a thousand tokens, never the full case file, which can pass 18,000. The digest
groups contacts by why no rule explained them, so a lure visit with a hundred ad-network contacts
reads as its two reasons.

Every reply is checked before it is used:
- every number, domain and address must appear in what the model read;
- no host-state or host-type claim, and no "suspicious" or "normal";
- threat labels only beside ThreatFox, the indicator or the family;
- no rule codes, and no sentence that argues with the code's decision.

A reply that fails is sent back with its problems, up to three attempts. After that, code's own
sentences stand in, and the card says so.

On the M1 with 8 GB this project runs on, a reply takes 20–60 s, so a feed of 52 cases takes
about half an hour or more. Replies are cached in `<out>/.model-cache/`, keyed by the exact
request, so re-rendering a run is instant. The cache holds case text and is git-ignored with
`output/`.

### Case reports

A case report is a PDF of about one page on a single case, laid out like page 1 of the php2shell hunt
write-up: an executive summary, the background, an analysis, the conclusion with next steps, then
one line of sources and limits. It is written for a reader who knows nothing of this tool, so it
says what we found and never how: no rules, thresholds, tools, data stores or models.

```shell
uv run ioc-case-report output/matches.json --budget 0.10            # every review case in that run
uv run ioc-case-report output/matches.json --case 2 --budget 0.05   # the case numbered 2 in that report, review or explained
uv run ioc-case-report output/matches.json --no-model               # a free layout preview in code's own text
uv run ioc-case-report output/matches.json --budget 0.10 --out reports/   # default: beside the report
```

A case report also says what else the same campus address matched in the run, and says when an address is on a network that shares its addresses by design (`knowledge.SHARED_NETWORKS`), where how few names we saw on it means nothing, and only a TLS name ties traffic to one site.

Beyond the method words and word limits, code sends back a reply that drops one of those other matches or a large download total, counts new destinations without the campus median beside them, or says there was no contact after a date. It cannot catch every misreading, so read the prose against `what_the_writer_read` in the audit file.

The report's writer always runs at low reasoning effort. At `medium`, a long case spent the whole
reply allowance on reasoning and returned no text. The second opinion keeps the effort it was
evaluated at.

`ioc-case-report` reads only the JSON a run wrote, so it needs no live source and no DuckDB, and it still
works after the source's minute window has passed. A report from before digests stops with a
message asking for a new run. `ioc-report --case-reports` does the same over the JSON it just wrote.

**Who writes what.** Haiku through OpenRouter writes the paragraphs, whatever writes the rest of the
report; `OPENROUTER_MODEL` overrides the model. It cost about $0.005 a report on 2026-11-06, and
$0.0025 for the demo's beacon case on 2026-11-26 (`demo/sample-output/haiku-case-beacon.pdf`).
Code writes the title, the facts line, the headings, the sources and the limits. The decision is the
one in the JSON, and no reply can change it.

**What the model reads.** A brief cut down from the case's saved digest, plus its next steps. The
blind verdict, the source tags, rule codes, thresholds and local times are gone, and the host's
address is replaced with `HOST` before anything leaves the machine. The brief is in the audit file
beside each PDF.

**What every reply must pass.** All the writer's checks above, a word limit per paragraph, and a
check for words that give the method away (`narrative.method_words`). A reply that fails is sent
back with its problems, up to three attempts. If none passes, the brief's own sentences stand in,
the tool warns that the PDF needs editing before submission, and `ioc-case-report` exits 1. Such a
failure is not cached, so the next run asks again; a reply that passed is never paid for twice.

**Families.** The Threat paragraph describes the family from `knowledge.py`: its profile, or a cited
entry in `REPORT_FAMILIES`, which no rule, case file or digest reads, so adding one changes no
decision and no blind input. ThreatFox's generic labels (`unknown_rat`) are said to name no family.
Any other family with no entry gets no description, and the tool says to add one.

**Output.** A review case is `<out>/<Threat> (<host>, <domain or address>).pdf`, so a folder sorts by
threat: `ClickFix-style lure (192.0.2.10, bad.example.org).pdf`. The threat is the family as the report
names it, or "Unnamed loader" and the like where the list names none. The port is left out unless the
same host matched the same address on another port in that run. A run never overwrites another run's
report: if the name is taken in a shared folder, it adds its own name to the end. An explained case
you ask for by number is
`<out>/<name>_case_<n>.pdf`. Beside each
PDF is a `.json` audit file of the same name: who wrote the text, attempts, any problems, what the model
read and every paragraph. The audit file is for checking sentences against the brief, and is not for
submission. Both carry internal addresses and domains, as the hunt write-ups do, so they stay under
the git-ignored `output/`, and the tool prints only the folder, never these file names.

### Shadow verdicts

The shadow mode tests whether a model reading the same facts would reach the same decision.
It is not a vote. A stable disagreement (every sample agrees with each other, not with the code) marks
a case worth a second look. An unstable one shows the model is guessing. Nothing is labelled, so no
disagreement ever changes a rule. Local thinking models need
`OLLAMA_THINK=false` so they answer in the JSON the schema asks for.

The run stops with a message before any query if any of these fail:
- the feed cannot be read;
- the DuckDB is missing, or locked by the publisher;
- Ollama is unreachable, or the model is not pulled.

An unreachable live source does not stop a run on the local model; it is labelled in every case. A
paid run (`MODEL_PROVIDER=openrouter`) stops before any model call instead, because the cases would
lack their live contacts: load the match days into the source, or pass `--no-live` to run on the feed
and history alone.

### When the source forgets: run each feed the day it arrives

A Zeek-loaded source keeps every day until it is reloaded, so nothing here applies unless retention is
set (`NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS`). The original probe kept minute detail for about fifteen days,
and the report re-queried only the last 13. Once a match day had gone:
- **The contacts are only the feed's own minutes.** Each record carries one minute, and on one
  measured day the source held minutes the feed lacked.
- **The schedule check K4 cannot run at minute grain.** Only the retained 5-minute bitmap remains.
- **Address sharing and the traffic around the contact** are no longer available.

Long flows last longer: `long_flows` held rows back to at least 2026-09-20 when read on
2026-10-22 (CASE_STUDY §1), so the long-flow re-query, and K5 with it, outlives the minute
window. A run soon after the match misses only long flows still open when it queries: 0.10–0.37%
of a day's rows at 08:00 UTC the next day (§8).

On 2026-10-21, 11 of 15 match days had expired when their feeds were run. The run prints how many
cases are still inside the window before it queries anything. The triage publisher must also run
daily: a day it misses is never retained or published, so K3 and the retained K4 cannot run on
that day.

### Name check (RDAP)

E3 explains a TLS contact because the family's channel carries no TLS. Its risk is a TLS name the
operator registered for the same infrastructure. On 2026-10-21, every name E3 alone rested on was
rare on campus, and most had never been seen there. Campus history cannot tell an old long-tail site
from a new operator domain; a registration date can.

- **Opt-in:** off unless `NAME_LOOKUP=rdap`. Without it, E3 behaves as before and the case carries
  an `e3-name` caveat.
- **What is sent:** only registered domains (never a full name, an address or case text). They go
  to the RDAP server that [IANA's bootstrap file](https://data.iana.org/rdap/dns.json) lists for
  their top-level domain. Only two kinds are looked up: the names E3 could rest on, and the flagged
  domains.
- **Cache:** answers stay in `data/rdap/` (git-ignored) for 30 days, and the bootstrap file for 7.
  Requests to one server are spaced 1.5 s apart, and rate limits are waited out.
- **The rule:** a name registered under 32 days before the first match (Unit 42's definition of a newly registered domain) loses E3 (`rules.NEW_NAME_DAYS`,
  CASE_STUDY §16). An unknown age (no RDAP service, no record, a failed lookup, or a registration
  after the match) changes nothing and is listed as a caveat. The check can only take an explanation
  away.

## Outputs

**`output/<feed>.html`, the report to read.** One self-contained page, laid out like the
security project's hunt write-ups. Its Content-Security-Policy allows only its own inline style and
script, so it opens from disk and loads nothing.
1. **Executive summary:** the writer's paragraph, and tiles that count the cases and filter the
   page: review, explained with caveats, explained with every check run. With `--shadow` there is
   also a tile for how often the blind model agrees.
2. **Background:**
   - each ThreatFox family in the feed, with its cited background and sources;
   - folded: the data, coverage and query footprint.
3. **Analysis:** one section per group of cases code decided the same way for the same reasons,
   review groups first. Each has the writer's paragraph and a table: host, first match, code
   verdict, blind model verdict, and the one-line reading.
4. **Conclusion and next steps:**
   - the writer's conclusion;
   - an actions table by the system that can settle them (device lease, endpoint, web gateway,
     resolver, mail, the report's next run), with the cases each covers.
5. **Cases:** one card per case, review first. Each card has:
   - **the code verdict and the blind model verdict;**
   - **the overview**: Threat, Host, What happened, How to read it;
   - **why code decided**, grouped by reason;
   - next steps, for a review case;
   - what the case could not check;
   - what would change the reading.

   Folded at the end: the evidence (facts box, charts and tables), the digest the writer read,
   and the case file the blind verdict read.
6. **Appendix:**
   - every case in one table;
   - the checks behind every verdict, with their scope and what a positive would have been;
   - the rules with their counts;
   - the blind-verdict tallies.

Light and dark follow the system. Print uses light and opens every fold.

**`output/<feed>.md`:** the same report as text, in the same order.

**`output/<feed>.json`:** for audit and reuse. It holds:
- every case's decision, contacts, rule findings, digest and overview (the model's fields, or why
  code's text stands);
- the groups and the summary.

**Caveats** say what an explained verdict could not check:
- `live`: a match day not re-queried;
- `stream`: a day never published, so no K3;
- `retained`: a day not retained, so no 5-minute K4;
- `e3-name`: E3 resting on a name of unknown age.

**`output/<Threat> (<host>, <domain or address>).pdf`:** with `--case-reports` or `ioc-case-report`, one short
report per review case for a reader outside the team's tools (see [Case reports](#case-reports)).

**All of these files contain internal IP addresses, domains and per-host activity.** They are
git-ignored. Do not share them outside the team, except a case report sent to the academic lead.

## Evaluating model verdicts

`evals/` tests whether a model could give the verdict itself rather than only write summaries. It is a
fixed set of 27 synthetic cases, and the model reads each one blind, without the decision or any rule outcome:

- **14 must-review cases.** Threat-shaped synthetic cases, such as a schedule, raw TCP, a dynamic-DNS name, a
  foreign serving network, a platform tenant, a lure visit, or a visit or transfer on a shared network.
- **9 must-clear cases.** Synthetic: one for each explanation rule, and E3 on a name registered
  years before.
- **8 twin pairs.** Each pair differs in one decisive fact. P7 differs only in when the TLS name was
  registered, and P8 only in whether the address is on a network that shares its addresses by design.
- **4 knowledge cases.** These need public knowledge of a family the knowledge base does not profile. They
  include one "unknown family" trap.

The original deployment also scored 10 real cases, one per decision signature on a real feed, blind
and pseudonymised. They are not in this repository, so the results below that count them (37 or 33
cases) cannot be reproduced here; `evals.run` scores the synthetic set alone.

```shell
uv run python -m evals.run --model openrouter:anthropic/claude-haiku-5.5 --budget 0.20 --dry-run
uv run python -m evals.run --model openrouter:anthropic/claude-haiku-5.5 --budget 0.20
uv run python -m evals.run --score        # writes output/eval/<evaluation version>/scorecard.md
```

The evaluation version is the prompt version plus a digest of the exact blind case files, so a
changed case file is answered afresh rather than from the cache of the old one.

Every reply is cached the moment it arrives, so a re-run never pays twice. A paid run stops before any call
whose worst-case cost would exceed `--budget`, and it reports the account balance before and after.

The prompt is versioned by hash, and a changed prompt starts a fresh evaluation. The pass bars were fixed
before the first paid run (`evals/score.py`):

| Bar | Requirement |
|---|---|
| Safety | at most 1 must-review case cleared |
| Usefulness | at least 80% of must-clear cases cleared |
| Twin pairs | at least 7 of 8 fully right (5 of 6 before P7 was added, 6 of 7 before P8; still one miss) |
| Stability | at least 90% of cases unanimous over 3 samples |
| Grounding | at most 10% of reasonings flagged for invented numbers, host-state words or contradicted shapes |
| Knowledge | at least 3 of 4 knowledge cases right |

There is no ground truth, so "correct" means the project's policy, plus cited public facts for the knowledge
cases. The evaluation screens models; it does not certify them.

### Decision: `anthropic/claude-haiku-5.5`

**We use `anthropic/claude-haiku-5.5` (via OpenRouter) for model verdicts.** We also evaluated other cloud
and local models and decided not to go with them. A model verdict is a second opinion shown beside code's
decision, never applied.

**Results on evaluation `3897e3117dfe-dc0e9ce2ac17` (this repository, 2026-11-26)**: the 27 synthetic
cases, on the prompt as published here, 3 samples per case. **It failed two bars, both in the safe
direction:** it kept two must-clear cases in review and cleared no must-review case. Beside it are the
same bars on the original deployment's last run, which also scored 10 real cases:

| Bar | This repository (27 synthetic cases) | Original, 2026-11-06 (37 cases) |
|---|---|---|
| Safety | pass: 0 of 15 must-review cases cleared | pass: 0 of 15 |
| Usefulness | **fail: 7 of 9 must-clear cases cleared** | pass: 9 of 9 |
| Twin pairs | **fail: 6 of 8 fully right** | pass: 8 of 8 |
| Stability | pass: 26 of 27 cases unanimous | pass: 35 of 37 |
| Grounding | pass: 0 of 81 reasonings flagged | pass: 0 of 111 |
| Knowledge | pass: 4 of 4 knowledge cases right | pass: 4 of 4 |
| Cost | $0.044 for 81 calls; 6.4 min | $0.066 for 111 calls; 9.4 min |

- **P4a** (E5, the host's own bore client on bore's client port) went from explained to review in all
  three samples. Each reasoning reads the domain rule's tunnel-client exception as "not shown", although
  the case file shows it.
- **P8a** (E4, an established site on a network that shares its addresses by design) split 1 to 2, the
  wrong way. It split 2 to 1 the right way in the original run, with the same objection: the measured
  count does not show sharing, and only a network fact does.

Between the two runs, the prompt changed by two words (it says "a university campus network" instead
of naming the university). Across all 27 case files, only the citation labels and the long-flow table's
name changed. Whether that wording or a change on the provider's side in the 20 days between moved the
verdicts was not tested. The pass bars stay as they were fixed, and the prompt was not changed to win
them back: the evaluation screens models and is never tuned to their verdicts.

**Results on evaluation `1f318da0f278-10ab2a7040d7`**: the same prompt, on case files that mark an
address on a network sharing its addresses by design as shared hosting, plus the new cases P8a, P8b,
S7 and S8 (3 samples per case, 2026-11-06). It passed every bar. The new rule changed no decision on
the 89 cases in the feeds held here, run without the live source:

| Bar | Result |
|---|---|
| Safety | 0 of 15 must-review cases cleared |
| Usefulness | 9 of 9 must-clear cases cleared |
| Twin pairs | 8 of 8 fully right |
| Stability | 35 of 37 cases unanimous |
| Grounding | 0 of 111 reasonings flagged |
| Knowledge | 4 of 4 knowledge cases right |
| Cost | $0.066 for 111 calls; 9.4 min |

It remains wrong on one real case, in the safe direction: it kept the real tunnel-client case in review
(2 to 1), as it has before. P8a split 2 to 1 with the right majority: one sample would not count a
network fact as marking the address shared.

**Results on evaluation `1f318da0f278-8edc76dd16f9`**: the same prompt, re-run on case files that
show each feed and live duplicate once, rank the traffic around the contact, and add the whole host
and the view after the contact (3 samples per case, 2026-10-22). It passed every bar, with the same
results as the run below:

| Bar | Result |
|---|---|
| Safety | 0 of 12 must-review cases cleared |
| Usefulness | 8 of 8 must-clear cases cleared |
| Twin pairs | 7 of 7 fully right |
| Stability | 32 of 33 cases unanimous |
| Grounding | 0 of 99 reasonings flagged |
| Knowledge | 4 of 4 knowledge cases right |
| Cost | $0.059 for 99 calls; 8.4 min |

**Results on prompt `1f318da0f278`**, the v1 prompt with the name check (3 samples per case,
2026-10-22; it passed every bar):

| Bar | Result |
|---|---|
| Safety | 0 of 12 must-review cases cleared |
| Usefulness | 8 of 8 must-clear cases cleared |
| Twin pairs | 7 of 7 fully right |
| Stability | 32 of 33 cases unanimous |
| Grounding | 0 of 99 reasonings flagged |
| Knowledge | 4 of 4 knowledge cases right |
| Cost | $0.056 for 99 calls; 8.1 min |

**On the way there, one prompt failed (`2f1c3696d973`).** It had both of these defects:
- **The prompt didn't say an unknown age leaves E3 standing.** The model read "registration not
  looked up" as missing data that blocks the reason. It kept knowledge case X3 in review and split
  a real E3 case 2 to 1. The prompt now says it.
- **Grounding checked numbers against the case file alone.** It flagged 11 reasonings that quoted the
  policy's own 32-day window. The check now accepts numbers from what the reader read: the policy and
  the case file.

The bars did not change, except that the twin-pair bar was set to 6 of 7 when P7 was added, before
any run of that set. A stopped run of a 30-day draft cost $0.0035.

**Results on prompt `f5e1f5ba093e`**, before the name check (October 2026; it passed every bar):

| Bar | Result |
|---|---|
| Safety | 0 of 11 must-review cases cleared |
| Usefulness | 7 of 7 must-clear cases cleared |
| Twin pairs | 6 of 6 fully right |
| Stability | 28 of 31 cases unanimous |
| Grounding | 0 of 93 reasonings flagged |
| Knowledge | 4 of 4 knowledge cases right |
| Cost | $0.052 for 93 calls, about $0.0006 a call; 7.4 min |

**What we found:**
- **It applies the policy to the facts.** It got every twin pair right, so it reacts to the one fact that
  decides each pair.
- **It adds knowledge the rules lack.** It correctly cleared AsyncRAT and njRAT contacts that the knowledge
  base cannot decide, because neither family has a cited profile. It kept the unknown-family trap in review
  and did not invent a profile.
- **Its one wrong case errs toward review.** It kept a real tunnel-client case in review in all 3 samples,
  where the rules explain it. It reasoned that the case file does not prove the client is the host's own.
- **It is not perfectly stable.** Three cases (a tunnel client, an inbound-only contact and a knowledge
  case) split 2 to 1, each with the right majority. This is why verdicts are sampled and decided by
  majority.

**The first run (prompt `e66acb793ca8`) failed on two defects in the test, now fixed:**
- **The prompt left out a policy exception.** It lacked E3's rule that a dynamic-DNS or tunnel name never
  makes TLS a protocol mismatch, so models cleared the dynamic-DNS twin exactly as that prompt said.
- **The grounding bar used a check built for summaries.** It flags any mention of the family's
  "command-and-control channel", which verdict reasoning has to name. Grounding now counts invented
  numbers, host-state words and contradicted shapes.

The bars did not change between the two runs.

### How we proceed

**Model verdicts are a second reader, and stay one.** Nothing is labelled, and no labelling is
planned, so no model verdict can be shown to be right where the rules are silent. So:

1. **Code decides every case.** `rules.py` alone sets the disposition, and the shadow verdicts
   (`--shadow 3` with Haiku) are recorded beside it and never applied.
2. **A disagreement is shown, not acted on.** A stable disagreement marks a case worth a second
   look. Rules and prompts are never tuned to agree with the model: without labels that would only
   teach the rules the model's mistakes.
3. **A new prompt version starts over.** Any change to `SHADOW_PROMPT` or to what the blind case
   file says gets a new evaluation, which must pass every bar before it is used.
   `tests/test_evals.py` pins the synthetic case files to catch a silent change, and the runner's
   cache is keyed by both, so a changed case file is never scored on old replies.

**Budget:** the project has a fixed $5 of OpenRouter credit that will not be topped up. Every paid
run should check the balance first.

## Limits

- **Live matching is by address.** A domain that moved to a new address is missed.
- **History keeps hashed services, not names or addresses.**
  - Names are hashed here exactly as the publisher hashes them.
  - Unnamed contact that the publisher retained under an application basis cannot be looked up.
  - A platform tenant (`*.github.io`) shares its platform's hash, so it never counts as established.
- **Knowledge is deliberately small.**
  - Only `win.nanocore` has the C2 fields that protocol rules need.
  - Only bore and cloudflared have client ports.
  - An unknown family or service enables no rule, and its cases stay in review unless E4 or E6 applies.
- **Address sharing measured on a later day** can describe a new tenant. E4 therefore also requires the
  name to have been served from the address's network before the match.
- **No host classification.** The overview names the products the address used (cited,
  `knowledge.SOFTWARE_SIGNALS`) and may say what they are typical of; nothing decides what a host
  is. IOC_Processor's host type was not ported:
  - its thresholds were set on 21 weak seeds;
  - two of its three sources are outside the authorized tables;
  - an address can change hands;
  - the rules judge each contact, which a host type cannot change.

  Case files carry the host's measured day profile as context only.
- **A contact does not say who opened it.** Contacts are built from minute rows (`contact.py`), and
  `activity_1m` records sessions the remote side opened like any other, without saying which
  side did (CASE_STUDY §7). A contact can therefore be the flagged address reaching a campus host that
  answered. E6 covers the case where the host sent nothing. `long_flows.initiator` records
  direction for long flows, and nothing here reads it, by decision (as in the triage repo,
  measured rather than built). What §7 measured, 2026-10-21:
  - a remote port of 1024 or more is on every long flow the remote side opened, and on 370 of
    584,152 the campus side opened;
  - for hosts that served remote-opened long flows, 85.9% of their addressed pairs had no long flow
    at all, so their direction is unknown.

  In the feeds run so far, every contact E1–E3 explain is on a remote port below 1024.
- **Plain DNS never appears as a contact.** `activity_1m` carries no port-53 row (CASE_STUDY
  §9), so a flagged address the host reached only as a DNS server shows no contact.
- **The published stream changed definitions under it.** Published days are never re-scored.
  - `primary-detectors-v8` limited DNS to clients that sent a query, leaving DNS servers out.
  - `-v9` limited transfer and fanout, and their peer pools, to addresses with a service row.

  K3 reads only relationship and persistence episodes, which neither changed: no other family
  carries a service id. The case file counts the whole host's episodes from before each change.
- **Accuracy is not measured.** Nothing is labelled. The evaluation set checks that a reader
  applies the policy, and caveats state what each explained case could not check. Neither shows
  how often a verdict is right.
- **E3 rests on rare names.** A name of unknown age keeps E3, with a caveat. On 2026-10-22, 16 of
  the 30 contacts E3 alone rested on had a known age (CASE_STUDY §16). The `.au` registry's RDAP
  server refused nearly every lookup with HTTP 403 or 429, and one top-level domain lists no
  service. Failed lookups are not cached, so later runs fill the gaps; a server still rate-limiting
  after the retries is left alone for the rest of that run. Certificate history
  is not consulted. A platform tenant (`*.workers.dev`) has its platform's registration date, so
  the age check says nothing about it.
- **The overviews are a small local model's prose.** They are checked against the digest, but
  they can still blur two contacts or pick the wrong emphasis. The digest and the case file are
  folded under every card, so each sentence can be checked.
- **Case reports are checked the same way, and read by someone who cannot check them.** The PDF
  shows no digest or case file, and the word check catches method language, not a wrong sentence.
  Read each PDF against its audit file before submitting it.
- **The model's text is checked crudely.** The checks catch invented numbers, host-state words,
  contradicted shapes and unattributed threat labels. They do not catch every wrong sentence. The
  decision never depends on the summary.
