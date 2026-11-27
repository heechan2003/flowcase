# Architecture

flowcase is two packages in one uv workspace. `network_behaviour` (`packages/triage`) publishes one immutable
stream of behavioural episodes per UTC day. `ioc_report` (`packages/ioc-report`) decides every IOC match in
code and has a model write the case up. They share one source boundary and one retained store. The
[README's diagram](../README.md#architecture) shows the whole pipeline; this page says where each part lives
and why it is built that way.

Paths name a package's source directory: `network_behaviour/` is `packages/triage/src/network_behaviour/`,
and `ioc_report/` is `packages/ioc-report/src/ioc_report/`.

## The pipeline

| Step | Command | Reads | Writes |
|---|---|---|---|
| Load | `network-behaviour load-zeek` | Zeek's conn, ssl, dns and weird logs; an ip2asn table | The source DuckDB: four `flow.*` tables |
| Triage | `network-behaviour run-day`, or `backfill` for a range | The source, read-only; retained history from before the day | The retained store: `history.*`, and the day's stream in `feed.*`. `run-day` also prints the stream as JSONL |
| Match | `ioc-match` | A ThreatFox export; the source | The IOC-match feed, and ThreatFox's own dates for each indicator |
| Report | `ioc-report` | The feed; the source, live; the store, read-only | A Markdown report and a JSON file |
| Case reports | `ioc-case-report`, or `ioc-report --case-reports` | That JSON file only | A PDF and an audit file per review case |

`make demo` runs every step on a synthetic network and checks each planted case (`demo/README.md`).

### One triage day

`DayRunService.run` (`network_behaviour/operations/pipeline.py`) takes a day through these steps in order.
A failure before publication writes nothing.

1. **Eligibility.** Day D runs no earlier than D+1 08:00 UTC (`time.py`). A day that is already published
   returns its stored stream: a rerun reads no source data and prints the same bytes.
2. **Source checks.** The contract check holds the four tables to the column types in `source/contracts.py`
   and requires the day's coverage to be complete. Then the day's aggregates are streamed into a staged day
   (`source/day.py`) and DNS is read (`detectors/dns.py`). Any failure stops the day.
3. **Drift gates** (`drift.py`). The day stops if its scored population moved too far from the last
   retained day with the same weekday, or if the mix of how its services are keyed (domain, network,
   address) moved too far from the last published day. A DNS population beyond tolerance only turns the DNS
   family off for that day.
4. **Scoring** (`operations/scoring.py`). Baselines come from retained history where `day < D`. Five
   detector families score the day, and their findings are fused into episodes, sorted into three evidence
   tiers and ordered, with ties kept as tie groups. Scoring reads `history.*` and writes nothing.
   `network_behaviour.evaluation` runs the same function, so a measurement cannot drift from what ships.
5. **Publication** (`publication.py`, `storage/feed.py`). One transaction writes the day's history rows and
   its complete stream, checks that the counts reconcile and cuts history to 365 days. Any mismatch rolls
   it all back. A storage guard stops growth before the configured limit.

One process writes at a time (`operations/locking.py`). The detector families are listed, from code, in
`packages/triage/docs/generated/detectors.md`, and the tiers and the ordering key in
`packages/triage/docs/generated/ordering.md`.

### One IOC report

`ioc_report/cli.py: main` runs these steps. The package README's "How it runs" names every module.

1. **Cases.** The feed is grouped into (indicator, host) cases (`feed.py`).
2. **Context, batched across all cases.** Live minute contact, address sharing and long flows from the
   source (`live.py`, phase 1); retained history and the published stream from the store (`history.py`);
   registration dates when RDAP is on (`registration.py`).
3. **Decision.** Contacts are built (`contact.py`) and every case is decided (`rules.py`).
4. **Review cases only:** what else the host did around its contact, and what was new after it (`live.py`,
   phases 2 and 3; `after.py`). The case file shows these; the decision never reads them.
5. **Write-up.** Code writes each case file and digest (`casefile.py`, `digest.py`), the writer turns the
   digests into prose (`narrative.py`), and the Markdown and the JSON are written (`report.py`). The
   Markdown leads each case with code's facts; the writer's overview is in the JSON.

### Where the packages meet

`ioc_report` depends on `network_behaviour` for its source guard, its service hashing and its store. Rule K3
is where the two meet: a case stays in review when triage's published stream has an episode on the flagged
destination itself. `demo/README.md` shows how that plays out in three of the planted cases.

## The source boundary

Zeek enters in one place. `load-zeek` (`network_behaviour/source/zeek/`) writes the four `flow.*` tables
into a DuckDB file, and everything above reads those tables: triage's checks and detectors, ioc-report's
live queries, and `ioc-match`. None of it reads a Zeek field. `docs/SOURCE_CONTRACT.md` gives the mapping
column by column, and the loader's versions.

The original deployment read four tables of the same shape from a commercial flow probe (`CASE_STUDY`).
When Zeek replaced it, the new code was the loader, a read-only DuckDB client, DuckDB versions of the
queries and the provider that wires them in. The detectors, the rules and the writer were not changed for
it. These seams made that possible:

| Seam | Where | What it holds apart |
|---|---|---|
| `ClientLike` | `source/client.py` | A client is anything with `query`, `query_row_block_stream` and `close`. `DuckDbSourceClient` (`source/duckdb_client.py`) opens the source file read-only, with external access off, its configuration locked, the session in UTC and a timeout on every query. Tests pass fakes |
| `ReadOnlyQueryRunner` | `source/client.py` | Every source query runs through it, in triage, `ioc-match` and ioc-report's live queries. A data query must have typed UTC bounds, and `start` and `end` can come only from them. Each query leaves an audit of its name, version, rows and bytes, never its text or parameters |
| Versioned SQL, checked by `validate_sql` | `source/sql.py`; `packages/triage/sql/source/` and `ioc_report/sql/` | Queries are files named `name.vN.sql`, and loading one checks it: `SELECT` or `WITH` only, one statement, no write keyword, no `SELECT *`, only the four tables, a half-open UTC bound on every branch, an aggregate when the query must be aggregate-only, and none of the identifiers the original source could expose (subscriber, mobile and user-agent fields). The queries keep typed placeholders (`{start:DateTime('UTC')}`), which the DuckDB client rewrites |
| `DayInputProvider` | `operations/pipeline.py` | The day run gets its inputs from one call, `load(day)`: the source aggregates, the staged day and the DNS observations. `SourceDayInputProvider` runs the checks and reads described above; the pipeline tests hand in staged days instead |
| The synthetic switch | `synthetic.py` | With `NETWORK_BEHAVIOUR_SYNTHETIC=1`, documentation and benchmarking ranges count as public destinations and `.test` as a public suffix, here and in ioc-report's name handling (`knowledge.py`), and each published day's normalization version gains `+synthetic`. Without it, normalization drops them like any non-public address or unknown suffix. The demo and the tests set it |

## Code decides, the model writes

Triage has no model. In ioc-report a model writes prose and nothing else.

- **The decision is code.** `rules.decide` explains a case only when an E rule explains every observed
  contact with the flagged address and no K rule holds. Missing data never explains anything. A case ends
  `review` or `explained`, and "explained" is a statement about the match, never about the host. The rule
  table is in the package README ("How a case is decided"), and every threshold cites a `CASE_STUDY`
  section.
- **The model reads code's digest.** `digest.py` groups the case's facts, and every line names its source.
  The writer reads that, never the raw case file, and answers in JSON fields (`narrative.py`).
- **Code checks every reply** (`narrative.check_prose`). A reply fails when it:
  - has a number, name or address that is not in what the model read;
  - describes the host's state, says what the host is, or calls anything benign or safe;
  - judges the traffic instead of saying what code found;
  - claims a traffic shape the measurements do not show;
  - uses a rule code, a threat label not attributed to the list, or the list's confidence as evidence;
  - contradicts code's decision, or leaves a field empty.
- **A failed reply goes back.** The model gets the problems listed and rewrites, three tries in all
  (`narrative.ATTEMPTS`). Then code's own text stands, and the report says who wrote each piece. A reply is
  also withheld when its input came within 10% of the model's context window. Replies are cached by the
  exact request, so re-rendering a run costs nothing.
- **Without a model, only the prose changes.** `--no-model` puts code's text everywhere, and the decisions
  are the same. The demo runs this way.
- **Case reports** (`case_report.py`) are for a reader who knows nothing of the tool. The decision is the
  one in the run's JSON. Haiku writes the paragraphs from a brief cut from the saved digest, with the blind
  verdict, the source tags, the rule codes and the thresholds taken out. The paragraphs pass the same checks,
  plus their own, among them a word limit and no word about how the analysis was done. Code writes the title,
  the facts line, the headings, the sources and the limits, and Typst renders the PDF.
- **The second opinion is recorded, never applied.** With `--shadow N`, a model reads the blind case file
  (the decision and every per-contact outcome removed) and says `review` or `explained`, N times at a
  non-zero temperature (`shadow.py`). It runs on ThreatFox cases only, the cases it was evaluated on. The
  report sets the votes beside code's decision, so an analyst can label the cases where they part. No
  labelled cases exist, so the rules are not tuned to agree with any model. `evals/` scores model verdicts
  on synthetic cases, and the package README ("Evaluating model verdicts") has the results.

## The privacy boundary

**What each store keeps.**

| Where | What it holds | Bound |
|---|---|---|
| The source DuckDB (`data/source.duckdb`) | Minute rows with client and server addresses, TLS names and DNS names | Read-only to every reader. Nothing deletes a loaded day; with `NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS` set, readers treat older days as expired, as the original fifteen-day source did |
| The retained store, `history.*` | Per address and day: counts, and each service as a 16-byte BLAKE2b hash. No raw domain, SNI, DNS or endpoint string | Cut to 365 days at every publication (`publication.py`) |
| The retained store, `feed.*` | The published streams. An episode names its service's domain only when the service is keyed by domain and affected the decision (`feed/domain.py`) | Kept as published |
| `output/` | ioc-report's Markdown, JSON and PDFs, with internal addresses and domains | Git-ignored |

The service hash has no secret: ioc-report hashes a name the same way to look it up (`history.py`). It
keeps names out of the store's text; it cannot hide a name someone already knows.

**What leaves the machine.** Two paths, both off by default:

- **Model text, through OpenRouter,** only when `MODEL_PROVIDER` or `SHADOW_PROVIDER` is `openrouter`, or a
  case report is asked for. The case's host address, as the feed wrote it and as normalized, becomes `HOST`
  before the text is sent, and is restored in the reply (`cli.pseudonymise`, `text.without_addresses`). The
  rest of the brief goes as code wrote it. Every request asks OpenRouter to route only to endpoints that
  retain nothing and collect nothing, and to fail rather than drop a parameter. No request is sent whose
  worst case could take the spend past the run's `--budget` (`openrouter.py`). The local model must listen
  on loopback (`model.py`).
- **RDAP lookups,** with `NAME_LOOKUP=rdap`: registered domains only, sent to the server IANA's bootstrap
  file names for the top-level domain, with every answer cached under `data/` (`registration.py`).

The demo uses neither: it runs with `--no-model`, and its RDAP bootstrap points at a closed loopback port.

**What the programs print.** Counts, never cases. `ioc-match` and `ioc-report` print counts and folders.
Triage's JSON log drops address, domain, SNI and DNS fields (`operations/logging.py`), and query audits
carry no SQL or parameters. The CLIs refuse a `.env` that group or others can access (`config.py`).

**What the repository holds.** Synthetic data only. `make check` runs `scripts/check_leaks.py`, which fails
on any IPv4 address outside the private, documentation and benchmarking ranges, bar a few named public
services, and on any data file outside `fixtures/zeek-real/`. `.gitignore` keeps `data/`, `output/`, the
stores and `.env` out.
