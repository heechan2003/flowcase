# ioc-report: agent guide

This tool reads an IOC-match feed (ThreatFox by default), adds live and retained context, decides every case in code
(`rules.py`), and has a local model summarise the review cases. It depends on `network_behaviour`
(`packages/triage`, a member of the same uv workspace) for source guards, service hashing and its DuckDB.

- **Never print or commit** feed contents, reports, internal addresses, domains or source rows. `data/` and
  `output/` are git-ignored; keep it that way. When you report, give counts, not cases. A review case's PDF
  and audit file are named for its threat, host and indicator (`case_report.file_stem`), so never list them either.
- **Source SQL** lives in `src/ioc_report/sql/` and must pass triage's `validate_sql`:
  - only the four authorized tables
  - typed half-open UTC bounds
  - aggregate only
  - batched across cases, never per host

  For any live access, follow `packages/triage/sql/CLAUDE.md`, and report the query footprint.
- **The DuckDB is read-only.** Never open it writable or run its migrations from here. DuckDB reads live in
  `history.py`, batched across cases. `validate_sql` does not apply to them.
- **No host verdicts.** A case ends `review` or `explained`. Never label a host compromised, infected or
  benign.
- **Code decides.** Dispositions come from `rules.py` alone. The local model is the writer: it turns each
  case's code-built digest (`digest.py`) into its overview, and writes the group paragraphs and the executive
  summary (`narrative.py`). It never changes a decision, code checks every reply, and code's own text stands
  when a reply fails. The model reads the digest, never the raw case file; the case file is the blind
  verdict's input only.
- **Case reports say what we found, never how.** Their reader is the academic lead, who marks only the PDF
  and knows nothing of this tool (`case_report.py`). Keep rules, thresholds, tools, data stores and models
  out of the PDF: `case_report.brief` takes them out of what the writer reads, and
  `narrative.method_words` sends back a reply that uses them. Haiku writes the paragraphs from the case's
  saved digest; code writes everything else, and the decision is the one in the run's JSON. Nothing here
  reads the source or the DuckDB.
- **A feed names its list.** `knowledge.LISTINGS` says who publishes each list and where its records keep
  what it says; ThreatFox is the default entry. Text names the claim's `source`, never ThreatFox by habit.
  ThreatFox's prompts, digests and blind case files must stay byte-identical, because they are what `evals/`
  judged (`tests/test_evals.py`, `tests/test_listing.py`). The second opinion runs on ThreatFox cases only.
- **Numbers come from measurement.** Every threshold cites a section of `docs/CASE_STUDY.md` (`CASE_STUDY §N`).
- **Populations are the scored ones.** A campus rate or quantile counts addresses with a service row
  (`behavioural-support-v3`, `history.SCORED_MIN_SERVICES`), never every `history.client_day` row:
  60–75% of those carry only unaddressed rows (CASE_STUDY §2, §3).
- **Knowledge is cited.** Every family and service entry in `knowledge.py` lists public sources. A field
  that cannot be cited stays `None` and enables no rule. To describe a family for the case reports alone,
  add it to `REPORT_FAMILIES`. Adding it to `FAMILIES`, or having a rule read `REPORT_FAMILIES`, changes blind
  case files, so it needs a new evaluation. So does a new `SHARED_NETWORKS` entry, because E4 and the blind case
  file read that table. A shared network only satisfies E4's sharing check: it never clears K1 or K5, and no
  protocol rule reads it, since such a network can also proxy raw TCP.
- **The model is local by default.** `OLLAMA_URL` must be loopback. An external model runs only when
  `MODEL_PROVIDER` or `SHADOW_PROVIDER` is `openrouter`, or a case report is asked for (`ioc-case-report`,
  `--case-reports`); the academic lead has permitted external models since the project began, and wants
  agents to generate these reports. The case's internal host address is replaced with `HOST` before any text
  leaves the machine (`cli.pseudonymise`, `text.without_addresses`), and every request demands zero-retention,
  no-collection routing. Keys live only in `.env`, never in `.env.example`. Software signals in `knowledge.py`
  cite public sources, as families do.
- **The chosen external model is `anthropic/claude-haiku-5.5`.** It is the only model that passed `evals/`.
  Its verdicts run in shadow mode, recorded and never applied (README, "How we proceed"), and it writes the
  case reports' paragraphs when asked. Any change to `SHADOW_PROMPT` must pass `evals/` again; `REPORT_PROMPT`
  gives no verdict, so a change to it need not. OpenRouter credit is a fixed $5 that will not be topped up:
  check the balance and use `--budget` before any paid run.

- **Synthetic data only.** Fixtures, eval cases and examples are synthetic. Never add a real feed,
  report, internal address or name. Campus hosts use documentation ranges or `10.0.0.0/8`.
- **Name lookups are opt-in.** `NAME_LOOKUP=rdap` sends registered domains, and nothing else, to RDAP
  servers (`registration.py`). Never send a full name, an address or case text, and keep the cache in
  `data/`.
- **No labels exist.** Never tune rules, thresholds or prompts to agree with the model's verdicts.

Validate with `ruff format --check . && ruff check . && mypy && pytest`.
