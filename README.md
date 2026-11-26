# flowcase

**Work in progress.** Daily behavioural triage and IOC case reports for a large network, being moved onto
Zeek logs.

The code grew out of a security project on a large Australian university's network. That
deployment read a commercial flow-telemetry platform. This repository replaces that source with Zeek and a
synthetic dataset, so it runs anywhere and holds no data from that network.

| Path | What it holds |
|---|---|
| `packages/triage` | `network-behaviour`: publishes one immutable stream of behavioural episodes per UTC day, then orders the hosts worth a look. Ordering is sequencing, never risk |
| `packages/ioc-report` | `ioc-report`: decides every IOC match in code (`review` or `explained`), then has a model write the case up. Code checks every reply, and its own text stands when a reply fails |
| `docs/` | Case study, architecture and source contract (coming) |
| `demo/` | A synthetic Zeek network with planted cases, and `make demo`, which runs everything and checks each case |
| `fixtures/zeek-real/` | A synthetic capture and the logs real Zeek wrote from it, for a compatibility test |

## Architecture

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 400}}}%%
flowchart TD
    zeek[/"Zeek logs<br/>conn · ssl · dns · weird"/]
    asn[/"ip2asn table"/]
    tfx[/"ThreatFox export"/]
    load["network-behaviour load-zeek"]
    src[("Source DuckDB<br/>four flow.* tables<br/>read-only to every reader")]
    store[("Retained store DuckDB<br/>daily episode streams<br/>365-day history, no raw names")]
    match["ioc-match"]
    feed[/"IOC-match feed"/]
    out[/"HTML · Markdown · JSON report<br/>PDF per review case"/]
    orr["OpenRouter · Haiku<br/>off the machine, opt-in<br/>zero-retention routing"]
    rdap["RDAP registration dates<br/>off the machine, opt-in"]

    zeek --> load
    asn --> load
    load --> src

    subgraph triage["triage: one UTC day at a time"]
        direction LR
        gates["Contract and<br/>drift gates"] --> detect["Baselines and five<br/>detector families"] --> order["Tiers and ordering<br/>sequencing, not risk"]
    end

    subgraph decides["ioc-report: code decides"]
        direction LR
        evid["Evidence<br/>per case"] --> rules{{"rules.py<br/>review or explained"}} --> digest["digest.py<br/>facts for the writer"]
    end

    subgraph writes["ioc-report: a model writes, code checks"]
        direction LR
        writer["Model writes the prose<br/>local by default"] <-->|"fails: sent back,<br/>3 tries in all"| check{{"narrative.py<br/>checks every reply"}}
    end

    src --> triage
    triage <-->|"publishes each day once<br/>reads the days before it"| store
    tfx --> match
    src --> match
    match --> feed --> decides
    src -->|"live contacts"| decides
    store -->|"history and triage episodes"| decides
    decides -->|"the digest only"| writes
    writes -->|"a reply that passes,<br/>else code's own text"| out
    decides -->|"the decision, unchanged"| out
    writes -.->|"HOST in place of the address"| orr
    decides -.->|"registered domains only"| rdap

    classDef offbox stroke-dasharray: 5 5
    class orr,rdap offbox
```

## Develop

Needs [uv](https://docs.astral.sh/uv/) and Python 3.12 or newer.

```shell
make sync         # uv sync --all-packages --all-extras
make check        # format, lint, types, generated docs and tests for both packages, and the leak check
make demo         # the whole pipeline on a synthetic network, checked case by case (see demo/README.md)
make demo-small   # the same cases on fewer background hosts, as CI runs it
make zeek-fixture # rebuild fixtures/zeek-real with scapy and real Zeek (needs Docker)
```

The leak check (`scripts/check_leaks.py`) fails on any IPv4 address outside the private, documentation
and benchmarking ranges, except a few named public services, and on any data file outside
`fixtures/zeek-real/`.
