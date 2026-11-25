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
| `demo/` | A synthetic Zeek world and a one-command demo (coming) |
| `fixtures/zeek-real/` | Real Zeek output for a compatibility test (coming) |

## Develop

Needs [uv](https://docs.astral.sh/uv/) and Python 3.12 or newer.

```shell
make sync     # uv sync --all-packages --all-extras
make check    # format, lint, types, generated docs and tests for both packages
```
